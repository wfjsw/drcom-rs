mod common;
mod crypto;
mod drcom;

use std::io::BufReader;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::net::ToSocketAddrs;
use std::thread::sleep;

use clap::Parser;
use drcom::wired::dialer::ChallengeResponse;
use drcom::wired::dialer::LoginResponse;
use drcom::wired::dialer::{LoginAccount, ChallengeRequest};
use drcom::wired::heartbeater::HeartbeatError;
use drcom::wired::heartbeater::HeartbeatFlag;
use drcom::wired::heartbeater::PhaseOneRequest;
use drcom::wired::heartbeater::PhaseOneResponse;
use drcom::wired::heartbeater::PhaseTwoRequest;
use drcom::wired::heartbeater::PhaseTwoResponse;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Server address
    #[arg(short, long)]
    server: String,

    /// Username
    #[arg(short, long)]
    username: String,

    /// Password
    #[arg(short, long)]
    password: String,
}

macro_rules! read_socket {
    ($socket:ident, $buf:ident) => {
        {
            $socket.recv_from(&mut $buf).unwrap();
            BufReader::new(&$buf[..])
        }
    };
}

fn phase1(
    socket: &UdpSocket, 
    hash_salt: [u8; 4],
    keep_alive_key: [u8; 16], 
    password: &str,
    remote_server: &SocketAddr,
) -> Result<PhaseOneResponse, HeartbeatError> {
    let mut recv_buf = [0u8; 1024];
    let p1_request = PhaseOneRequest::new(
        hash_salt,
        password,
        keep_alive_key,
        None
    );
    let p1_packet = p1_request.as_bytes();
    println!("[Phase 1] Sending P1 Request... {:#X?}", &p1_packet);
    socket.send_to(&p1_packet, remote_server).unwrap();
    let mut recv_reader = {
        socket.recv_from(&mut recv_buf).unwrap();
        println!("[Phase 1] Receiving response... {:#X?}", recv_buf);
        BufReader::new(&recv_buf[..])
    };
    PhaseOneResponse::from_bytes(&mut recv_reader)
}

fn main() {
    let args = Args::parse();

    let socket = UdpSocket::bind("0.0.0.0:61440").unwrap();
    let remote_server = args.server.to_socket_addrs().unwrap().next().unwrap();

    let host_ip = Ipv4Addr::new(10,30,22,17);

    let mut recv_buf = [0u8; 1024];

    let challenge_response = {
        let challenge_request = ChallengeRequest::new(None);
        let challenge_packet = challenge_request.as_bytes();
        println!("[ChalResp] Sending challenge... {:#X?}", &challenge_packet);
        socket.send_to(&challenge_packet, remote_server).unwrap();
        let mut recv_reader = read_socket!(socket, recv_buf);
        println!("[ChalResp] Receiving response... {:#X?}", recv_buf);
        ChallengeResponse::from_bytes(&mut recv_reader).unwrap()
    };

    let mut account = LoginAccount::new(
        &args.username,
        &args.password,
        challenge_response.hash_salt,
    );

    account.client_version(0xf);

    let login_response = {
        let login_request = account.login_request().unwrap();
        let login_packet = login_request.as_bytes().unwrap();
        println!("[Login] Logging in... {:#X?}", &login_packet);
        socket.send_to(&login_packet, remote_server).unwrap();
        let mut recv_reader = read_socket!(socket, recv_buf);
        println!("[Login] Receiving login response... {:#X?}", recv_buf);
        LoginResponse::from_bytes(&mut recv_reader)
    };

    if login_response.is_err() {
        continue;
    }

    let login_response = login_response.unwrap();

    phase1(&socket, challenge_response.hash_salt, login_response.keep_alive_key, &args.password, &remote_server).unwrap();

    {
        let mut sequence = 0;
        let mut keep_alive_key = [0u8; 4];

        loop {
            let p2_response = {
                let p2_request = PhaseTwoRequest::new(
                    sequence, 
                    keep_alive_key,
                    &HeartbeatFlag::First,
                    host_ip,
                    Some(1),
                );
                let p2_packet = p2_request.as_bytes();
                println!("[keep-alive2] send1");
                socket.send_to(&p2_packet, remote_server).unwrap();
                println!("[keep-alive2] recv1");
                let mut recv_reader = read_socket!(socket, recv_buf);
                PhaseTwoResponse::from_bytes(&mut recv_reader)
            };

            if p2_response.is_ok() {
                let p2_response = p2_response.unwrap();
                if p2_response.sequence == 0 || p2_response.sequence == sequence {
                    break;
                } else {
                    println!("[keep-alive2] recv file, resending...");
                    sequence += 1;
                    break;
                }
            }
        }

        {
            let p2_request = PhaseTwoRequest::new(
                sequence, 
                keep_alive_key,
                &HeartbeatFlag::NotFirst,
                host_ip,
                Some(1),
            );
            let p2_packet = p2_request.as_bytes();
            println!("[keep-alive2] send2");
            socket.send_to(&p2_packet, remote_server).unwrap();
            loop {
                let mut recv_reader = read_socket!(socket, recv_buf);
                let p2_response = PhaseTwoResponse::from_bytes(&mut recv_reader);
                match p2_response {
                    Ok(resp) => {
                        sequence += 1;
                        keep_alive_key = resp.keep_alive_key;
                        break;
                    },
                    Err(drcom::wired::heartbeater::HeartbeatError::ValidateError(_)) => {
                        println!("[keep-alive2] recv2/unexpected");
                    }
                    _ => {
                        unreachable!("[keep-alive2] recv2/unexpected error");
                    }
                }
            }
        }
    
        {
            let p2_request = PhaseTwoRequest::new(
                sequence, 
                keep_alive_key,
                &HeartbeatFlag::NotFirst,
                host_ip,
                Some(3),
            );
            let p2_packet = p2_request.as_bytes();
            println!("[keep-alive2] send3");
            socket.send_to(&p2_packet, remote_server).unwrap();
            loop {
                let mut recv_reader = read_socket!(socket, recv_buf);
                let p2_response = PhaseTwoResponse::from_bytes(&mut recv_reader);
                match p2_response {
                    Ok(resp) => {
                        sequence += 1;
                        keep_alive_key = resp.keep_alive_key;
                        break;
                    },
                    Err(drcom::wired::heartbeater::HeartbeatError::ValidateError(_)) => {
                        println!("[keep-alive2] recv2/unexpected");
                    }
                    _ => {
                        unreachable!("[keep-alive2] recv2/unexpected error");
                    }
                }
            }
        }
    
        let mut i = sequence;
        println!("[keep-alive2] keep-alive2 loop was in daemon.");

        loop {
            sleep(std::time::Duration::from_secs(20));
            phase1(&socket, challenge_response.hash_salt, login_response.keep_alive_key, &args.password, &remote_server).unwrap();
            
            {
                let p2_request = PhaseTwoRequest::new(
                    i, 
                    keep_alive_key,
                    &HeartbeatFlag::NotFirst,
                    host_ip,
                    Some(1),
                );
                let p2_packet = p2_request.as_bytes();
                println!("[keep-alive2] send");
                socket.send_to(&p2_packet, remote_server).unwrap();
                let mut recv_reader = read_socket!(socket, recv_buf);
                let p2_response = PhaseTwoResponse::from_bytes(&mut recv_reader);
                match p2_response {
                    Ok(resp) => {
                        keep_alive_key = resp.keep_alive_key;
                    },
                    _ => {
                        continue;
                    }
                }
            }
        
            {
                let p2_request = PhaseTwoRequest::new(
                    i+1, 
                    keep_alive_key,
                    &HeartbeatFlag::NotFirst,
                    host_ip,
                    Some(3),
                );
                let p2_packet = p2_request.as_bytes();
                println!("[keep-alive2] send");
                socket.send_to(&p2_packet, remote_server).unwrap();
                loop {
                    let mut recv_reader = read_socket!(socket, recv_buf);
                    let p2_response = PhaseTwoResponse::from_bytes(&mut recv_reader);
                    match p2_response {
                        Ok(resp) => {
                            keep_alive_key = resp.keep_alive_key;
                            break;
                        },
                        _ => {
                            continue;
                        }
                    }
                }
            }

            i = (i+2) % 0x7F;
        }
    }




    

}
