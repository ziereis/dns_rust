pub mod dns_packet;

pub mod dns_server {
    use std::io;
    use std::io::{Error, ErrorKind};
    use std::net::{AddrParseError, Ipv4Addr, UdpSocket};
    use std::str::FromStr;
    use crate::dns_server::dns_packet::dns_packet::{DnsPacket, ResponseCode};

    const ROOT_SERVER_STRS: [&str; 13] = ["198.41.0.4",
                                        "199.9.14.201",
                                        "192.33.4.12",
                                        "199.7.91.13",
                                        "192.203.230.10",
                                        "192.5.5.241",
                                        "192.112.36.4",
                                        "198.97.190.53",
                                        "192.36.148.17",
                                        "192.58.128.30",
                                        "193.0.14.129",
                                        "199.7.83.42",
                                        "202.12.27.33",
                                        ];

    pub struct DnsServer {
        client_socket: UdpSocket,
        lookup_socket: UdpSocket,
        buf: [u8;512],
    }

    impl DnsServer {
        pub fn new(addr: &str) -> io::Result<DnsServer> {
            Ok(DnsServer {
                client_socket: UdpSocket::bind(addr)?,
                lookup_socket: UdpSocket::bind("0.0.0.0:3267")?,
                buf: [0; 512],
            })
        }

        pub fn recursive_lookup<'a>(&self, out_buf: &[u8], ips: impl Iterator<Item = &'a Ipv4Addr>) -> io::Result<(usize, [u8;512])> {
            for addr in ips {
                println!("looking up ip: {:#?}", addr);
                let (amt, buf) = self.lookup(addr, &out_buf)?;
                let packet = DnsPacket::from_buf(&buf[0..amt])?;
                println!("{:#?}", packet);
                let res_code = packet.header.get_response_code();
                if !packet.answers.is_empty() &&
                   (res_code == ResponseCode::NOERROR || res_code == ResponseCode::NXDOMAIN) {
                    println!("finished");
                    return Ok((amt, buf));
                }
                else if packet.header.additional > 0 {
                    println!("starting recursive lookup with additional");
                    let ns = packet.get_resolved_ns(&packet.questions.first().expect("123").name);
                    let (amt, buf) = self.recursive_lookup(&out_buf, ns)?;
                    return Ok((amt,buf));
                }
                else if packet.header.authorities > 0 {
                    return Err(Error::new(ErrorKind::InvalidInput, "no additional"));
                }

                return Err(Error::new(ErrorKind::InvalidInput, "rec lookup error"));
            }
            return Err(Error::new(ErrorKind::InvalidInput, "rec lookup error"));
        }
        pub fn lookup(&self, addr: &Ipv4Addr, out_buf: &[u8]) -> io::Result<(usize,[u8;512])> {
            self.lookup_socket.send_to(&out_buf, (*addr,53 as u16))?;
            let mut buf =  [0u8;512];
            let amt = self.lookup_socket.recv(&mut buf)?;
            Ok((amt, buf))
        }

        pub fn start(&mut self) {
            loop {
                let (amt, client) = self.client_socket.recv_from(&mut self.buf)
                    .expect("could recv packet from client");
                let in_packet = DnsPacket::from_buf(&self.buf).
                    expect("could parse packet from client");
                //println!("{:#?}", in_packet);
                let root_server_ips: Vec<Ipv4Addr> = ROOT_SERVER_STRS
                    .iter()
                    .filter_map(|&ip_str | match Ipv4Addr::from_str(ip_str) {
                        Ok(ip) => Some(ip),
                        _ => None,
                    }).collect();

                let (amt, buf) = self.recursive_lookup(&self.buf[0..amt], root_server_ips.iter()).expect("lookup failed");
                let out_packet = DnsPacket::from_buf(&buf)
                    .expect("could parse packet from server");
                self.client_socket.send_to(&buf[0..amt],client)
                    .expect("couldnt return packet to client");

            }
        }
    }

}

