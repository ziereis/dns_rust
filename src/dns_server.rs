pub mod dns_packet;

pub mod dns_server {
    use std::fmt::format;
    use std::io;
    use std::io::{Error, ErrorKind};
    use std::net::{Ipv4Addr, SocketAddr};
    use std::str::FromStr;
    use std::time::Duration;
    use tokio::net::UdpSocket;
    use async_recursion::async_recursion;
    use crate::dns_server::dns_packet::buffer::buffer::BufferBuilder;
    use crate::dns_server::dns_packet::dns_packet::{DnsPacket, Header, QueryType, Question, ResponseCode};

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
        root_server_ips: Vec<Ipv4Addr>,
    }

    impl DnsServer {
        pub async fn new(addr: &str) -> io::Result<DnsServer> {
            let mut server = DnsServer {
                client_socket: UdpSocket::bind(addr).await?,
                lookup_socket: UdpSocket::bind("0.0.0.0:3267").await?,
                root_server_ips: ROOT_SERVER_STRS
                    .iter()
                    .filter_map(|ip_str | match Ipv4Addr::from_str(ip_str) {
                        Ok(ip) => Some(ip),
                        _ => None,
                    }).collect(),
            };
            Ok(server)
        }

        #[async_recursion]
        pub async fn recursive_lookup<'a>(&self, out_buf: &[u8], ips: impl Iterator<Item = &'a Ipv4Addr> + std::marker::Send) -> io::Result<DnsPacket> {
            for addr in ips {
                println!("looking up ip: {:#?}", addr);
                let packet = self.lookup(addr, &out_buf).await?;
                let res_code = packet.header.get_response_code();
                if !packet.answers.is_empty() &&
                   (res_code == ResponseCode::NOERROR || res_code == ResponseCode::NXDOMAIN) {
                    println!("finished");
                    return Ok(packet);
                }
                else if packet.header.additional_count > 0 {
                    println!("starting recursive lookup with additional");
                    let ips = packet.get_resolved_ns(&packet.questions.first().expect("123").name);
                    let packet = self.recursive_lookup(&out_buf, ips).await?;
                    return Ok(packet);
                }
                else if packet.header.authoritiy_count > 0 {
                    println!("starting recursive lookup without additional");
                    let name_servers = packet.get_unresolved_ns(&packet.questions.first().expect("123").name);
                    for (server_name, _) in name_servers {
                        let mut packet  = DnsPacket::new(
                            Header::new(1, true, false, ResponseCode::NOERROR));
                        packet.add_question(Question{
                            name: server_name.to_string(),
                            query_type: QueryType::A,
                            class: 1,
                        });
                        let (buf, bytes_written) = packet.to_buf()?;
                        let packet_ns = self.recursive_lookup(&buf[..bytes_written], self.root_server_ips.iter()).await?;
                        let ips = packet_ns.get_ipv4_iterator_answers();
                        let packet = self.recursive_lookup(&out_buf, ips).await?;
                        return Ok(packet);
                    }
                }
                else {
                    return Err(Error::new(ErrorKind::InvalidInput, "packet contains nothing"));
                }
            }
            return Err(Error::new(ErrorKind::InvalidInput, "rec lookup error"));
        }

        pub async fn lookup(&self, addr: &Ipv4Addr, out_buf: &[u8]) -> io::Result<DnsPacket> {
            self.lookup_socket.send_to(&out_buf, (*addr,53 as u16)).await?;
            let mut buf =  [0u8;512];
            let amt = self.lookup_socket.recv(&mut buf).await?;
            Ok(DnsPacket::from_buf(&buf[0..amt])?)
        }

        pub async fn resolve_request(&mut self, client: SocketAddr, packet: DnsPacket) -> io::Result<()> {
            let (buf, bytes_written) = packet.to_buf()?;
            Ok(())
        }

        pub async fn start(&mut self) {
            loop {
                let (amt, client) = self.client_socket.recv_from(&mut self.buf)
                    .await
                    .expect("could recv packet from client");
                let in_packet = DnsPacket::from_buf(&self.buf)
                    .expect("could parse packet from client");
                match in_packet.questions.first().unwrap().query_type {
                    QueryType::UNKOWN(_) =>  {
                        ()
                    }
                    _ =>  {
                        println!("{:?}", in_packet);
                        match self.recursive_lookup(&self.buf[0..amt], self.root_server_ips.iter()).await {
                            Ok(packet) =>  {
                                let (buf, bytes_written) = packet.to_buf()
                                    .expect("couldnt convert packet into buffer");
                                self.client_socket.send_to(&buf[..bytes_written],client)
                                    .await
                                    .expect("couldnt return packet to client");
                            }
                            Err(_) => ()
                        }
                    }
                }

            }
        }
    }

}

