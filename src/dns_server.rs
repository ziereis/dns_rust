pub mod dns_packet;

pub mod dns_server {
    use std::io;
    use std::io::{Error, ErrorKind};
    use std::net::{Ipv4Addr, SocketAddr};
    use std::str::FromStr;
    use std::sync::Arc;
    use tokio::net::UdpSocket;
    use async_recursion::async_recursion;
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
            let server = DnsServer {
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
        pub async fn recursive_lookup<'a>(&self, out_buf: &[u8], ips: impl Iterator<Item = &'a Ipv4Addr> + std::marker::Send + 'async_recursion) -> io::Result<([u8;512], usize)> {
            for addr in ips {
                println!("looking up ip: {:#?}", addr);
                let (buf, amt) = self.lookup(addr, &out_buf).await?;
                let packet = DnsPacket::from_buf(&buf[..amt])?;
                let res_code = packet.header.get_response_code();
                if !packet.answers.is_empty() &&
                   (res_code == ResponseCode::NOERROR || res_code == ResponseCode::NXDOMAIN) {
                    return Ok((buf, amt));
}
                else if packet.header.additional_count > 0 {
                    println!("starting recursive lookup with additional");
                    let ips = packet.get_resolved_ns(&packet.questions.first().expect("123").name);
                    let res = self.recursive_lookup(&out_buf, ips).await?;
                    return Ok(res);
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
                        let (buf, amt) = packet.to_buf()?;
                        let (buf_ns, amt_ns) = self.recursive_lookup(&buf[..amt], self.root_server_ips.iter()).await?;
                        let packet_ns = DnsPacket::from_buf(&buf_ns[..amt_ns])?;
                        let ips = packet_ns.get_ipv4_iterator_answers();
                        let res= self.recursive_lookup(&out_buf, ips).await?;
                        return Ok(res);
                    }
                }
                else {
                    return Err(Error::new(ErrorKind::InvalidInput, "packet contains nothing"));
                }
            }
            return Err(Error::new(ErrorKind::InvalidInput, "rec lookup error"));
        }

        pub async fn lookup(&self, addr: &Ipv4Addr, out_buf: &[u8]) -> io::Result<([u8;512], usize)> {
            self.lookup_socket.send_to(&out_buf, (*addr,53 as u16)).await?;
            let mut buf =  [0u8;512];
            let amt = self.lookup_socket.recv(&mut buf).await?;
            Ok((buf, amt))
        }

        pub async fn resolve_request(self: Arc<Self>, client: SocketAddr, in_packet: DnsPacket) {
            let (buf, amt) = match in_packet.questions.first().unwrap().query_type {
                QueryType::UNKOWN(_) => {
                    let packet = DnsPacket::new(Header::new(6969, true, true, ResponseCode::NOTIMP));
                    packet.to_buf().unwrap()
                },
                _ =>  {
                    let (buf, bytes_written) = in_packet.to_buf().unwrap();
                    match self.recursive_lookup(&buf[..bytes_written], self.root_server_ips.iter()).await {
                        Ok(packet) => packet,
                        Err(_) => {
                            let packet = DnsPacket::new(Header::new(6969, true, true, ResponseCode::SERVFAIL));
                            packet.to_buf().unwrap()
                        },
                    }
                },
            };
            self.client_socket.send_to(&buf[..amt],client).await.unwrap();
        }

        pub async fn start(self: Arc<Self>) {
            loop {
                let mut buf =  [0u8;512];
                let (_, client) = self.client_socket.recv_from(&mut buf)
                    .await
                    .expect("could recv packet from client");
                let in_packet = DnsPacket::from_buf(&buf)
                    .expect("could parse packet from client");
                let self_clone = Arc::clone(&self);
                tokio::task::spawn(async move {
                    self_clone.resolve_request(client, in_packet).await;
                });
            }

        }
    }

}

