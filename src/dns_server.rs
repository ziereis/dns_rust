pub mod dns_packet;

pub mod dns_server {
    use std::borrow::BorrowMut;
    use std::io;
    use tokio::time::timeout;
    use std::time::Duration;
    use std::io::{Error, ErrorKind};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::str::FromStr;
    use std::sync::Arc;
    use tokio::net::UdpSocket;
    use async_recursion::async_recursion;
    use crate::dns_cache::dns_cache::DnsCache;
    use crate::dns_server::dns_packet::dns_packet::{Answer, DnsPacket, Header, QueryType, Question, Record, ResponseCode};

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
        cache: DnsCache,
        root_server_ips: Vec<Ipv4Addr>,
    }

    impl DnsServer {
        pub async fn new(addr: &str) -> io::Result<DnsServer> {
            let server = DnsServer {
                client_socket: UdpSocket::bind(addr).await?,
                lookup_socket: UdpSocket::bind("0.0.0.0:3267").await?,
                cache: DnsCache::new(),
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
        pub async fn recursive_lookup<'a>(&self, out_buf: &[u8], ips: impl Iterator<Item = &'a Ipv4Addr> + Send + 'async_recursion) -> io::Result<DnsPacket> {
            for addr in ips {
                println!("looking up ip: {:#?}", addr);
                let packet = self.lookup(addr, &out_buf).await?;
                let res_code = packet.header.get_response_code();
                if !packet.answers.is_empty() &&
                   (res_code == ResponseCode::NOERROR || res_code == ResponseCode::NXDOMAIN) {
                    self.cache.insert_all(&packet);
                    return Ok(packet);
                } else if packet.header.additional_count > 0 {
                    println!("starting recursive lookup with additional");
                    let ips = packet.get_resolved_ns(&packet.questions.first().expect("123").name);
                    self.cache.insert_all(&packet);
                    let res = self.recursive_lookup(&out_buf, ips).await?;
                    return Ok(res);
                }
                else if packet.header.authoritiy_count > 0 {
                    println!("starting recursive lookup without additional");
                    self.cache.insert_all(&packet);
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
                        let packet_ns = self.recursive_lookup(&buf[..amt], self.root_server_ips.iter()).await?;
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

        pub async fn lookup(&self, addr: &Ipv4Addr, out_buf: &[u8]) -> io::Result<DnsPacket> {
            self.lookup_socket.send_to(&out_buf, (*addr,53 as u16)).await?;
            let mut buf =  [0u8;512];
            let amt = timeout(Duration::from_secs(1),self.lookup_socket.recv(&mut buf)).await??;
            Ok(DnsPacket::from_buf(&buf[..amt])?)
        }

        pub async fn iterative_cache_resolve(&self, name: &str, out_buf: &[u8]) -> io::Result<DnsPacket> {
            let labels: Vec<&str> = name.split('.').collect();
            println!("{:#?}",self.cache);
            for label_idx in 0..labels.len() {
                let domain = labels[label_idx..].join(".");
                if let Some(nss) = self.cache.get(&domain, &QueryType::NS) {
                    println!("found subdomain {} while resolving {}", domain, name);
                    let ns_name_iter = nss.iter()
                        .filter_map(|ans| match &ans.record {
                            Record::NS(name)=> Some(name),
                            _ => None,
                        });
                    for ns_name in ns_name_iter  {
                        if let Some(resolved_ns) = self.cache.get(ns_name, &QueryType::A){
                            let ips = resolved_ns.iter()
                                .filter_map(|ans| match &ans.record {
                                    Record::A(ip) => Some(ip),
                                    _ => None,
                                });
                            return Ok(self.recursive_lookup(&out_buf, ips).await?);
                        }
                    }
                } else {
                    continue
                }
            }
            Ok(self.recursive_lookup(&out_buf, self.root_server_ips.iter()).await?)

        }

        pub async fn resolve_request(&self, client: SocketAddr, query: DnsPacket) {
            let mut header = Header::new(query.header.id, true, true, ResponseCode::NOERROR);
            header.set_recursion_available(true);
            let mut response;
            if query.questions.is_empty() {
                header.set_response_code(ResponseCode::FORMERR);
                response = DnsPacket::new(header);
            } else if matches!(query.questions.first().unwrap().query_type, QueryType::UNKOWN(_)) {
                header.set_response_code(ResponseCode::NOTIMP);
                response = DnsPacket::new(header);
            } else {
                let question = query.questions.first().unwrap();
                if let Some(cached) = self.cache.get(&question.name, &question.query_type) {
                    response = DnsPacket::new(header);
                    response.set_questions(query.questions);
                    response.set_answers(cached);
                } else {
                    let (buf, bytes_written) = query.to_buf().unwrap();
                    if let Ok(packet) = self.iterative_cache_resolve(&question.name, &buf[..bytes_written]).await {
                        response = packet;
                    } else {
                        header.set_response_code(ResponseCode::SERVFAIL);
                        response = DnsPacket::new(header);
                        }
                    }
                }
            let (buf, amt) = response.to_buf().unwrap();
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

