use std::io;
use std::net::UdpSocket;
use crate::dns_server::dns_packet::dns_packet::DnsPacket;
use crate::dns_server::dns_server::DnsServer;

pub mod dns_server;


fn main() -> io::Result<()> {
    let mut server = DnsServer::new("127.0.0.1:2053")?;
    server.start();
    Ok(())
}
