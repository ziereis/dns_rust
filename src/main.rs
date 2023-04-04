use std::io;
use std::net::UdpSocket;
use futures::executor::block_on;
use crate::dns_server::dns_packet::dns_packet::DnsPacket;
use crate::dns_server::dns_server::DnsServer;


pub mod dns_server;
pub mod test;


fn main() -> io::Result<()> {
    let mut server = block_on(DnsServer::new("127.0.0.1:2053"))?;
    block_on(server.start());
    Ok(())


/*    let client_socket = UdpSocket::bind("127.0.0.1:2053")?;
    let mut buf = [0u8; 512];
    let (amt, client) = client_socket.recv_from(&mut buf)?;
    let in_packet = DnsPacket::from_buf(&buf)?;
    println!("{:#?}", in_packet);
    Ok(())
*/}
