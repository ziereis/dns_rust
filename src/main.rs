use std::io;
use std::sync::Arc;
use crate::dns_server::dns_packet::dns_packet::DnsPacket;
use crate::dns_server::dns_server::DnsServer;


pub mod dns_server;
pub mod test;

#[tokio::main]
async fn main() -> io::Result<()> {
    let mut server = Arc::new(DnsServer::new("127.0.0.1:2053").await?);
    server.start().await;
    Ok(())
}
