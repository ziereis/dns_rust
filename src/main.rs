extern crate core;

use std::io;
use std::sync::Arc;
use crate::dns_server::dns_server::DnsServer;


pub mod dns_server;
pub mod test;
mod dns_cache;

#[tokio::main]
async fn main() -> io::Result<()> {
    let server = Arc::new(DnsServer::new("127.0.0.1:2053").await?);
    server.start().await;
    Ok(())
}
