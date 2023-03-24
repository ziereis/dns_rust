pub mod dns_packet;

pub mod dns_server {
    use std::io;
    use std::net::UdpSocket;
    use crate::dns_server::dns_packet::dns_packet::DnsPacket;

    pub struct DnsServer {
        client_socket: UdpSocket,
        lookup_socket: UdpSocket,
        buf: [u8;512]
    }

    impl DnsServer {
        pub fn new(addr: &str) -> io::Result<DnsServer> {
            Ok(DnsServer {
                client_socket: UdpSocket::bind(addr)?,
                lookup_socket: UdpSocket::bind("0.0.0.0:3267")?,
                buf: [0; 512]
            })
        }

        pub fn lookup(&mut self, addr: &str) -> io::Result<[u8;512]> {
            self.lookup_socket.send_to(&self.buf, addr)?;
            let mut buf: [u8;512] = [0;512];
            let amt = self.lookup_socket.recv(&mut self.buf);
            Ok(buf)
        }

        pub fn start(&mut self) {
            loop {
                let (amt, client) = self.client_socket.recv_from(&mut self.buf)
                    .expect("could recv packet from client");
                let in_packet = DnsPacket::from_buf(&self.buf).
                    expect("could parse packet from client");
                println!("{:#?}", in_packet);
                let buf = self.lookup("8.8.8.8:53")
                    .expect("could perform lookup");
                let out_packet = DnsPacket::from_buf(&buf).
                    expect("could parse packet from server");
                println!("{:#?}", out_packet);
                self.client_socket.send_to(&self.buf,client)
                    .expect("couldnt return packet to client");

            }
        }
    }

}

