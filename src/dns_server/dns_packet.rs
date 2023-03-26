mod buffer;

pub mod dns_packet {
    use std::{fmt, io};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use crate::dns_server::dns_packet::buffer::buffer::BufferParser;

    pub mod flags {
        pub const QUERY_RESPONSE: u8 = 0b1000_0000;
        pub const OP_CODE: u8 = 0b0111_1000;
        pub const AUTHORITATIVE_ANSWER: u8 = 0b0000_0100;
        pub const TRUNCATED_MESSAGE: u8 = 0b0000_0010;
        pub const RECURSION_DESIRED: u8 = 0b0000_0001;

        pub const RECURSION_AVAILABLE: u8 = 0b1000_0000;
        pub const RESERVED: u8 = 0b0111_0000;
        pub const RESPONSE_CODE: u8 = 0b0000_1111;
    }


    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub enum ResponseCode {
        NOERROR = 0,
        FORMERR = 1,
        SERVFAIL = 2,
        NXDOMAIN = 3,
        NOTIMP = 4,
        REFUSED = 5,
        YXDOMAIN = 6,
        XRRSET = 7,
        NOTAUTH = 8,
        NOTZONE = 9,
        UNKNOWN
    }

    impl ResponseCode {
        fn from(num: u8) -> ResponseCode {
            match num {
                0 => ResponseCode::NOERROR,
                1 => ResponseCode::FORMERR,
                2 => ResponseCode::SERVFAIL,
                3 => ResponseCode::NXDOMAIN,
                4 => ResponseCode::NOTIMP,
                5 => ResponseCode::REFUSED,
                6 => ResponseCode::YXDOMAIN,
                7 => ResponseCode:: XRRSET,
                8 => ResponseCode:: NOTAUTH,
                9 => ResponseCode:: NOTZONE,
                _ => ResponseCode::UNKNOWN,
            }
        }
    }

    #[derive(Debug, PartialEq, Eq, Clone)]
    pub enum QueryType {
        UNKOWN(u16),
        A,
        NS,
        CNAME,
        MX,
        AAAA,
    }
    impl QueryType {
        pub fn from(num: u16) -> QueryType {
            match num {
                1 => QueryType::A,
                2 => QueryType::NS,
                5 => QueryType::CNAME,
                15 => QueryType::MX,
                28 => QueryType::AAAA,
                _ => QueryType::UNKOWN(num),
            }
        }
        pub fn to_u16(&self) -> u16 {
            match *self {
                QueryType::A => 1,
                QueryType::NS => 2,
                QueryType::CNAME => 5,
                QueryType::MX => 15,
                QueryType::AAAA => 28,
                QueryType::UNKOWN(x) => x,
            }
        }
    }

    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub enum OperationCode {
        Query = 0,
        IQuery = 1,
        Status = 2,
        Notify = 4,
        Update = 5,
        Unkown,
    }

    impl OperationCode {
        fn from(num: u8) -> OperationCode {
            match num {
                0 => OperationCode::Query,
                1 => OperationCode::IQuery,
                2 => OperationCode::Status,
                4 => OperationCode::Notify,
                5 => OperationCode::Update,
                _ => OperationCode::Unkown
            }
        }
    }

    #[derive(PartialEq, Eq, Clone, Copy)]
    pub struct Header {
        pub id: u16,
        pub flags1: u8,
        pub flags2: u8,
        pub questions: u16,
        pub answers: u16,
        pub authorities: u16,
        pub additional: u16,
    }

    impl Header {
        pub fn from_buf(buf: &mut BufferParser) -> io::Result<Header> {
            Ok(Header {
                id: buf.read_u16()?,
                flags1: buf.read()?,
                flags2: buf.read()?,
                questions: buf.read_u16()?,
                answers: buf.read_u16()?,
                authorities: buf.read_u16()?,
                additional: buf.read_u16()?,
            })
        }
        pub fn get_query_response(&self) -> bool {
            ((self.flags1 & flags::QUERY_RESPONSE) >> 7) != 0
        }
        pub fn get_op_code(&self) -> OperationCode {
            OperationCode::from((self.flags1 & flags::OP_CODE) >> 3)
        }
        pub fn get_authoritative_answer(&self) -> bool {
            ((self.flags1 & flags::AUTHORITATIVE_ANSWER) >> 2) !=0
        }
        pub fn get_truncated_message(&self) -> bool {
            ((self.flags1 & flags::TRUNCATED_MESSAGE) >> 1) != 0
        }
        pub fn get_recursion_desired(&self) -> bool {
            (self.flags1 & flags::RECURSION_DESIRED)  !=0
        }
        pub fn get_recursion_available(&self) -> bool {
            ((self.flags2 & flags::RECURSION_AVAILABLE) >> 7) !=0
        }
        pub fn get_reserved(&self) -> u8 {
            (self.flags2 & flags::RESERVED) >> 4
        }
        pub fn get_response_code(&self) -> ResponseCode {
            return ResponseCode::from(self.flags2 & flags::RESPONSE_CODE)
        }

    }

    impl fmt::Debug for Header {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Header")
                .field("id", &self.id)
                .field("flags1", &format!("{:08b}", self.flags1))
                .field("query_response", &self.get_query_response())
                .field("op_code", &self.get_op_code())
                .field("authoritative_answer", &self.get_authoritative_answer())
                .field("truncated_message", &self.get_truncated_message())
                .field("recursion_desired", &self.get_recursion_desired())
                .field("flags2", &format!("{:08b}", self.flags2))
                .field("recursion_available", &self.get_recursion_available())
                .field("reserved", &self.get_reserved())
                .field("response_code", &self.get_response_code())
                .field("questions", &self.questions)
                .field("answers", &self.answers)
                .field("authorities", &self.authorities)
                .field("additional", &self.additional)
                .finish()
        }
    }

    #[derive(Debug, PartialEq, Eq, Clone)]
    pub enum Record {
        A(Ipv4Addr),
        NS(String),
        CNAME(String),
        MX {priority: u16, host:String},
        AAAA(Ipv6Addr),
        UNKOWN(u16),
    }

    impl Record {
        pub fn from_buf(buf: &mut BufferParser, len: u16, query_type: QueryType) -> io::Result<Record> {
            let result = match query_type {
                QueryType::A => {
                    let raw_addr = buf.read_u32()?;
                    let addr = Ipv4Addr::from(raw_addr);
                    Record::A(addr)
                }
                QueryType::AAAA => {
                    let raw_addr = buf.read_u128()?;
                    let addr = Ipv6Addr::from(raw_addr);
                    Record::AAAA(addr)
                }
                QueryType::CNAME => {
                    Record::CNAME(buf.read_name()?)
                }
                QueryType::NS => {
                    Record::NS(buf.read_name()?)
                }
                QueryType::MX => {
                    Record::MX {
                        priority: buf.read_u16()?,
                        host: buf.read_name()?
                    }
                }
                QueryType::UNKOWN(x) => {
                    buf.seek(buf.get_pos() + len as usize);
                    Record::UNKOWN(x)
                }
            };
            Ok(result)
        }

    }

    #[derive(Debug, PartialEq, Eq, Clone)]
    pub struct Answer {
        pub name: String,
        pub query_type: QueryType,
        pub class: u16,
        pub ttl: u32,
        pub len: u16,
        pub record: Record,
    }

    impl Answer {
        pub fn from_buf(buf: &mut BufferParser) -> io::Result<Answer> {
            let name_ = buf.read_name()?;
            let query_type_ = QueryType::from(buf.read_u16()?);
            let query_class_ = buf.read_u16()?;
            let ttl_ = buf.read_u32()?;
            let len_ = buf.read_u16()?;
            Ok(Answer {
                name: name_,
                query_type: query_type_.clone(),
                class: query_class_,
                ttl: ttl_,
                len: len_,
                record: Record::from_buf(buf ,len_, query_type_)?,
            })
        }
    }

    #[derive(Debug, PartialEq, Eq, Clone)]
    pub struct Question {
        pub name: String,
        pub query_type: QueryType,
        pub class: u16,
    }

    impl Question {
        pub fn from_buf(buf: &mut BufferParser) -> io::Result<Question> {
            Ok(Question {
                name: buf.read_name()?,
                query_type: QueryType::from(buf.read_u16()?),
                class: buf.read_u16()?,
            })
        }
    }

    #[derive(Debug, PartialEq, Eq, Clone)]
    pub struct DnsPacket {
        pub header: Header,
        pub questions: Vec<Question>,
        pub answers: Vec<Answer>,
        pub authorities: Vec<Answer>,
        pub additional: Vec<Answer>
    }

    impl DnsPacket {
        pub fn from_buf(buf: &[u8]) -> io::Result<DnsPacket>
        {
            let mut parser = BufferParser::new(buf);
            let mut dns_packet = DnsPacket {
                header: Header::from_buf(&mut parser)?,
                questions: Vec::new(),
                answers: Vec::new(),
                authorities: Vec::new(),
                additional: Vec::new(),
            };

            for _ in 0..dns_packet.header.questions {
                dns_packet.questions.push(Question::from_buf(&mut parser)?);
            }
            for _ in 0..dns_packet.header.answers {
                dns_packet.answers.push(Answer::from_buf(&mut parser)?);
            }
            for _ in 0..dns_packet.header.authorities {
                dns_packet.authorities.push(Answer::from_buf(&mut parser)?);
            }
            for _ in 0..dns_packet.header.additional {
                dns_packet.additional.push(Answer::from_buf(&mut parser)?);
            }
            Ok(dns_packet)
        }

        pub fn get_ipv4_iterator<'a>(&'a self) -> impl Iterator<Item = (&Ipv4Addr, &'a str)> {
            self.additional.iter()
                .filter_map(|additional| match &additional.record {
                    Record::A(ip) => Some((ip, &additional.name[..])),
                    _ => None
                })
        }

        pub fn get_unresolved_ns<'a>(&'a self, qname: &'a str) -> impl Iterator<Item = (&'a str, &'a str)>{
            return  self.authorities.iter()
                .filter_map(|auth| match  &auth.record {
                    Record::NS(server) => Some((&server[..], &auth.name[..])),
                    _ => None
                })
                .filter(|(server, auth_name)| qname.ends_with(&auth_name[..]))
        }

       pub fn get_resolved_ns<'a>(&'a self, qname: &'a str) -> impl Iterator<Item = &'a Ipv4Addr> {
           self.get_unresolved_ns(qname)
               .flat_map(|(server, auth_name)|
                   self.get_ipv4_iterator()
                       .filter( move |(ip, additional_name)|
                           if *additional_name == server {
                               return true;
                           } else {
                               return false;
                           }
                       )
                          .map(|(ip, _)| ip))

        }
    }

}
