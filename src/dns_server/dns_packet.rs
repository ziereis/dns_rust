pub(crate) mod buffer;

pub mod dns_packet {
    use std::{fmt, io};
    use std::iter::Chain;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::slice::Iter;
    use crate::dns_server::dns_packet::buffer::buffer::{BufferBuilder, BufferParser};

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
        pub fn to_u8(&self) -> u8 {
            match self {
                ResponseCode::NOERROR => 0,
                ResponseCode::FORMERR => 1,
                ResponseCode::SERVFAIL => 2,
                ResponseCode::NXDOMAIN => 3,
                ResponseCode::NOTIMP => 4,
                ResponseCode::REFUSED => 5,
                ResponseCode::YXDOMAIN => 6,
                ResponseCode::XRRSET => 7,
                ResponseCode::NOTAUTH => 8,
                ResponseCode::NOTZONE => 9,
                ResponseCode::UNKNOWN => 2,
            }
        }
    }

    #[derive(Debug, PartialEq, Eq, Clone, Hash)]
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
            match self {
                QueryType::A => 1,
                QueryType::NS => 2,
                QueryType::CNAME => 5,
                QueryType::MX => 15,
                QueryType::AAAA => 28,
                QueryType::UNKOWN(x) => *x,
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
        pub question_count: u16,
        pub answer_count: u16,
        pub authoritiy_count: u16,
        pub additional_count: u16,
    }

    impl Header {
        pub fn from_buf(buf: &mut BufferParser) -> io::Result<Header> {
            Ok(Header {
                id: buf.read_u16()?,
                flags1: buf.read()?,
                flags2: buf.read()?,
                question_count: buf.read_u16()?,
                answer_count: buf.read_u16()?,
                authoritiy_count: buf.read_u16()?,
                additional_count: buf.read_u16()?,
            })
        }
        pub fn new(id: u16, recursion: bool, is_response: bool, response_code: ResponseCode) -> Header {
            let mut result = Header {
                id,
                flags1: 0,
                flags2: 0,
                question_count: 0,
                answer_count: 0,
                authoritiy_count: 0,
                additional_count: 0,
            };
            result.set_recursion_desired(recursion);
            result.set_query_response(is_response);
            result.set_response_code(response_code);
            result
        }


        pub fn write_to_buf(&self, builder: &mut BufferBuilder) -> io::Result<()> {
            builder.write_u16(self.id)?;
            builder.write(self.flags1)?;
            builder.write(self.flags2)?;
            builder.write_u16(self.question_count)?;
            builder.write_u16(self.answer_count)?;
            builder.write_u16(self.authoritiy_count)?;
            builder.write_u16(self.additional_count)?;
            Ok(())
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
        pub fn set_query_response(&mut self, value: bool) {
            if value {
                self.flags1 |= flags::QUERY_RESPONSE;
            } else {
                self.flags1 &= !flags::QUERY_RESPONSE;
            }
        }

        pub fn set_op_code(&mut self, value: OperationCode) {
            self.flags1 &= !flags::OP_CODE;
            self.flags1 |= (value as u8) << 3;
        }

        pub fn set_authoritative_answer(&mut self, value: bool) {
            if value {
                self.flags1 |= flags::AUTHORITATIVE_ANSWER;
            } else {
                self.flags1 &= !flags::AUTHORITATIVE_ANSWER;
            }
        }

        pub fn set_truncated_message(&mut self, value: bool) {
            if value {
                self.flags1 |= flags::TRUNCATED_MESSAGE;
            } else {
                self.flags1 &= !flags::TRUNCATED_MESSAGE;
            }
        }

        pub fn set_recursion_desired(&mut self, value: bool) {
            if value {
                self.flags1 |= flags::RECURSION_DESIRED;
            } else {
                self.flags1 &= !flags::RECURSION_DESIRED;
            }
        }

        pub fn set_recursion_available(&mut self, value: bool) {
            if value {
                self.flags2 |= flags::RECURSION_AVAILABLE;
            } else {
                self.flags2 &= !flags::RECURSION_AVAILABLE;
            }
        }

        pub fn set_reserved(&mut self, value: u8) {
            self.flags2 &= !flags::RESERVED;
            self.flags2 |= value << 4;
        }

        pub fn set_response_code(&mut self, value: ResponseCode) {
            self.flags2 &= !flags::RESPONSE_CODE;
            self.flags2 |= value.to_u8();
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
                .field("questions", &self.question_count)
                .field("answers", &self.answer_count)
                .field("authorities", &self.authoritiy_count)
                .field("additional", &self.additional_count)
                .finish()
        }
    }

    #[derive(Debug, PartialEq, Eq, Clone, Hash)]
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

        pub fn write_to_buf(&self, builder: &mut BufferBuilder) -> io::Result<()> {
            match self {
                Record::A(addr) => {
                    builder.write_u16(4)?;
                    builder.write_u32(u32::from(*addr))?;
                }
                Record::NS(name) | Record::CNAME(name) => {
                    let pos = builder.get_pos();
                    builder.write_u16(0);
                    builder.write_name(name)?;
                    builder.set_u16( (builder.get_pos() - (pos+2))as u16, pos)?;
                }
                Record::MX { priority, host } => {
                    let pos = builder.get_pos();
                    builder.write_u16(*priority)?;
                    builder.write_name(host)?;
                    builder.set_u16( (builder.get_pos() - (pos+2)) as u16, pos)?;
                }
                Record::AAAA(addr) => {
                    builder.write_u16(16)?;
                    builder.write_u128(u128::from(*addr))?;
                }
                Record::UNKOWN(_) => {
                    // do nothing
                }
            }
            Ok(())
        }
    }


    #[derive(Debug, PartialEq, Eq, Clone, Hash)]
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

        pub fn write_to_buf(&self, builder: &mut BufferBuilder) -> io::Result<()> {
            builder.write_name(&self.name)?;
            builder.write_u16(self.query_type.to_u16())?;
            builder.write_u16(self.class)?;
            builder.write_u32(self.ttl)?;
            self.record.write_to_buf(builder)?;
            Ok(())
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
        pub fn write_to_buf(&self, builder: &mut BufferBuilder) -> io::Result<()> {
            builder.write_name(&self.name)?;
            builder.write_u16(self.query_type.to_u16())?;
            builder.write_u16(self.class)?;
            Ok(())
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

            for _ in 0..dns_packet.header.question_count {
                dns_packet.questions.push(Question::from_buf(&mut parser)?);
            }
            for _ in 0..dns_packet.header.answer_count {
                dns_packet.answers.push(Answer::from_buf(&mut parser)?);
            }
            for _ in 0..dns_packet.header.authoritiy_count {
                dns_packet.authorities.push(Answer::from_buf(&mut parser)?);
            }
            for _ in 0..dns_packet.header.additional_count {
                dns_packet.additional.push(Answer::from_buf(&mut parser)?);
            }
            Ok(dns_packet)
        }

        pub fn new(header: Header) -> DnsPacket {
            DnsPacket {
                header,
                questions: vec![],
                answers: vec![],
                authorities: vec![],
                additional: vec![],
            }
        }

        pub fn add_question(&mut self, question: Question) {
            self.questions.push(question);
            self.header.question_count += 1;
        }
        pub fn set_questions(&mut self, questions: Vec<Question>) {
            self.questions = questions;
            self.header.question_count = self.questions.len() as u16;
        }
        pub fn add_answer(&mut self, answer: Answer) {
            self.answers.push(answer);
            self.header.answer_count += 1;
        }
        pub fn set_answers(&mut self, answers: Vec<Answer>) {
            self.answers = answers;
            self.header.answer_count = self.answers.len() as u16;
        }
        pub fn add_authority(&mut self, auth: Answer) {
            self.authorities.push(auth);
            self.header.authoritiy_count += 1;
        }
        pub fn add_additional(&mut self, additional: Answer) {
            self.additional.push(additional);
            self.header.additional_count += 1;
        }

        pub fn write_to_buf(&self, builder: &mut BufferBuilder) -> io::Result<()> {
            self.header.write_to_buf(builder)?;
            for q in &self.questions {
                q.write_to_buf(builder)?
            }
            for a in &self.answers {
                a.write_to_buf(builder)?
            }
            for a in &self.authorities {
                a.write_to_buf(builder)?
            }
            for a in &self.additional {
                a.write_to_buf(builder)?
            }
            Ok(())
        }

        pub fn to_buf(&self) -> io::Result<([u8;512], usize)> {
            let mut buf = [0u8;512];
            let bytes_written;
            {
                let mut builder =BufferBuilder::new(&mut buf);
                self.write_to_buf(&mut builder)?;
                bytes_written = builder.get_pos();
            }

            Ok((buf, bytes_written))
        }

        pub fn get_ipv4_iterator_additional<'a>(&'a self) -> impl Iterator<Item = (&Ipv4Addr, &'a str)> {
            self.additional.iter()
                .filter_map(|additional| match &additional.record {
                    Record::A(ip) => Some((ip, &additional.name[..])),
                    _ => None
                })
        }

        pub fn get_ipv4_iterator_answers(&self) -> impl Iterator<Item=&Ipv4Addr> {
            self.answers.iter()
                .filter_map(|additional| match &additional.record {
                    Record::A(ip) => Some(ip),
                    _ => None
                })
        }

        pub fn get_unresolved_ns<'a>(&'a self, qname: &'a str) -> impl Iterator<Item = (&'a str, &'a str)>{
            return  self.authorities.iter()
                .filter_map(|auth| match  &auth.record {
                    Record::NS(server) => Some((&server[..], &auth.name[..])),
                    _ => None
                })
                .filter(|(_, auth_name)| qname.ends_with(auth_name))
        }

       pub fn get_resolved_ns<'a>(&'a self, qname: &'a str) -> impl Iterator<Item = &'a Ipv4Addr> {
           self.get_unresolved_ns(qname)
               .flat_map(|(server, _)|
                   self.get_ipv4_iterator_additional()
                       .filter( move |(_, additional_name)|
                           if *additional_name == server {
                               return true;
                           } else {
                               return false;
                           }
                       )
                          .map(|(ip, _)| ip))

        }

        pub fn get_all_answers<'a>(&'a self, qname: &'a str) -> impl Iterator<Item=&'a Answer> {
            std::iter::once(self.answers.iter())
                .chain(std::iter::once(self.authorities.iter()))
                .chain(std::iter::once(self.additional.iter()))
                .flat_map(|x| x)
                .filter(|x | qname.ends_with(&x.name))
        }
    }

}
