#[cfg(test)]
mod tests {
    use std::io::ErrorKind;
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use crate::dns_server::dns_packet::buffer::buffer::{BufferParser, BufferBuilder};
    use crate::dns_server::dns_packet::dns_packet::{Answer, DnsPacket, Header, OperationCode, QueryType, Question, Record, ResponseCode};
    use crate::dns_server::dns_server::DnsServer;

    #[test]
    fn test_buffer_parser_basic() {
        let data = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];

        let parser = BufferParser::new(&data);

        assert_eq!(parser.get(0).unwrap(), 0x01);
        assert_eq!(parser.get_u16(0).unwrap(), 0x0102);
        assert_eq!(parser.get_u32(0).unwrap(), 0x01020304);
        assert_eq!(parser.get_u128(0).unwrap(), 0x0102030405060708090a0b0c0d0e0f10);
        assert_eq!(
            parser.get_range(0, 4).unwrap(),
            &[0x01, 0x02, 0x03, 0x04]
        );
    }
    #[test]
    fn test_buffer_parser_read() {
        let data = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];

        let mut parser = BufferParser::new(&data);

        assert_eq!(parser.read().unwrap(), 0x01);
        assert_eq!(parser.read_u16().unwrap(), 0x0203);
        assert_eq!(parser.read_u32().unwrap(), 0x04050607);
        assert_eq!(parser.read_u128().unwrap(), 0x08090a0b0c0d0e0f1011121314151617);
    }

    #[test]
    fn test_buffer_parser_read_name() {
        let data = [
            0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x07,
            0x61, 0x6e, 0x6f, 0x74, 0x68, 0x65, 0x72, 0x03, 0x6f, 0x72, 0x67, 0x00,
        ];

        let mut parser = BufferParser::new(&data);

        assert_eq!(parser.read_name().unwrap(), "example.com");
        assert_eq!(parser.read_name().unwrap(), "another.org");
    }


    #[test]
    fn test_write_buffer_basic() {
        let mut data = [0u8; 32];
        let mut write_buffer = BufferBuilder::new(&mut data);

        write_buffer.write(0x01).unwrap();
        write_buffer.write_u16(0x0203).unwrap();
        write_buffer.write_u32(0x04050607).unwrap();
        write_buffer.write_u128(0x08090a0b0c0d0e0f1011121314151617).unwrap();

        let expected_output = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        assert_eq!(data, expected_output);
    }

    #[test]
    fn test_read_write_buffer_integration() {
        let mut data = [0u8; 32];

        {
            let mut write_buffer = BufferBuilder::new(&mut data);

            write_buffer.write(0x01).unwrap();
            write_buffer.write_u16(0x0203).unwrap();
            write_buffer.write_u32(0x04050607).unwrap();
            write_buffer.write_u128(0x08090a0b0c0d0e0f1011121314151617).unwrap();
        }

        {
            let mut read_buffer = BufferParser::new(&data);

            assert_eq!(read_buffer.read().unwrap(), 0x01);
            assert_eq!(read_buffer.read_u16().unwrap(), 0x0203);
            assert_eq!(read_buffer.read_u32().unwrap(), 0x04050607);
            assert_eq!(read_buffer.read_u128().unwrap(), 0x08090a0b0c0d0e0f1011121314151617);
        }
    }

    #[test]
    fn test_read_write_name_integration() {
        let mut data = [0u8; 32];

        {
            let mut write_buffer = BufferBuilder::new(&mut data);

            write_buffer.write_name("example.com").unwrap();
            write_buffer.write_name("another.org").unwrap();
        }

        {
            let mut read_buffer = BufferParser::new(&data);

            assert_eq!(read_buffer.read_name().unwrap(), "example.com");
            assert_eq!(read_buffer.read_name().unwrap(), "another.org");
        }
    }

    #[test]
    fn test_header_creation() {
        let header = Header::new(42, true, true, ResponseCode::NXDOMAIN);
        assert_eq!(header.id, 42);
        assert_eq!(header.get_query_response(), true);
        assert_eq!(header.get_recursion_available(), true);
        assert_eq!(header.get_response_code(), ResponseCode::NXDOMAIN);
    }

    #[test]
    fn test_header_flags() {
        let mut header = Header::new(42, false, false, ResponseCode::NOERROR);
        header.set_query_response(true);
        header.set_op_code(OperationCode::Update);
        header.set_authoritative_answer(true);
        header.set_truncated_message(true);
        header.set_recursion_desired(true);
        header.set_recursion_available(true);
        header.set_response_code(ResponseCode::SERVFAIL);

        assert_eq!(header.get_query_response(), true);
        assert_eq!(header.get_op_code(), OperationCode::Update);
        assert_eq!(header.get_authoritative_answer(), true);
        assert_eq!(header.get_truncated_message(), true);
        assert_eq!(header.get_recursion_desired(), true);
        assert_eq!(header.get_recursion_available(), true);
        assert_eq!(header.get_response_code(), ResponseCode::SERVFAIL);
    }

    #[test]
    fn test_parse_header_invalid_size() {
        let data = [0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x02];

        let mut parser = BufferParser::new(&data);
        let result = Header::from_buf(&mut parser);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn test_header_read_write() {
        let header = Header::new(42, true, true, ResponseCode::NXDOMAIN);
        let mut  buf = [0u8;512];
        let mut builder = BufferBuilder::new(&mut buf);
        header.write_to_buf(&mut builder).unwrap();

        let mut parser = BufferParser::new(&buf);
        let header2 = Header::from_buf(&mut parser).unwrap();

        assert_eq!(header.id, header2.id);
        assert_eq!(header.flags1, header2.flags1);
        assert_eq!(header.flags2, header2.flags2);
        assert_eq!(header.question_count, header2.question_count);
        assert_eq!(header.answer_count, header2.answer_count);
        assert_eq!(header.authoritiy_count, header2.authoritiy_count);
        assert_eq!(header.additional_count, header2.additional_count);
    }

    #[test]
    fn packet_create_and_query() {
        let header = Header::new(42, true, false, ResponseCode::NOERROR);
        let mut packet = DnsPacket::new(header);
        let question = Question {
            name: "exmaple.com".to_string(),
            query_type: QueryType::A,
            class: 1,
        };
        packet.add_question(question.clone());
        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.header.question_count, 1);
        assert_eq!(packet.questions[0], question);
    }

    #[test]
    fn test_add_answer() {
        let header = Header::new(42, true, false, ResponseCode::NOERROR);
        let mut packet = DnsPacket::new(header);
        let answer = Answer {
            name: "example.com".to_string(),
            query_type: QueryType::A,
            class: 1,
            ttl: 100,
            len: 4,
            record: Record::A(Ipv4Addr::new(93, 184, 216, 34)),
        };
        packet.add_answer(answer.clone());
        assert_eq!(packet.answers.len(), 1);
        assert_eq!(packet.header.answer_count, 1);
        assert_eq!(packet.answers[0], answer);
    }

    #[test]
    fn build_and_parse_packet() {
        let header = Header::new(42, true, false, ResponseCode::NOERROR);
        let mut packet = DnsPacket::new(header);
        let question = Question {
            name: "example.com".to_string(),
            query_type: QueryType::A,
            class: 1,
        };
        packet.add_question(question.clone());

        let mut buf = [0u8; 512];
        let bytes_written;
        {
            let mut builder = BufferBuilder::new(&mut buf);
            packet.write_to_buf(&mut builder).unwrap();
            bytes_written = builder.get_pos();
        }

        // Parse the packet from the buffer
        let parsed_packet = DnsPacket::from_buf(&buf[..bytes_written]).unwrap();

        // Check if the parsed packet matches the original packet
        assert_eq!(parsed_packet.header, packet.header);
        assert_eq!(parsed_packet.questions.len(), packet.questions.len());
        assert_eq!(parsed_packet.answers.len(), packet.answers.len());
        assert_eq!(parsed_packet.authorities.len(), packet.authorities.len());
        assert_eq!(parsed_packet.additional.len(), packet.additional.len());

        assert_eq!(parsed_packet.questions[0], question);
    }

    #[test]
    fn test_query_built_packet() {
        let header = Header::new(42, true, false, ResponseCode::NOERROR);
        let mut packet = DnsPacket::new(header);
        let question = Question {
            name: "google.com".to_string(),
            query_type: QueryType::A,
            class: 1,
        };
        packet.add_question(question);

        let mut buf = [0u8; 512];
        let bytes_written;
        {
            let mut builder = BufferBuilder::new(&mut buf);
            packet.write_to_buf(&mut builder).unwrap();
            bytes_written = builder.get_pos();
        }
        let ns = Ipv4Addr::from_str("198.41.0.4").unwrap();
        let mut server = DnsServer::new("127.0.0.1:2053").unwrap();
        let mut out_buf = [0u8; 512];
        let (amt, in_buf) = server.lookup(&ns, &buf[..bytes_written]).unwrap();
        let mut packet = DnsPacket::from_buf(&in_buf[..amt]).unwrap();

        assert_eq!(packet.header.get_response_code(), ResponseCode::NOERROR);
    }

}
