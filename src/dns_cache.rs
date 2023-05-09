
pub mod dns_cache
{
    use std::collections::{HashMap, HashSet};
    use std::hash::{Hash, Hasher};
    use std::sync::Mutex;
    use chrono::{Duration, Local, DateTime};
    use crate::dns_server::dns_packet::dns_packet::{Answer, DnsPacket, QueryType};

    #[derive(Eq, Debug)]
    pub struct RecordEntry {
        pub record: Answer,
        pub expires_in: DateTime<Local>,
    }

    impl RecordEntry {
        pub fn new(record: Answer) -> Self {
            let ttl = record.ttl as i64;
            RecordEntry {
                record,
                expires_in: Local::now() + Duration::seconds(ttl),
            }
        }

        pub fn is_expired(&self) -> bool {
            self.expires_in < Local::now()
        }
    }

    impl Hash for RecordEntry {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.record.hash(state);
        }
    }
    impl PartialEq for RecordEntry {
        fn eq(&self, other: &Self) -> bool {
            self.record == other.record
        }
    }

    #[derive(Debug)]
    pub struct CacheEntry {
        pub domain: String,
        pub record_types: HashMap<QueryType, HashSet<RecordEntry>>
    }

    #[derive(Debug)]
    pub struct DnsCache {
        cache: Mutex<HashMap<String, CacheEntry>>
    }

    impl DnsCache {
        pub fn new() -> Self {
            DnsCache {
                cache: Mutex::new(Default::default()),
            }
        }
        pub fn get(&self, query_name: &str, query_type: &QueryType) -> Option<Vec<Answer>> {
            let cache = self.cache.lock().unwrap();
            cache.get(query_name)
                .and_then(|x| x.record_types.get(query_type))
                .and_then(|x| {
                    let answers: Vec<Answer> = x.iter().filter(|entry| !entry.is_expired())
                        .map(|entry| entry.record.clone())
                        .collect();
                    if answers.is_empty() {
                        None
                    } else {
                        Some(answers)
                    }
                })
        }

        pub fn insert(&self, answers: Vec<Answer>) {
            if answers.is_empty() {
                return;
            }
            if let Some(()) = self.update(&answers) {
                return;
            }
            let mut entry = CacheEntry {
                domain: answers.first().unwrap().name.to_string(),
                record_types: HashMap::new(),
            };

            for answer in answers {
                entry.record_types.entry(answer.query_type.clone())
                    .or_insert_with(HashSet::new)
                    .insert(RecordEntry::new(answer));
            }
            let mut cache = self.cache.lock().unwrap();
            cache.insert(entry.domain.clone(), entry);
        }

        pub fn insert_all(&self, packet: &DnsPacket) {
            self.insert(packet.answers.clone());
            self.insert(packet.authorities.clone());
            self.insert(packet.additional.clone());
        }

        pub fn update(&self, answers: &Vec<Answer>) -> Option<()> {
            let mut cache = self.cache.lock().unwrap();

            answers.first().map(|q| &q.name)
                .and_then(|qname| cache.get_mut(qname))
                .and_then(|entry|
                    Some(for answer in answers {
                        entry.record_types.entry(answer.query_type.clone())
                            .or_insert_with(HashSet::new)
                            .insert(RecordEntry::new(answer.clone()));
                    }))
        }

    }


    #[cfg(test)]
    mod tests {
        use std::thread;
        use super::*;
        use crate::dns_server::dns_packet::dns_packet::{Answer, Record, Question, Header, ResponseCode};
        use std::net::Ipv4Addr;
        use std::str::FromStr;
        use std::net::Ipv6Addr;



        #[test]
        fn test_dns_cache() {
            let mut dns_cache = DnsCache::new();
            let question = Question {
                name: "example.com".to_string(),
                query_type: QueryType::A,
                class: 1,
            };

            let answer = Answer {
                name: "example.com".to_string(),
                query_type: QueryType::A,
                class: 1,
                ttl: 1,
                len: 4,
                record: Record::A(Ipv4Addr::from_str("127.0.0.1").unwrap()),
            };

            let mut packet = DnsPacket::new(Header::new(42,true,true, ResponseCode::NOERROR));
            packet.add_question(question);
            packet.add_answer(answer.clone());

            dns_cache.insert_all(&packet);
            let cache_result = dns_cache.get("example.com", &QueryType::A);

            assert_eq!(cache_result.unwrap(), vec![answer]);
        }
        #[test]
        fn test_dns_cache_entry_expiration() {
            let dns_cache = DnsCache::new();
            let question = Question {
                name: "example.com".to_string(),
                query_type: QueryType::A,
                class: 1,
            };

            let answer = Answer {
                name: "example.com".to_string(),
                query_type: QueryType::A,
                class: 1,
                ttl: 1,
                len: 4,
                record: Record::A(Ipv4Addr::from_str("127.0.0.1").unwrap()),
            };

            let mut packet = DnsPacket::new(Header::new(42, true, true, ResponseCode::NOERROR));
            packet.add_question(question);
            packet.add_answer(answer);

            dns_cache.insert_all(&packet);
            thread::sleep(Duration::from_secs(2));
            let cache_result = dns_cache.get("example.com", &QueryType::A);
            assert_eq!(cache_result, None);
        }

        #[test]
        fn test_dns_cache_multiple_record_types() {
            let dns_cache = DnsCache::new();
            let question_a = Question {
                name: "example.com".to_string(),
                query_type: QueryType::A,
                class: 1,
            };

            let question_aaaa = Question {
                name: "example.com".to_string(),
                query_type: QueryType::AAAA,
                class: 1,
            };

            let answer_a = Answer {
                name: "example.com".to_string(),
                query_type: QueryType::A,
                class: 1,
                ttl: 300,
                len: 4,
                record: Record::A(Ipv4Addr::from_str("127.0.0.1").unwrap()),
            };

            let answer_aaaa = Answer {
                name: "example.com".to_string(),
                query_type: QueryType::AAAA,
                class: 1,
                ttl: 300,
                len: 16,
                record: Record::AAAA(Ipv6Addr::from_str("2001:db8::1").unwrap()),
            };

            let mut packet_a = DnsPacket::new(Header::new(42, true, true, ResponseCode::NOERROR));
            packet_a.add_question(question_a);
            packet_a.add_answer(answer_a.clone());

            let mut packet_aaaa = DnsPacket::new(Header::new(43, true, true, ResponseCode::NOERROR));
            packet_aaaa.add_question(question_aaaa);
            packet_aaaa.add_answer(answer_aaaa.clone());

            dns_cache.insert_all(&packet_a);
            dns_cache.insert_all(&packet_aaaa);
            println!("{:#?}", dns_cache);
            let cache_result_a = dns_cache.get("example.com", &QueryType::A);
            assert_eq!(cache_result_a.unwrap(), vec![answer_a]);

            let cache_result_aaaa = dns_cache.get("example.com", &QueryType::AAAA);
            assert_eq!(cache_result_aaaa.unwrap(), vec![answer_aaaa]);
        }
        #[test]
        fn test_dns_cache_insert_same() {
            let dns_cache = DnsCache::new();
            let question_a = Question {
                name: "example.com".to_string(),
                query_type: QueryType::A,
                class: 1,
            };

            let answer_a = Answer {
                name: "example.com".to_string(),
                query_type: QueryType::A,
                class: 1,
                ttl: 300,
                len: 4,
                record: Record::A(Ipv4Addr::from_str("127.0.0.1").unwrap()),
            };

            let mut packet_a = DnsPacket::new(Header::new(42, true, true, ResponseCode::NOERROR));
            packet_a.add_question(question_a);
            packet_a.add_answer(answer_a.clone());

            let mut packet_b = packet_a.clone();
            dns_cache.insert_all(&packet_a);
            dns_cache.insert_all(&packet_b);
            let cache_result = dns_cache.get("example.com", &QueryType::A);

            println!("{:#?}", dns_cache);
            assert_eq!(cache_result.clone().unwrap().len(), 1);
        }
    }
}