use std::net::{Ipv4Addr, Ipv6Addr};

use ethers::providers::ProviderError;
use ipnet::AddrParseError;
use multiaddr::{Multiaddr, Protocol};
use nom::{
    number::complete::be_u16,
    IResult,
};

pub use self::proto::{DnsQuestion, DnsName, DnsAnswerProvider, DnsHeader, DnsFlags, Parseable, Opcode, RCode};

mod proto;
pub mod rule_trie;

#[derive(Debug)]
pub enum DnsError {
    InvalidMultiaddr(Option<multiaddr::Error>),
    InvalidAddress(AddrParseError),
    EthersProviderError(ProviderError),
    ErrNoServiceTypeRecognized,
}

impl From<multiaddr::Error> for DnsError {
    fn from(err: multiaddr::Error) -> Self {
        DnsError::InvalidMultiaddr(Some(err))
    }
}
impl From<AddrParseError> for DnsError {
    fn from(err: AddrParseError) -> Self {
        DnsError::InvalidAddress(err)
    }
}
impl From<ProviderError> for DnsError {
    fn from(err: ProviderError) -> Self {
        DnsError::EthersProviderError(err)
    }
}

fn parse_dns_question(input: &[u8]) -> IResult<&[u8], DnsQuestion> {
    let (input, qname) = DnsName::parse(input)?;
    let (input, qtype) = be_u16(input)?;
    let (input, qclass) = be_u16(input)?;
    Ok((
        input,
        DnsQuestion {
            qname,
            qtype,
            qclass,
        },
    ))
}

fn serialize_dns_question(question: &DnsQuestion) -> Vec<u8> {
    let mut serialized = DnsName::serialize(&question.qname).to_vec();
    serialized.extend_from_slice(&question.qtype.to_be_bytes());
    serialized.extend_from_slice(&question.qclass.to_be_bytes());
    serialized
}

struct HandleIp4Ip6Ret {
    answers: u16,
    response_packet: Vec<u8>,
}

trait SelectCorrectMultiAddrProtocol<T> {
    fn select_protocol<'a>(p: Protocol<'a>) -> Option<Protocol<'a>>;
}

impl SelectCorrectMultiAddrProtocol<Ipv4Addr> for Ipv4Addr {
    fn select_protocol<'a>(p: Protocol<'a>) -> Option<Protocol<'a>> {
        match p {
            Protocol::Ip4(x) => Some(Protocol::Ip4(x)),
            _ => None,
        }
    }
}
impl SelectCorrectMultiAddrProtocol<Ipv6Addr> for Ipv6Addr {
    fn select_protocol<'a>(p: Protocol<'a>) -> Option<Protocol<'a>> {
        match p {
            Protocol::Ip6(x) => Some(Protocol::Ip6(x)),
            _ => None,
        }
    }
}
fn handle_ip4_ip6_question<T>(_question: &DnsQuestion, answer: String) -> HandleIp4Ip6Ret
where T: SelectCorrectMultiAddrProtocol<T> {
    let mut response_packet: Vec<u8> = Vec::new();
    let multiaddr_ip_query = answer.parse::<Multiaddr>().map_err(DnsError::from).and_then(|x: Multiaddr| -> Result<Protocol, DnsError> {
        if x.len() < 2 {
            return Err(DnsError::InvalidMultiaddr(None))
        }
        let v = x.into_iter().next().ok_or_else(|| DnsError::InvalidMultiaddr(None))?;
        match T::select_protocol(v) {
            Some(x) => Ok(x.acquire()),
            None => Err(DnsError::InvalidMultiaddr(None))
        }
    });
    match multiaddr_ip_query {
        Ok(Protocol::Ip4(ip)) => {
            let rd_length:u16 = 4;
            response_packet.extend_from_slice(&rd_length.to_be_bytes());
            response_packet.extend_from_slice(&ip.octets());
            HandleIp4Ip6Ret { answers: 1, response_packet }
        },
        Ok(Protocol::Ip6(ip)) => {
            let rd_length:u16 = 16;
            response_packet.extend_from_slice(&rd_length.to_be_bytes());
            response_packet.extend_from_slice(&ip.octets());
            HandleIp4Ip6Ret { answers: 1, response_packet }
        }
        _ => {
            HandleIp4Ip6Ret { answers: 0, response_packet }
        }

    }
}

async fn generate_dns_response_packet<'a, P: DnsAnswerProvider>(
    questions: Vec<DnsQuestion>,
    original_header: DnsHeader,
    answer_provider: &'a P,
) -> Vec<u8> {
    let flags = DnsFlags {
        qr: true,
        opcode: Opcode::Query,
        aa: false,
        tc: false,
        rd: original_header.flags.rd,
        ra: true,
        rcode: RCode::NoError,
    };
    let mut header = DnsHeader {
        id: original_header.id,
        flags,
        qd_count: questions.len() as u16,
        an_count: 0,
        ar_count: 0,
        ns_count: 0,
    };

    let mut response_packet = Vec::new();

    // Serialize questions
    for question in &questions {
        let serialized_question = serialize_dns_question(&question);
        response_packet.extend_from_slice(&serialized_question);
    }

    for question in &questions {
        let ans = answer_provider.get_answer_async(question.clone()).await;
        println!("ans {:?}", ans);
        if let Some(answer) = ans {
            let qname_bytes = DnsName::serialize(&question.qname);
            let qclass:u16 = 1; // IN (Internet)
            let ttl:u32 = 300; //TODO
            if question.qtype == 16 {
                header.an_count += 1;
                let qtype: u16 = 16; // TXT
                let txt_data = answer.as_bytes();
                let rd_length: u16 = (txt_data.len() + 1) as u16; // +1 for the TXT length byte
                response_packet.extend_from_slice(&qname_bytes);
                response_packet.extend_from_slice(&qtype.to_be_bytes());
                response_packet.extend_from_slice(&qclass.to_be_bytes());
                response_packet.extend_from_slice(&ttl.to_be_bytes());
                response_packet.extend_from_slice(&rd_length.to_be_bytes());
                response_packet.push(txt_data.len() as u8);
                response_packet.extend_from_slice(txt_data);
            }
            else if question.qtype == 1 { //A record
                response_packet.extend_from_slice(&qname_bytes);
                response_packet.extend_from_slice(&question.qtype.to_be_bytes());
                response_packet.extend_from_slice(&qclass.to_be_bytes());
                response_packet.extend_from_slice(&ttl.to_be_bytes());
                let ret = handle_ip4_ip6_question::<Ipv4Addr>(question, answer);
                header.an_count += ret.answers;
                response_packet.extend_from_slice(&ret.response_packet);
            } else if question.qtype == 28 { //AAAA record
                response_packet.extend_from_slice(&qname_bytes);
                response_packet.extend_from_slice(&question.qtype.to_be_bytes());
                response_packet.extend_from_slice(&qclass.to_be_bytes());
                response_packet.extend_from_slice(&ttl.to_be_bytes());
                let ret = handle_ip4_ip6_question::<Ipv6Addr>(question, answer);
                header.an_count += ret.answers;
                response_packet.extend_from_slice(&ret.response_packet);
            }
        }
    }

    let serialized_header = DnsHeader::serialize(&header);
    response_packet.splice(0..0, serialized_header.iter().cloned());

    response_packet
}


pub async fn handle_dns_packet<P: DnsAnswerProvider>(data: Vec<u8>, answer_provider: &P) -> Vec<u8> {
    match DnsHeader::parse(&data) {
        Ok((remaining_data, header)) => {
            println!("Parsed header: {:?}", header);
            let questions = if header.qd_count > 0 {
                (0..header.qd_count).fold((remaining_data, Vec::new()), |(input, mut questions), _| {
                    match parse_dns_question(input) {
                        Ok((new_input, question)) => {
                            questions.push(question);
                            (new_input, questions)
                        }
                        Err(err) => {
                            //TODO: if this fails, there's no point in processing any questions
                            println!("Failed to parse question: {:?}", err);
                            (input, questions)
                        }
                    }
                }).1
            } else {
                vec![]
            };
            generate_dns_response_packet(questions, header, answer_provider).await
        }
        Err(err) => {
            println!("Failed to parse header: {:?}", err);
            vec![] // FIXME
        }
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use super::*;
    use async_trait::async_trait;

    struct DummyAnswerProvider {
        _lifetime: PhantomData<()>
    }

    #[async_trait]
    impl<'a> DnsAnswerProvider for DummyAnswerProvider {
        async fn get_answer_async(&self, _question: DnsQuestion) -> Option<String> {
            Some("dummy_answer".into())
        }
    }

    #[tokio::test]
    async fn test_dnsheader_serialize_idempotent() {
        let header = DnsHeader {
            id: 1,
            flags: DnsFlags { qr: true, opcode: Opcode::Query, aa: false, tc: false, rd: false, ra: false, rcode: RCode::NoError },
            qd_count: 0,
            an_count: 0,
            ar_count: 0,
            ns_count: 0,
        };
        let serialized = header.serialize();
        let parsed = DnsHeader::parse(&serialized).unwrap().1;
        assert_eq!(header, parsed);
    }

    #[tokio::test]
    async fn test_dnsheader_parse_idempotent()
    {
        let header = DnsHeader {
            id: 1,
            flags: DnsFlags { qr: true, opcode: Opcode::Query, aa: false, tc: false, rd: false, ra: false, rcode: RCode::NoError },
            qd_count: 0,
            an_count: 0,
            ar_count: 0,
            ns_count: 0,
        };
        let serialized = header.serialize();
        let parsed = DnsHeader::parse(&serialized).unwrap().1;
        assert_eq!(header, parsed);
    }

    #[tokio::test]
    async fn test_generate_dns_response_packet_zero_questions() {
        let questions = vec![];
        let answer_provider = DummyAnswerProvider { _lifetime: PhantomData };
        let packet = generate_dns_response_packet(
            questions,
            DnsHeader {
                id: 1,
                flags: DnsFlags { qr: true, opcode: Opcode::Query, aa: false, tc: false, rd: false, ra: false, rcode: RCode::NoError },
                qd_count: 0,
                an_count: 0,
                ar_count: 0,
                ns_count: 0,
            },
            &answer_provider,
        )
        .await;

        // Only the header is present, no questions or answers
        assert_eq!(packet.len(), 12);
    }

    #[tokio::test]
    async fn test_generate_dns_response_packet_one_txt_question() {
        let questions = vec![DnsQuestion {
            qname: DnsName::from("example.com".to_string()),
            qtype: 16, // TXT Record
            qclass: 1, // IN (Internet)
        }];
        let answer_provider = DummyAnswerProvider{ _lifetime: PhantomData};
        let packet = generate_dns_response_packet(
            questions,
            DnsHeader {
                id: 1,
                flags: DnsFlags { qr: true, opcode: Opcode::Query, aa: false, tc: false, rd: false, ra: false, rcode: RCode::NoError },
                qd_count: 1,
                an_count: 0,
                ar_count: 0,
                ns_count: 0,
            },
            &answer_provider,
        )
        .await;
        // Header + serialized question + serialized answer
        assert!(packet.len() > 12);
    }

}
