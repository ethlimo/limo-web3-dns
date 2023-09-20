use async_trait::async_trait;
use nom::{
    bytes::complete::take,
    number::complete::{be_u16, be_u8},
    IResult,
};
use std::str::from_utf8;

trait Parseable<T> {
    fn parse(input: &[u8]) -> IResult<&[u8], T>;
    fn serialize(&self) -> Vec<u8>;
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct DnsHeader {
    id: u16,
    flags: DnsFlags,
    qd_count: u16,
    an_count: u16,
    ns_count: u16,
    ar_count: u16,
}

impl Parseable<DnsHeader> for DnsHeader {
    fn parse(input: &[u8]) -> IResult<&[u8], DnsHeader> {
        let (input, id) = be_u16(input)?;
        let (input, flags) = DnsFlags::parse(input)?;
        let (input, qd_count) = be_u16(input)?;
        let (input, an_count) = be_u16(input)?;
        let (input, ns_count) = be_u16(input)?;
        let (input, ar_count) = be_u16(input)?;
        Ok((
            input,
            DnsHeader {
                id,
                flags,
                qd_count,
                an_count,
                ns_count,
                ar_count
            },
        ))
    }
    fn serialize(&self) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(&self.id.to_be_bytes());
        header.extend_from_slice(&self.flags.serialize());
        header.extend_from_slice(&self.qd_count.to_be_bytes());
        header.extend_from_slice(&self.an_count.to_be_bytes());
        header.extend_from_slice(&[0u8; 4]);
        header
    }
}


#[derive(Debug, Clone, Eq, PartialEq, Copy)]
struct DnsFlags {
    qr: bool,      // Query/Response
    opcode: Opcode,  // Opcode
    aa: bool,      // Authoritative Answer
    tc: bool,      // Truncation
    rd: bool,      // Recursion Desired
    ra: bool,      // Recursion Available
    rcode: RCode,   // Response Code
}

impl Parseable<DnsFlags> for DnsFlags {
    fn parse(input: &[u8]) -> IResult<&[u8], DnsFlags> {
        let (input, flags) = be_u16(input)?;
        Ok((input, DnsFlags {
            qr: (flags & 0b1000000000000000) != 0,
            opcode: Opcode::from((flags & 0b0111100000000000) >> 11),
            aa: (flags & 0b0000010000000000) != 0,
            tc: (flags & 0b0000001000000000) != 0,
            rd: (flags & 0b0000000100000000) != 0,
            ra: (flags & 0b0000000010000000) != 0,
            rcode: RCode::from(flags & 0b0000000000001111),
        }))
    }
    fn serialize(&self) -> Vec<u8> {
        let mut flags: u16 = 0;
        flags |= (self.qr as u16) << 15;
        flags |= (u16::from(self.opcode) & 0b0000000000001111) << 11;
        flags |= (self.aa as u16) << 10;
        flags |= (self.tc as u16) << 9;
        flags |= (self.rd as u16) << 8;
        flags |= (self.ra as u16) << 7;
        flags |= (u16::from(self.rcode)) & 0b0000000000001111;
        flags.to_be_bytes().to_vec()
    }
}


#[derive(Debug, Clone, PartialEq, Eq, Copy)]
#[non_exhaustive]
#[repr(u16)]
enum Opcode {
    Query = 0,
    Other(u16),
}

impl From<u16> for Opcode {
    fn from(code: u16) -> Self {
        match code {
            0 => Opcode::Query,
            _ => Opcode::Other(code),
        }
    }
}

impl From<Opcode> for u16 {
    fn from(code: Opcode) -> Self {
        match code {
            Opcode::Query => 0,
            Opcode::Other(code) => code,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
#[non_exhaustive]
#[repr(u16)]
enum RCode {
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    Other(u16),
}

impl From<u16> for RCode {
    fn from(code: u16) -> Self {
        match code {
            0 => RCode::NoError,
            1 => RCode::FormatError,
            2 => RCode::ServerFailure,
            _ => RCode::Other(code),
        }
    }
}
impl From<RCode> for u16 {
    fn from(code: RCode) -> Self {
        match code {
            RCode::NoError => 0,
            RCode::FormatError => 1,
            RCode::ServerFailure => 2,
            RCode::Other(code) => code,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[async_trait]
pub trait DnsAnswerProvider: Send + Sync {
    async fn get_answer_async(&self, question: DnsQuestion) -> Option<String>;
}

fn parse_dns_question(input: &[u8]) -> IResult<&[u8], DnsQuestion> {
    let (input, qname) = parse_qname(input)?;
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

fn parse_qname(mut input: &[u8]) -> IResult<&[u8], String> {
    let mut qname = String::new();
    loop {
        let (new_input, length) = be_u8(input)?;
        if length == 0 {
            break;
        }
        let (new_input, label) = take(length as usize)(new_input)?;
        let label_str = from_utf8(label).map_err(|_| {
            nom::Err::Error(nom::error::Error {
                input,
                code: nom::error::ErrorKind::Alpha,
            })
        })?;
        qname.push_str(label_str);
        qname.push('.');
        input = new_input;
    }
    qname.pop(); // Remove trailing '.'
    let (input, _) = be_u8(input)?; // Consume null byte
    Ok((input, qname))
}

fn serialize_dns_header(header: &DnsHeader) -> Vec<u8> {
    let mut response_packet = Vec::new();
    response_packet.extend_from_slice(&header.id.to_be_bytes());
    response_packet.extend_from_slice(&(header.flags.serialize().as_slice()));
    response_packet.extend_from_slice(&header.qd_count.to_be_bytes());
    response_packet.extend_from_slice(&header.an_count.to_be_bytes());
    response_packet.extend_from_slice(&[0u8; 4]);
    response_packet
}

fn serialize_qname(qname: &str) -> Vec<u8> {
    let mut serialized_qname = Vec::new();
    for label in qname.split('.') {
        let len = label.len() as u8;
        serialized_qname.push(len);
        serialized_qname.extend_from_slice(label.as_bytes());
    }
    serialized_qname.push(0); // Null byte to end QNAME
    serialized_qname
}

fn serialize_dns_question(question: &DnsQuestion) -> Vec<u8> {
    let mut serialized = serialize_qname(&question.qname);
    serialized.extend_from_slice(&question.qtype.to_be_bytes());
    serialized.extend_from_slice(&question.qclass.to_be_bytes());
    serialized
}

async fn generate_dns_response_packet<P: DnsAnswerProvider>(
    questions: Vec<DnsQuestion>,
    original_header: DnsHeader,
    answer_provider: &P,
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
            header.an_count += 1;
            let qname_bytes = serialize_qname(&question.qname);
            let qclass:u16 = 1; // IN (Internet)
            let ttl:u32 = 300;

            if question.qtype == 16 {
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
            else if question.qtype == 1 {
                //TODO: figure a scheme for handling A records?
            }
        }
    }

    let serialized_header = serialize_dns_header(&header);
    response_packet.splice(0..0, serialized_header.iter().cloned());

    response_packet
}


fn parse_questions(
    mut remaining_data: &[u8],
    qd_count: u16,
) -> Result<Vec<DnsQuestion>, nom::Err<nom::error::Error<&[u8]>>> {
    let mut questions = Vec::new();
    for _ in 0..qd_count {
        match parse_dns_question(remaining_data) {
            Ok((new_remaining_data, question)) => {
                println!("Parsed question: {:?}", question);
                questions.push(question);
                remaining_data = new_remaining_data;
            }
            Err(err) => return Err(err),
        }
    }
    Ok(questions)
}

pub async fn handle_dns_packet<P: DnsAnswerProvider>(data: &[u8], answer_provider: &P) -> Vec<u8> {
    match DnsHeader::parse(data) {
        Ok((remaining_data, header)) => {
            println!("Parsed header: {:?}", header);
            let questions = if header.qd_count > 0 {
                match parse_questions(remaining_data, header.qd_count) {
                    Ok(qs) => qs,
                    Err(err) => {
                        println!("Failed to parse questions: {:?}", err);
                        return vec![]; //FIXME
                    }
                }
            } else {
                vec![] //FIXME
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
    use super::*;
    use async_trait::async_trait;

    struct DummyAnswerProvider;

    #[async_trait]
    impl DnsAnswerProvider for DummyAnswerProvider {
        async fn get_answer_async(&self, _question: DnsQuestion) -> Option<String> {
            Some("dummy_answer".to_string())
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
        let answer_provider = DummyAnswerProvider;
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
            qname: "example.eth".to_string(),
            qtype: 16, // TXT Record
            qclass: 1, // IN (Internet)
        }];
        let answer_provider = DummyAnswerProvider;
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
