use async_trait::async_trait;
use nom::{
    number::complete::{be_u16, be_u8},
    IResult, bytes::complete::take,
};

pub trait Parseable<'a, T> {
    fn parse(input: &'a [u8]) -> IResult<&[u8], T>;
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


impl<'a> Parseable<'a, DnsHeader> for DnsHeader {
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

impl<'a> Parseable<'a, DnsFlags> for DnsFlags {
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
pub struct DnsLabel<'a> {
    pub label: &'a [u8],
}

impl<'a> From<&'a str> for DnsLabel<'a> {
    fn from(label: &'a str) -> Self {
        DnsLabel { label: label.as_bytes() }
    }
}

impl<'a> DnsLabel<'a> {
    pub fn punycode_decode(&self) -> Option<String> {
        if self.label.len() >= 4 && &self.label[0..4] == b"xn--" {
            let decoded = punycode::decode(String::from_utf8(self.label[4..].to_vec()).ok()?.as_str()).ok()?;
            Some(decoded)
        } else {
            String::from_utf8(self.serialize().to_vec()).ok()
        }
    }
}

impl<'a> Parseable<'a, DnsLabel<'a>> for DnsLabel<'a> {
    fn parse(input: &[u8]) -> IResult<&[u8], DnsLabel> {
        let (input, len) = be_u8(input)?;
        println!("len {:?}", len);
        let (input, label) = take(len)(input)?;
        Ok((input, DnsLabel { label }))
    }
    fn serialize(&self) -> Vec<u8> {
        let mut serialized = Vec::new();
        serialized.push(self.label.len() as u8);
        serialized.extend_from_slice(self.label);
        serialized
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsName<'a> {
    pub labels: Vec<DnsLabel<'a>>,
}

impl<'a> From<&'a str> for DnsName<'a> {
    fn from(name: &'a str) -> Self {
        let labels = name
            .split(".")
            .map(|label| DnsLabel::from(label))
            .collect::<Vec<DnsLabel>>();
        DnsName { labels }
    }
}

impl<'a> DnsName<'a> {
    pub fn is_label_of(&self, other: &DnsName) -> bool {
        if self.labels.len() > other.labels.len() {
            return false;
        }
        let mut self_iter = self.labels.iter();
        let mut other_iter = other.labels.iter();
        loop {
            match (self_iter.next(), other_iter.next()) {
                (Some(self_label), Some(other_label)) => {
                    if self_label.label != other_label.label {
                        return false;
                    }
                }
                (Some(_), None) => return false,
                (None, Some(_)) => return true,
                (None, None) => return true,
            }
        }
    }

    pub fn remove_prefix_labels(&self, prefix: &DnsName) -> Option<DnsName> {
        if !self.is_label_of(prefix) {
            return None;
        }
        let mut self_iter = self.labels.iter();
        let mut prefix_iter = prefix.labels.iter();
        let mut new_labels = Vec::new();
        loop {
            match (self_iter.next(), prefix_iter.next()) {
                (Some(self_label), Some(prefix_label)) => {
                    if self_label.label != prefix_label.label {
                        return None;
                    }
                }
                (Some(self_label), None) => {
                    new_labels.push(self_label.clone());
                }
                (None, Some(_)) => return None,
                (None, None) => break,
            }
        }
        Some(DnsName { labels: new_labels })
    }

    pub fn punycode_decode(&self) -> Option<String> {
        let mut decoded_labels = Vec::new();
        for label in &self.labels {
            let decoded = label.punycode_decode()?;
            decoded_labels.push(decoded);
        }
        Some(decoded_labels.join("."))
    }
}

impl<'a> Parseable<'a, DnsName<'a>> for DnsName<'a> {
    fn parse(input: &[u8]) -> IResult<&[u8], DnsName> {
        let mut labels = Vec::new();
        let mut remaining_input = input;
        loop {
            println!("{:?}", remaining_input);
            let (input, label) = DnsLabel::parse(remaining_input)?;
            remaining_input = input;
            if label.label.is_empty() {
                break;
            }
            labels.push(label);
        }
        Ok((remaining_input, DnsName { labels }))
    }
    fn serialize(&self) -> Vec<u8> {
        let mut serialized = Vec::new();
        for label in &self.labels {
            serialized.extend_from_slice(&label.serialize());
        }
        serialized.push(0); // Null byte to end QNAME
        serialized
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion<'a> {
    pub qname: DnsName<'a>,
    pub qtype: u16,
    pub qclass: u16,
}

impl<'a> Parseable<'a, DnsQuestion<'a>> for DnsQuestion<'a> {
    fn parse(input: &[u8]) -> IResult<&[u8], DnsQuestion> {
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
    fn serialize(&self) -> Vec<u8> {
        let mut serialized = DnsName::serialize(&self.qname);
        serialized.extend_from_slice(&self.qtype.to_be_bytes());
        serialized.extend_from_slice(&self.qclass.to_be_bytes());
        serialized
    }
}

#[async_trait]
pub trait DnsAnswerProvider<'a>: Send + Sync {
    async fn get_answer_async(&self, question: DnsQuestion<'a>) -> Option<String>;
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
    let mut serialized = DnsName::serialize(&question.qname);
    serialized.extend_from_slice(&question.qtype.to_be_bytes());
    serialized.extend_from_slice(&question.qclass.to_be_bytes());
    serialized
}

async fn generate_dns_response_packet<'a, P: DnsAnswerProvider<'a>>(
    questions: Vec<DnsQuestion<'a>>,
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
            header.an_count += 1;
            let qname_bytes = DnsName::serialize(&question.qname);
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

    let serialized_header = DnsHeader::serialize(&header);
    response_packet.splice(0..0, serialized_header.iter().cloned());

    response_packet
}


pub async fn handle_dns_packet<'a, P: DnsAnswerProvider<'a>>(data: &'a [u8], answer_provider: &'a P) -> Vec<u8> {
    match DnsHeader::parse(data) {
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

    struct DummyAnswerProvider<'a> {
        _lifetime: PhantomData<&'a ()>
    }

    #[async_trait]
    impl<'a> DnsAnswerProvider<'a> for DummyAnswerProvider<'a> {
        async fn get_answer_async(&self, _question: DnsQuestion<'a>) -> Option<String> {
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
            qname: DnsName::parse("example.eth".as_bytes()).unwrap().1,
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
