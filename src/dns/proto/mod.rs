use async_trait::async_trait;
use nom::{IResult, number::complete::{be_u16, be_u8}, bytes::complete::take};

pub use self::parseable::Parseable;

mod parseable;

#[derive(Debug, Clone, Eq, PartialEq, Copy)]
pub struct DnsFlags {
    pub qr: bool,      // Query/Response
    pub opcode: Opcode,  // Opcode
    pub aa: bool,      // Authoritative Answer
    pub tc: bool,      // Truncation
    pub rd: bool,      // Recursion Desired
    pub ra: bool,      // Recursion Available
    pub rcode: RCode,   // Response Code
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: DnsFlags,
    pub qd_count: u16,
    pub an_count: u16,
    pub ns_count: u16,
    pub ar_count: u16,
}


impl<'a> Parseable<DnsHeader> for DnsHeader {
    fn parse(input: &[u8]) -> IResult<&[u8], DnsHeader> {
        let (input, id) = be_u16(input)?;
        let (input, flags) = DnsFlags::parse(input.into())?;
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
pub enum Opcode {
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
pub enum RCode {
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

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct DnsLabel {
    pub label: Vec<u8>,
}

impl From<String> for DnsLabel {
    fn from(label: String) -> Self {
        DnsLabel { label: label.into_bytes() }
    }
}

impl<'a> DnsLabel {
    pub fn punycode_decode(&self) -> Option<String> {
        if self.label.len() >= 4 && &self.label[0..4] == b"xn--" {
            let decoded = punycode::decode(String::from_utf8(self.label[4..].to_vec()).ok()?.as_str()).ok()?;
            Some(decoded)
        } else {
            String::from_utf8(self.serialize().to_vec()).ok()
        }
    }
}

impl Parseable<DnsLabel> for DnsLabel {
    fn parse(input: &[u8]) -> IResult<&[u8], DnsLabel> {
        let (input, len) = be_u8(input)?;
        println!("len {:?}", len);
        let (input, label) = take(len)(input)?;
        Ok((input, DnsLabel { label: label.to_vec() }))
    }
    fn serialize(&self) -> Vec<u8> {
        let mut serialized = Vec::new();
        serialized.push(self.label.len() as u8);
        serialized.extend_from_slice(self.label.as_slice());
        serialized
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DnsName {
    pub labels: Vec<DnsLabel>,
}

impl From<String> for DnsName {
    fn from(name: String) -> Self {
        let labels = name
            .split(".")
            .map(|label| DnsLabel::from(label.to_string()))
            .collect::<Vec<DnsLabel>>();
        DnsName { labels: labels }
    }
}

impl<'a> DnsName {
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
        let mut new_labels: Vec<DnsLabel> = Vec::new();
        loop {
            match (self_iter.next(), prefix_iter.next()) {
                (Some(self_label), Some(prefix_label)) => {
                    if self_label.label != prefix_label.label {
                        return None;
                    }
                }
                (Some(self_label), None) => {
                    new_labels.push( self_label.clone());
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


impl<'a> Parseable<DnsName> for DnsName {
    fn parse(input: &[u8]) -> IResult<&[u8], DnsName> {
        let mut labels = Vec::new();
        let mut remaining_input = input;
        loop {
            println!("{:?}", remaining_input);
            let (input, label) = DnsLabel::parse(remaining_input)?;
            remaining_input = &input;
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

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DnsQuestion {
    pub qname: DnsName,
    pub qtype: u16,
    pub qclass: u16,
}

impl<'a> Parseable<DnsQuestion> for DnsQuestion {
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
        let mut serialized = DnsName::serialize(&self.qname).to_vec();
        serialized.extend_from_slice(&self.qtype.to_be_bytes());
        serialized.extend_from_slice(&self.qclass.to_be_bytes());
        serialized
    }
}

#[async_trait]
pub trait DnsAnswerProvider: Send + Sync {
    async fn get_answer_async(&self, question: DnsQuestion) -> Option<String>;
}