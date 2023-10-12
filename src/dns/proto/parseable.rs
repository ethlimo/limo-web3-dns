use nom::IResult;

pub trait Parseable<T> {
    fn parse(input: &[u8]) -> IResult<&[u8], T>;
    fn serialize(&self) -> Vec<u8>;
}