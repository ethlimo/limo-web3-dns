use dns::DnsName;
use ethers::prelude::*;

use async_trait::async_trait;
use tokio::net::UdpSocket;
use once_cell::sync::Lazy;


mod dns;


struct EthersAnswerProvider<T: Send + Sync> {
    provider: ethers::providers::Provider<T>,
}

//maybe these should be prepended by something?
const ENS_RECORD_SERVICES: Lazy<Vec<DnsName>> = Lazy::new(|| {
    vec![
    "_atproto", //bsky
    "avatar",
    "description",
    "display",
    "email",
    "keywords",
    "mail",
    "notice",
    "location",
    "phone",
    "url",
    "com.github",
    "com.peepeth",
    "com.linkedin",
    "com.twitter",
    "io.keybase",
    "org.telegram"
    ].iter().map(|x: &&'static str| DnsName::from(*x)).collect()
});

#[async_trait]
impl<'a, T: Send + Sync + JsonRpcClient> dns::DnsAnswerProvider<'a> for EthersAnswerProvider<T> {
    async fn get_answer_async(&self, question: dns::DnsQuestion<'a>) -> Option<String> {
        let binding = ENS_RECORD_SERVICES;
        let svc = binding
            .iter()
            .filter(|x| question.qname.is_label_of(*x))
            .next();
        println!("{:?}", svc);
        match svc {
            Some(x) => {
                let res = self
                    .provider
                    .resolve_field(&question.qname.remove_prefix_labels(x).unwrap().punycode_decode()?, &x.punycode_decode()?)
                    .await;
                match res {
                    Ok(r) => if r.len() > 0 {
                        Some(r)
                    } else {
                        None
                    },
                    Err(e) => {
                        println!("error resolving {:?} {:?} {:?}", x, question.qname, e);
                        None
                    }
                }
            }
            None => None,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    let socket = UdpSocket::bind("0.0.0.0:5353").await?;
    println!("Listening on: {}", socket.local_addr()?);

    let answer_provider = EthersAnswerProvider {
        provider: ethers::providers::test_provider::MAINNET.provider(),
    };

    let mut buf = [0u8; 1024];

    loop {
        let (size, src) = socket.recv_from(&mut buf).await?;
        let data = &buf[0..size];

        let response_packet = dns::handle_dns_packet(data, &answer_provider).await;

        if !response_packet.is_empty() {
            socket.send_to(&response_packet, &src).await?;
        }
    }
}
