use clap::Parser;
use dns::DnsName;
use ethers::prelude::*;

use async_trait::async_trait;
use tokio::net::UdpSocket;
use once_cell::sync::Lazy;

use crate::dns::DnsError;


mod dns;
mod cli;

struct EthersAnswerProvider<T: Send + Sync> {
    provider: ethers::providers::Provider<T>,
}

//maybe these should be prepended by something?
const ENS_RECORD_SERVICES: Lazy<Vec<DnsName>> = Lazy::new(|| {
    let v: Vec<String> = vec![
    "_atproto".to_string(), //bsky
    "avatar".to_string(),
    "description".to_string(),
    "display".to_string(),
    "email".to_string(),
    "keywords".to_string(),
    "mail".to_string(),
    "notice".to_string(),
    "location".to_string(),
    "phone".to_string(),
    "url".to_string(),
    "com.github".to_string(),
    "com.peepeth".to_string(),
    "com.linkedin".to_string(),
    "com.twitter".to_string(),
    "io.keybase".to_string(),
    "org.telegram".to_string()
    ];
    
    v.iter().map(|x| DnsName::from(x.to_string())).collect()
});

#[async_trait]
impl<'a, T: Send + Sync + JsonRpcClient> dns::DnsAnswerProvider for EthersAnswerProvider<T> {
    async fn get_answer_async(&self, question: dns::DnsQuestion) -> Option<String> {
        let binding = ENS_RECORD_SERVICES;
        let svcname_dnsrecord_a = DnsName::from("A".to_string());
        let svcname_dnsrecord_aaaa = DnsName::from("AAAA".to_string());

        let svc: Option<&DnsName> = match question.qtype {
            1 => {
                Some(&svcname_dnsrecord_a)
            },
            28 => {
                Some(&svcname_dnsrecord_aaaa)
            },
            _ => {
                binding
                .iter()
                .filter(|x| x.is_label_of(&question.qname))
                .next()
            }
        };
        
        
        println!("svc {:?}", svc);
        let res = match svc {
            Some(x) => {
                let name = question.qname.clone().remove_prefix_labels(x).or(Some(question.qname.clone()))?;
                self
                    .provider
                    .resolve_field(&name.punycode_decode()?, &x.punycode_decode()?)
                    .await.map_err(DnsError::from)
            }
            None => Err(DnsError::ErrNoServiceTypeRecognized)
        };
        match res {
            Ok(r) => if r.len() > 0 {
                Some(r)
            } else {
                None
            },
            Err(e) => {
                println!("error resolving {:?} {:?}", question.qname, e);
                None
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    let opts = cli::Opts::parse();
    let resolved_opts = cli::ResolvedOpts::<ethers::providers::Http>::try_from(opts)?;

    let socket = UdpSocket::bind(resolved_opts.udp_bind).await?;
    println!("Listening on: {}", socket.local_addr()?);

    let block_time = resolved_opts.provider.get_block(BlockNumber::Latest).await?.map(|block| block.timestamp);
    let chain_id = resolved_opts.provider.get_chainid().await?;

    println!("Current block time: {:?}, Chain ID: {:?}", block_time.unwrap(), chain_id);
    let answer_provider = EthersAnswerProvider {
        provider: resolved_opts.provider
    };

    let mut buf = [0u8; 1024];

    loop {
        let (size, src) = socket.recv_from(&mut buf).await?;
        let data = &buf[0..size];

        let response_packet = dns::handle_dns_packet(data.to_vec(), &answer_provider).await;

        if !response_packet.is_empty() {
            socket.send_to(&response_packet, &src).await?;
        }
    }
}
