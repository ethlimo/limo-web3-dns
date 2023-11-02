use clap::Parser;
use url::ParseError;
use std::error::Error;
use std::fmt::{Display, Debug};
use std::net::SocketAddr;
use std::env;

#[derive(Parser)]
#[clap(version = "0.1.0", author = "eth.limo")]
pub(crate) struct Opts {
    #[clap(short, long, env = "RPC_ENDPOINT")]
    rpc_endpoint: Option<String>,
    #[clap(short, long, env = "UDP_BIND", default_value = "127.0.0.1:53")]
    udp_bind: String,
}

pub(crate) struct ResolvedOpts<T> {
    pub provider: ethers::providers::Provider<T>,
    pub udp_bind: String,
}

pub(crate) enum OptionsError {
    InvalidRpcEndpoint(ParseError),
    InvalidUdpAddress,
}

impl Debug for OptionsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OptionsError::InvalidRpcEndpoint(e) => write!(f, "Invalid RPC endpoint: {}", e),
            OptionsError::InvalidUdpAddress => write!(f, "Invalid UDP address"),
        }
    }
}

impl Display for OptionsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OptionsError::InvalidRpcEndpoint(e) => write!(f, "Invalid RPC endpoint: {}", e),
            OptionsError::InvalidUdpAddress => write!(f, "Invalid UDP address"),
        }
    }
}

impl Error for OptionsError {}

impl TryFrom<Opts> for ResolvedOpts<ethers::providers::Http> {
    type Error = OptionsError;
    fn try_from(opts: Opts) -> Result<Self, Self::Error> {
        let rpc_endpoint = opts.rpc_endpoint.or_else(|| env::var("RPC_ENDPOINT").ok());
        let provider = match rpc_endpoint {
            Some(endpoint) => {
                ethers::providers::Provider::try_from(endpoint)
            },
            None => {
                Ok(ethers::providers::SEPOLIA.provider())
            }
        };
        
        let udp_addr = opts.udp_bind.parse::<SocketAddr>().map_err(|_| OptionsError::InvalidUdpAddress)?;
        let udp_bind = udp_addr.to_string();

        Ok(ResolvedOpts {
            provider: provider.map_err(|x| OptionsError::InvalidRpcEndpoint(x))?,
            udp_bind,
        })
    }
}
