use clap::{command, Parser};
use ic_agent::export::Principal;
use serde::Deserializer;
use serde_derive::Deserialize;
use serde::de::Error;
use std::time::Duration;

#[derive(Clone, Deserialize, Debug)]
pub struct Callback {
    #[serde(deserialize_with = "deserialize_canister_id")]
    pub canister: Principal,
    pub func: String,
    #[serde(default="default_ic_local")]
    pub ic_local: bool,
    pub ic_url: Option<String>,
}

#[derive(Clone, Deserialize, Debug/*, Default*/)] // https://github.com/serde-rs/serde/issues/3002
pub struct UpstreamTimeouts {
    #[serde(default="default_upstream_connect_timeout", deserialize_with = "parse_duration_option")]
    pub connect_timeout: Option<Duration>,
    #[serde(default="default_upstream_read_timeout", deserialize_with = "parse_duration_option")]
    pub read_timeout: Option<Duration>,
    #[serde(default="default_upstream_total_timeout", deserialize_with = "parse_duration_option")]
    pub total_timeout: Option<Duration>,
}

#[derive(Clone, Deserialize, Debug, Default)]
pub struct CacheConfig {
    #[serde(deserialize_with = "parse_duration")]
    pub cache_timeout: Duration,
}

#[derive(Clone, Deserialize, Debug, Default)]
pub struct Serve {
    // #[serde(default="default_host")]
    pub host: String,
    // #[serde(default="default_port")]
    pub port: u16,
    // #[serde(default="default_https")]
    pub https: bool,
}

#[derive(Clone, Debug, /*Default,*/ Deserialize)] // https://github.com/serde-rs/serde/issues/3002
pub struct Config {
    #[serde(default="default_proxy_serve")]
    pub bind_proxy: Serve,
    #[serde(default="default_api_serve")]
    pub bind_api: Serve,
    pub our_secret: Option<String>, // simple Bearer authentication
    pub require_x_principal: bool,
    pub cache: CacheConfig,
    pub upstream_timeouts: UpstreamTimeouts,
    pub callback: Option<Callback>,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
}

#[derive(Parser)]
#[command(version, name = "join-proxy", about = "A deduplication proxy for ICP")]
pub struct Args {
    #[arg(short, long="config", help="Config file")]
    pub config_file: Option<String>,
    #[arg(long="proxy.host", help="Bind proxy to host")]
    pub bind_proxy_host: Option<String>,
    #[arg(long="proxy.port", help="Bind proxy to port")]
    pub bind_proxy_port: Option<u16>,
    #[arg(long="proxy.https", help="Bind proxy to SSL")]
    pub bind_proxy_https: Option<bool>,
    #[arg(long="api.host", help="Bind API endpoint to host")]
    pub bind_api_host: Option<String>,
    #[arg(long="api.port", help="Bind API endpoint to port")]
    pub bind_api_port: Option<u16>,
    #[arg(long="api.https", help="Bind API endpoint to SSL")]
    pub bind_api_https: Option<bool>,
    #[arg(long="our-secret", help="Secret to check by proxy (not secure by alone)")]
    pub our_secret: Option<String>, // simple Bearer authentication
    #[arg(long="require-x-principal", help="Require `X-Principal:` header")]
    pub require_x_principal: Option<bool>,
    #[arg(long="timeout.cache", value_parser = extract_duration_simple, help="Cache timeout")]
    pub cache_timeout: Option<Duration>,
    #[arg(long="timeout.connect", value_parser = extract_duration_simple, help="Connect to upstream timeout")]
    pub connect_timeout: Option<Duration>,
    #[arg(long="timeout.read", value_parser = extract_duration_simple, help="Read from upstream timeout")]
    pub read_timeout: Option<Duration>,
    #[arg(long="timeout.total", value_parser = extract_duration_simple, help="Total upstream timeout")]
    pub total_timeout: Option<Duration>,
}

fn default_proxy_serve() -> Serve {
    Serve {
        host: "localhost".to_string(),
        port: 8080,
        https: false,
    }
}

fn default_api_serve() -> Serve {
    Serve {
        host: "localhost".to_string(),
        port: 8084,
        https: false,
    }
}

fn default_upstream_connect_timeout() -> Option<Duration> {
    Some(Duration::from_secs(10))
}

fn default_upstream_read_timeout() -> Option<Duration> {
    Some(Duration::from_secs(60)) // I set it big, for the use case of OpenAI API
}

fn default_upstream_total_timeout() -> Option<Duration> {
    Some(Duration::from_secs(120)) // I set it big, for the use case of OpenAI API
}

fn default_ic_local() -> bool {
    false
}

fn extract_duration_simple(s: &str) -> Result<Duration, String> { // TODO@P3: Can use `&str` instead?
    let pos = s.find(|c: char| !c.is_numeric()).unwrap_or(s.len());
    let (value_str, unit) = s.split_at(pos);

    let value: u64 = value_str.parse().map_err(|_| "Can't extract number")?;

    match unit {
        "d" => Ok(Duration::from_secs(value*3600*24)),
        "h" => Ok(Duration::from_secs(value*3600)),
        "m" => Ok(Duration::from_secs(value*60)),
        "s" => Ok(Duration::from_secs(value)),
        "ms" => Ok(Duration::from_millis(value)),
        _ => Err("Invalid duration unit".to_string()),
    }
}

fn extract_duration<'de, D>(s: &str) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    extract_duration_simple(s).map_err(|_| serde::de::Error::custom("Invalid duration unit"))
}

fn parse_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = serde::Deserialize::deserialize(deserializer)?;
    extract_duration::<D>(s.as_str())
}

fn parse_duration_option<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = serde::Deserialize::deserialize(deserializer)?;
    Ok(if let Some(s) = opt {
        Some(extract_duration::<D>(s.as_str())?)
    } else {
        None
    })
}

fn deserialize_canister_id<'de, D>(deserializer: D) -> Result<Principal, D::Error>
where
    D: Deserializer<'de>,
{
    let input: String = serde::Deserialize::deserialize(deserializer)?;
    match Principal::from_text(input) {
        Ok(principal) => Ok(principal),
        Err(principal_error) =>
            Err(D::Error::custom(format!("Invalid principal: {}", principal_error))),
    }
}

impl Config {
    pub fn update_from_args(&mut self, cli: Args) {
        if let Some(proxy_host) = cli.bind_proxy_host {
            self.bind_proxy.host = proxy_host;
        }
        if let Some(proxy_port) = cli.bind_proxy_port {
            self.bind_proxy.port = proxy_port;
        }
        if let Some(proxy_https) = cli.bind_proxy_https {
            self.bind_proxy.https = proxy_https;
        }
        if let Some(api_host) = cli.bind_api_host {
            self.bind_api.host = api_host;
        }
        if let Some(api_port) = cli.bind_api_port {
            self.bind_api.port = api_port;
        }
        if let Some(api_https) = cli.bind_api_https {
            self.bind_api.https = api_https;
        }
        if let Some(our_secret) = cli.our_secret {
            self.our_secret = Some(our_secret);
        }
        if let Some(require_x_principal) = cli.require_x_principal {
            self.require_x_principal = require_x_principal;
        }
        if let Some(cache_timeout) = cli.cache_timeout {
            self.cache.cache_timeout = cache_timeout;
        }
        if let Some(connect_timeout) = cli.connect_timeout {
            self.upstream_timeouts.connect_timeout = Some(connect_timeout);
        }
        if let Some(read_timeout) = cli.read_timeout {
            self.upstream_timeouts.read_timeout = Some(read_timeout);
        }
        if let Some(total_timeout) = cli.total_timeout {
            self.upstream_timeouts.total_timeout = Some(total_timeout);
        }
    }
}