use std::vec::Vec;
use std::{fs::File, io::BufReader};

use actix_web::{
    body::MessageBody,
    web::{self, Query},
    App, HttpRequest, HttpResponse, HttpServer,
};
use anyhow::anyhow;
use anyhow::Context;
use clap::Parser;
use derive_more::From;
use log::info;
use rustls::ServerConfig;
use rustls_pemfile::{certs, pkcs8_private_keys};
use serde_derive::Deserialize;
use thiserror::Error;

#[derive(clap::Parser, Debug)]
#[command(version, about, long_about = None)]
struct Flags {
    #[arg(short, long = "config", default_value = "8081")]
    port: u16,
}

#[derive(Deserialize)]
struct TestServerArgs {
    arg: String,
}

async fn test_page(
    req: HttpRequest,
    args: Query<TestServerArgs>,
    body: web::Bytes,
) -> Result<HttpResponse, Box<dyn std::error::Error + 'static>> {
    let b = body
        .try_into_bytes()
        .or_else(|_| Err(anyhow!("cannot read body")))?;
    let res = format!(
        "path={}&arg={}&body={}",
        req.uri().path(),
        args.arg,
        String::from_utf8(Vec::from(&*b))?
    );
    info!(
        "Test server serving: {}",
        req.uri()
            .path_and_query()
            .ok_or_else(|| anyhow!("error in path or query"))?
    );
    Ok(HttpResponse::Ok().content_type("text/plain").body(res))
}

async fn return_headers(
    req: HttpRequest,
) -> Result<HttpResponse, Box<dyn std::error::Error + 'static>> {
    let mut res = "".to_string();
    for (k, v) in req.headers() {
        res += format!("{}: {}\n", k.as_str(), v.to_str()?).as_str();
    }
    Ok(HttpResponse::Ok().content_type("text/plain").body(res))
}

#[derive(Debug, Error, From)]
pub enum MyError {
    #[error("{0}")]
    Anyhow(Box<anyhow::Error>),
    #[error("{0}")]
    Io(std::io::Error),
}

impl From<anyhow::Error> for MyError {
    fn from(err: anyhow::Error) -> Self {
        Self::Anyhow(Box::new(err))
    }
}

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let args = Flags::parse();

    let cert_file =
        &mut BufReader::new(File::open("localhost.crt").context("Can't read HTTPS cert.")?);
    let key_file = &mut BufReader::new(
        File::open("localhost.decrypted.key").context("Can't read HTTPS key.")?,
    );
    let cert_chain = certs(cert_file)
        .collect::<Result<Vec<_>, _>>()
        .context("Can't parse HTTPS certs chain.")?;
    let key = pkcs8_private_keys(key_file)
        .next()
        .transpose()?
        .ok_or(anyhow!("No private key in the file."))?;

    HttpServer::new(|| {
        App::new()
            .route("/headers", web::post().to(return_headers))
            .service(
                // Define the general routes within a scope
                web::scope("/{_:.*}")
                    .route("", web::get().to(test_page))
                    .route("", web::post().to(test_page))
                    .route("/{tail:.*}", web::get().to(test_page))
                    .route("/{tail:.*}", web::post().to(test_page)),
            )
    })
    .bind_rustls_0_23(
        format!("local.vporton.name:{}", args.port),
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, rustls::pki_types::PrivateKeyDer::Pkcs8(key))?,
    )?
    .run()
    .await
    .map_err(|e| e.into())
}
