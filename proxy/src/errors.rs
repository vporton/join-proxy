use actix_web::{http::{header::ContentType, StatusCode}, HttpResponse, ResponseError};
use http_for_actix::status::InvalidStatusCode;
use ic_agent::AgentError;
use thiserror::Error;
use std::fmt::{Debug, Display, Formatter};
use derive_more::From;

#[derive(Debug, Error, From)]
pub enum MyError {
    #[error("{0}")]
    Anyhow(Box<anyhow::Error>),
    #[error("{0}")]
    Io(std::io::Error),
    #[error("Invalid HTTP method")]
    InvalidMethod(http::method::InvalidMethod),
    #[error("Invalid HTTP response")]
    HttpResponse(reqwest::Response),
    #[error("Request error: {0}")]
    ReqwestError(reqwest::Error),
    #[error("Invalid HTTP status code")]
    InvalidStatus(InvalidStatusCode),
    #[error("Invalid HTTP header")]
    HeaderToStrForActix(http_for_actix::header::ToStrError),
    #[error("Invalid HTTP header")]
    HeaderToStr(http::header::ToStrError),
    // InvalidHeaderName(Box<http_for_actix::header::IntoHeaderName>),
    #[error("The DB is corrupted")]
    MyCorruptedDB(MyCorruptedDBError),
    #[error("Invalid HTTP header name")]
    InvalidHeaderName(InvalidHeaderNameError),
    #[error("Invalid HTTP header value")]
    InvalidHeaderValue(InvalidHeaderValueError),
    #[error("Invalid Base64 encoded data")]
    Base64Decode(base64::DecodeError),
    #[error("Candid error: {0}")]
    Candid(candid::Error),
    #[error("IC agent error: {0}")]
    Agent(AgentError),
    #[error("Invalid URI: {0}")]
    InvalidUri(http::uri::InvalidUri),
    // #[error("Auth error: {0}")]
    // Auth(oxide_auth::frontends::simple::endpoint::Error<Request>),
    #[error("Auth Web error: {0}")]
    Web(oxide_auth_actix::WebError),
}

#[derive(Debug, Default, Error)]
pub struct MyCorruptedDBError {}

impl Display for MyCorruptedDBError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Wrong data in DB.")
    }
}

#[derive(Debug, Default, Error)]
pub struct InvalidHeaderNameError {}

impl Display for InvalidHeaderNameError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid header name.")
    }
}

#[derive(Debug, Default, Error)]
pub struct InvalidHeaderValueError {}

impl Display for InvalidHeaderValueError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid header value.")
    }
}

impl From<anyhow::Error> for MyError {
    fn from(err: anyhow::Error) -> Self {
        Self::Anyhow(Box::new(err))
    }
}

impl ResponseError for MyError {
    fn status_code(&self) -> StatusCode {
        StatusCode::BAD_REQUEST
    }
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code())
            .insert_header(ContentType::plaintext())
            .body(format!("{}", self.to_string()))
    }
}

pub type MyResult<T> = Result<T, MyError>;