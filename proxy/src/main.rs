mod api;
mod auth;
mod errors;
mod cache;
mod config;
mod schema;
mod models;

use std::{collections::{btree_map::Entry, BTreeMap}, fs::{read_to_string, File}, io::BufReader, str::{from_utf8, FromStr}, sync::Arc};
use actix::Actor;
use diesel::{Connection, ExpressionMethods, PgConnection, QueryDsl, RunQueryDsl};
use log::info;
use rustls::{crypto::ring, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use actix_web::{http::StatusCode, web::{self, Data}, App, HttpResponse, HttpServer};
use anyhow::{anyhow, Context};
use cache::{cache::BinaryCache, mem_cache::BinaryMemCache};
use clap::Parser;
use errors::{InvalidHeaderNameError, InvalidHeaderValueError, MyCorruptedDBError, MyResult};
use reqwest::ClientBuilder;
use ic_agent::Agent;
use candid::{Decode, Encode, Principal};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use anyhow::bail;

use crate::{auth::{authorize, refresh, token}, config::{Args, Config}, errors::MyError};

struct State {
    client: reqwest::Client,
    agent: Option<Agent>,
    conn: tokio::sync::Mutex<PgConnection>,
}

// Two similar functions with different data types follow:

fn serialize_http_request(request: &actix_web::HttpRequest, url: &str, bytes: &actix_web::web::Bytes) -> anyhow::Result<Vec<u8>> {
    // Actix convert headers to lowercase.
    let mut headers = BTreeMap::new();
    for (k, v) in request.headers().into_iter() { // lexicographical order
        let entry = headers.entry(k.as_str());
        let v_str = v.to_str()?;
        match entry {
            Entry::Vacant(vacant_entry) => {
                vacant_entry.insert(vec![v_str]);
            }
            Entry::Occupied(mut occupied_entry) => {
                occupied_entry.get_mut().push(v_str);
            }
        }
    }
    let headers_list = headers.into_iter()
        .map(|(k, v)| k.to_string() + "\t" + &v.join("\t"))
        .collect::<Vec<_>>();
    let headers_joined = headers_list.into_iter().reduce(|a, b| a + "\r" + &b);
    let headers_joined = headers_joined.unwrap_or_else(|| "".to_string());
    let header_part = request.method().as_str().to_owned() + "\n" + url + "\n" + &headers_joined;

    Ok([header_part.as_bytes(), b"\n", bytes.to_vec().as_slice()].concat())
}

async fn serialize_http_response(response: reqwest::Response) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let headers_list = response.headers().into_iter()
        .map(|(k, v)| -> anyhow::Result<String> {
            Ok(k.to_string() + "\t" + v.to_str()?)
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let headers_joined = headers_list.into_iter().reduce(|a, b| a + "\r" + &b);
    let headers_joined = headers_joined.unwrap_or_else(|| "".to_string());
    let header_part = response.status().as_u16().to_string() + "\n" + &headers_joined;

    let bytes = response.bytes().await?;
    Ok(([header_part.as_bytes(), b"\n", &bytes].concat(), bytes.to_vec())) // TODO: `bytes` is passed two times.
}

fn deserialize_http_response(data: &[u8]) -> anyhow::Result<actix_web::HttpResponse<Vec<u8>>> {
    let mut iter1 = data.splitn(3, |&c| c == b'\n');
    let status_code_bytes = iter1.next().ok_or_else(|| MyCorruptedDBError::default())?;
    let headers_bytes = iter1.next().ok_or_else(|| MyCorruptedDBError::default())?;
    let body = iter1.next().ok_or_else(|| MyCorruptedDBError::default())?;

    let status_code: u16 = str::parse(from_utf8(status_code_bytes)?)?;
    let mut response = actix_web::HttpResponse::with_body(
        StatusCode::from_u16(status_code)?, Vec::from(body));

    let headers = response.headers_mut();
    for header_str in headers_bytes.split(|&c| c == b'\r') {
        let mut iter2 = header_str.splitn(2, |&c| c == b'\t');
        let k = iter2.next().ok_or_else(|| MyCorruptedDBError::default())?;
        let v = iter2.next().ok_or_else(|| MyCorruptedDBError::default())?;
        headers.append(http_for_actix::HeaderName::from_bytes(k)?, http_for_actix::HeaderValue::from_bytes(v)?);
    }

    Ok(response)
}

fn obtain_upstream_base_url(req: &actix_web::HttpRequest) -> anyhow::Result<String> {
    let host = req.headers().get("host")
        .ok_or_else(|| anyhow!("Missing Host: header"))?
        .to_str()?;
    Ok("https://".to_string() + host)
}

async fn proxy(
    req: actix_web::HttpRequest,
    body: web::Bytes,
    config: Data<Config>,
    cache: Data<Arc<tokio::sync::Mutex<Box<BinaryCache>>>>,
    state: Data<State>, 
)
    -> MyResult<actix_web::HttpResponse<Vec<u8>>>
{
    let path = req.uri().path_and_query().ok_or(anyhow!("can't get path and query"))?.as_str();
    info!("Joining proxy received a request to {}", path);
    // First level of defense: X-JoinProxy-Key can be stolen by an IC replica owner:
    if let Some(our_secret) = &config.our_secret {
        let passed_key = req.headers()
            .get("x-joinproxy-key")
            .map(|v| v.to_str().map_err(|_| anyhow!("Cannot read header X-JoinProxy-Key")))
            .transpose()?;
        if passed_key != Some(&("Bearer ".to_string() + &our_secret)) {
            return Ok(HttpResponse::with_body(StatusCode::NETWORK_AUTHENTICATION_REQUIRED, Vec::new()));
        }
    }

    // TODO: Test that it works for paths like `/xx?` with question sign but without arguments.
    // TODO: Check that https://example.com and https://example.com/ are exchangeable.
    let serialized_request = serialize_http_request(&req, path, &body)?;
    let actix_request_hash = Sha256::digest(serialized_request.as_slice());

    let mut cache = (***cache).lock().await; // FIXME: locked for too long

    // We lock during the time of downloading from upstream to prevent duplicate requests with identical data.
    let mut cache_lock = cache.lock(&Vec::from(actix_request_hash.as_slice())).await?;

    if let Some(serialized_response) = (*cache_lock).inner().await {
        std::mem::drop(cache_lock);
        info!("Cache hit.");

        let /*mut*/ response = deserialize_http_response(serialized_response.as_slice())?;
        // if config.response_headers.show_hit_miss { // TODO: Can't show `Hit` by default.
        //     response.headers_mut().append(
        //         http_for_actix::HeaderName::from_str("X-JoinProxy-Response").unwrap(),
        //         http_for_actix::HeaderValue::from_str("Hit").unwrap(),
        //     );
        // }
        Ok(response)
    } else {
        info!("Cache miss.");

        // Second level of defense: Ask back the calling canister.
        // Do it only once per outcall (our response content isn't secure anyway).
        if let (Some(agent), Some(callback)) = (&state.agent, &config.callback) {
            info!("Callback...");
            let res = agent.update(&callback.canister, &callback.func)
                .with_arg(Encode!(&actix_request_hash.as_slice())?).call_and_wait().await;
            match res {
                Ok(res) => {
                    Decode!(res.as_slice()).context("Callback decode")?; // checking for errors
                    info!("Callback OK.");
                }
                Err(e) => {
                    info!("Callback failed: {e}");
                    Err(e)?;
                }
            }
        }

        let base_url = obtain_upstream_base_url(&req)?;

        let caller_principal = req.headers().get_all("x-principal").next_back();
        // req.headers().remove("x-principal"); // TODO: Should remove only the last `X-Principal`. (Or is it removed by `next_back()`?)
        if config.require_x_principal && caller_principal.is_none() { // FIXME: Is `Some(true)` correct?
            return Err(anyhow!("missing X-Principal header").into());
        }
        // TODO: The below line is a hack.
        let serve_config_uid_s =
            if let Some(serve_config_uid) = req.headers().get("x-config") { // TODO: Use the last header, remove it.;
                if let Some(caller_principal) = caller_principal {
                    let caller_principal = Principal::from_text(caller_principal.to_str()?)
                        .map_err(|_| anyhow!("can't parse X-Principal"))?;
                    Some((serve_config_uid, caller_principal))
                } else {
                    None
                }
        } else {
            None
        };
        use self::schema::server_setups::dsl::*;
        use self::schema::users::dsl::*;
        use self::schema::add_response_headers::dsl::*;
        use self::schema::remove_response_headers::dsl::*;
        use self::schema::add_request_headers::dsl::*;
        use self::schema::remove_request_headers::dsl::*;
        let (actix_response, reqwest_response) = if let Some((serve_config_uid, caller_principal)) = serve_config_uid_s {
            let serve_config_uid_raw = serve_config_uid.to_str()?;
            let serve_config_uid = hex::decode(serve_config_uid_raw).map_err(|_| anyhow!("broken hex ID"))?;
            // TODO: Should JOIN two following SQL requests into one?
            let (
                a_server_setup_id,
                a_user_id,
                a_show_hit_miss,
                a_add_forwarded_from_header,
                // TODO:
                // a_connect_timeout,
                // a_read_timeout,
                // a_total_timeout,
            ) = server_setups
                .filter(guid.eq(serve_config_uid))
                .select((
                    self::schema::server_setups::dsl::id,
                    user_id,
                    show_hit_miss,
                    add_forwarded_from_header,
                    // connect_timeout,
                    // read_timeout,
                    // total_timeout,
                ))
                .get_result::<(i64, i32, bool, bool/*, i32, i32, i32*/)>(&mut *state.conn.lock().await)
                .map_err(|_| anyhow!(format!("no serve config with uid {serve_config_uid_raw}")))?;
            let a_user_principal: Principal = users.filter(self::schema::users::dsl::id.eq(a_user_id))
                .select(user_principal)
                .get_result::<Vec<u8>>(&mut *state.conn.lock().await)
                .map_err(|_| anyhow!(format!("no user with id {a_user_id}")))?
                .try_into()
                .map_err(|_| anyhow!(format!("wrong principal format")))?;
            if a_user_principal != caller_principal {
                return Err(anyhow!("access denied").into());
            }

            let additional_request_headers =  add_request_headers
                .filter(self::schema::add_request_headers::dsl::server_setup_id.eq(a_server_setup_id))
                .select((
                    self::schema::add_request_headers::dsl::header_name,
                    self::schema::add_request_headers::dsl::header_value,
                ))
                .get_results::<(String, String)>(&mut *state.conn.lock().await)
                .map_err(|_| anyhow!(format!("cannot read DB")))?
                .into_iter()
                .map(|h| (
                    // TODO: `unwrap()`
                    http_for_actix::HeaderName::from_str(&h.0).unwrap(),
                    http_for_actix::HeaderValue::from_str(&h.1).unwrap(),
                ))
                .collect::<Vec<_>>(); // TODO: Can this be refactored without `collect`?
            let request_headers_to_remove = remove_request_headers
                .filter(self::schema::remove_request_headers::dsl::server_setup_id.eq(a_server_setup_id))
                .select(
                    self::schema::remove_request_headers::dsl::header_name,
                )
                .get_results::<String>(&mut *state.conn.lock().await)
                .map_err(|_| anyhow!(format!("cannot read DB")))?;
            let request_headers = req.headers().into_iter()
                .filter(|h|
                    !request_headers_to_remove.contains(&h.0.to_string()) ||
                        h.0 == http_for_actix::HeaderName::from_static("host"))
                .map(|(k, v)| (k.clone(), v.clone()))
                .chain(
                    additional_request_headers.into_iter().map(|h| (h.0.clone(), h.1.clone()))
                );
            let request_headers = http::HeaderMap::from_iter(
                request_headers
                    .map(|h| -> MyResult<_> {
                        Ok((
                            http::HeaderName::from_str(h.0.as_str()).map_err(|_| InvalidHeaderNameError::default())?,
                            http::HeaderValue::from_str(h.1.to_str()?).map_err(|_| InvalidHeaderValueError::default())?,
                        ))
                    })
                    .into_iter()
                    .collect::<MyResult<Vec<_>>>()?
            );

            // TODO: duplicate block of code
            let method = reqwest::Method::from_bytes(req.method().as_str().as_bytes())?;
            let builder = state.client.request(method, req.uri().to_string()).headers(request_headers).body(Vec::from(body.as_ref()));
            let reqwest_response = state.client.execute(builder.build()?).await?;
            info!("Upstream status: {}", reqwest_response.status());
            let status = reqwest_response.status().as_u16();

            // TODO: duplicate block of code
            let mut actix_response = actix_web::HttpResponse::new(
                StatusCode::from_u16(status)?);
            let response_headers = actix_response.headers_mut();
            for (k, v) in reqwest_response.headers() {
                response_headers.append(
                    http_for_actix::HeaderName::from_str(k.as_str()).map_err(|_| InvalidHeaderNameError::default())?,
                    http_for_actix::HeaderValue::from_str(v.to_str()?).map_err(|_| InvalidHeaderValueError::default())?,
                );
            }
    
            if a_show_hit_miss {
                response_headers.append(
                    http_for_actix::HeaderName::from_str("X-JoinProxy-Response").unwrap(),
                    http_for_actix::HeaderValue::from_str("Miss").unwrap(),
                );
            }
            if a_add_forwarded_from_header {
                if let Some(addr) = req.head().peer_addr {
                    response_headers.append(
                        http_for_actix::HeaderName::from_str("X-Forwarded-For").unwrap(),
                        http_for_actix::HeaderValue::from_str(&addr.ip().to_string()).unwrap(),
                    );
                }
            }
            let response_headers_to_remove = remove_response_headers
                .filter(self::schema::remove_response_headers::dsl::server_setup_id.eq(a_server_setup_id))
                .select(
                    self::schema::remove_response_headers::dsl::header_name,
                )
                .get_results::<String>(&mut *state.conn.lock().await)
                .map_err(|_| anyhow!(format!("cannot read DB")))?
                .into_iter();
            //  http://tools.ietf.org/html/rfc2616#section-13.5.1
            let hop_by_hop = ["connection", "keep-alive", "te", "trailers", "transfer-encoding", "upgrade"];
            for k in hop_by_hop.into_iter().map(|s| Ok(http_for_actix::HeaderName::from_static(s)))
                .chain(response_headers_to_remove.map(|s| http_for_actix::HeaderName::from_str(&s).map_err(|_| InvalidHeaderNameError::default().into())))
                .collect::<Result<Vec<_>, MyError>>()?
            {
                response_headers.remove(k);
            }
            let response_headers_to_add = add_response_headers
                .filter(self::schema::add_response_headers::dsl::server_setup_id.eq(a_server_setup_id))
                .select((
                    self::schema::add_response_headers::dsl::header_name,
                    self::schema::add_response_headers::dsl::header_value,
                ))
                .get_results::<(String, String)>(&mut *state.conn.lock().await)
                .map_err(|_| anyhow!(format!("cannot read DB")))?
                .into_iter();
            for (k, v) in response_headers_to_add {
                response_headers.append(
                    http_for_actix::HeaderName::from_str(&k).map_err(|_| InvalidHeaderNameError::default())?,
                    http_for_actix::HeaderValue::from_str(&v).map_err(|_| InvalidHeaderValueError::default())?
                );
            }

            (actix_response, reqwest_response)
        } else {
            // TODO: duplicate block of code
            let request_headers = req.headers().into_iter()
                .filter(|h|
                    h.0 == http_for_actix::HeaderName::from_static("host")
                );
            let request_headers = http::HeaderMap::from_iter(
                request_headers
                    .map(|h| -> MyResult<_> {
                        Ok((
                            http::HeaderName::from_str(h.0.as_str()).map_err(|_| InvalidHeaderNameError::default())?,
                            http::HeaderValue::from_str(h.1.to_str()?).map_err(|_| InvalidHeaderValueError::default())?,
                        ))
                    })
                    .into_iter()
                    .collect::<MyResult<Vec<_>>>()?
            );
    
            // TODO: duplicate block of code
            let method = reqwest::Method::from_bytes(req.method().as_str().as_bytes())?;
            let builder = state.client.request(method, base_url + path).headers(request_headers).body(Vec::from(body.as_ref()));
            let reqwest_response = state.client.execute(builder.build()?).await?;
            info!("Upstream status: {}", reqwest_response.status());
            let status = reqwest_response.status().as_u16();

            // TODO: duplicate block of code
            let mut actix_response = actix_web::HttpResponse::new(
                StatusCode::from_u16(status)?);
            let response_headers = actix_response.headers_mut();
            for (k, v) in reqwest_response.headers() {
                response_headers.append(
                    http_for_actix::HeaderName::from_str(k.as_str()).map_err(|_| InvalidHeaderNameError::default())?,
                    http_for_actix::HeaderValue::from_str(v.to_str()?).map_err(|_| InvalidHeaderValueError::default())?,
                );
            }

            // request_headers.remove("date"); // Remove only `Date:` by default. // TODO
            (actix_response, reqwest_response)
        };

        // We retrieved the response, immediately set and release the cache:
        let (cached, response_body) = serialize_http_response(reqwest_response).await?;
        (*cache_lock).set(Some(cached)).await;
        std::mem::drop(cache_lock);

        Ok(actix_response.set_body(response_body)) // TODO: inefficient
    }
}

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let cli = Args::parse();
    let mut config: Config = if let Some(config_file) = &cli.config_file {
        let config_string = read_to_string(&config_file)
            .map_err(|e| anyhow!("Cannot read config file {}: {}", config_file, e))?;
        toml::from_str(&config_string)
            .map_err(|e| anyhow!("Cannot parse config file {}: {}", config_file, e))?
    } else {
        Config::default()
    };
    config.update_from_args(cli);
    // TODO
    if let Some(callback) = &mut config.callback {
        if callback.ic_url.is_none() && callback.ic_local {
            callback.ic_url = Some("http://localhost:8000".to_string())
        }
    }

    let proxy_server_url = config.bind_proxy.host.clone() + ":" + config.bind_proxy.port.to_string().as_str();
    let api_server_url = config.bind_api.host.clone() + ":" + config.bind_api.port.to_string().as_str(); // TODO: duplicate code

    ring::default_provider().install_default().unwrap();

    let cache =
        Arc::new(Mutex::new(Box::<BinaryCache>::from(Box::new(BinaryMemCache::new(config.cache.cache_timeout)))));

    let agent = {
        if let Some(callback) = &config.callback {
            let mut builder = Agent::builder();
            if let Some(ic_url) = &callback.ic_url {
                builder = builder.with_url(ic_url);
            }
            let agent = builder.build()?;
            if callback.ic_local {
                agent.fetch_root_key().await?;
            }
            Some(agent)
        } else {
            None
        }
    };
    let agent2 = agent.clone();

    let database_url = std::env::var("DATABASE_URL").context("DATABASE_URL must be set")?;
    let database_url2 = database_url.clone();
    let is_https = config.bind_proxy.https; // FIXME: for API?

    let oauth_state = auth::State::preconfigured().start();

    let config2 = config.clone(); // TODO: hack
    let (cert_file, key_file) = (config.cert_file.clone(), config.key_file.clone());
    let proxy_server = HttpServer::new(move || {
        let mut builder = ClientBuilder::new();
        if let Some(t) = config.upstream_timeouts.connect_timeout {
            builder = builder.connect_timeout(t);
        }
        if let Some(t) = config.upstream_timeouts.read_timeout {
            builder = builder.connect_timeout(t);
        }
        if let Some(t) = config.upstream_timeouts.total_timeout {
            builder = builder.timeout(t);
        }
        let state = State {
            client: builder.build().unwrap(),
            agent: agent.clone(),
            conn: tokio::sync::Mutex::new(PgConnection::establish(&database_url).expect("DB connection")),
        };
        App::new().service(
            web::scope("")
            .app_data(Data::new(config.clone())) // TODO: Can remove clone?
            .app_data(Data::new(state))
            .app_data(Data::new(cache.clone()))
                .route("/{_:.*}", web::route().to(proxy))
        )
    });
    info!("Starting Proxy at {} (https={})", proxy_server_url, is_https);
    let proxy = if is_https {
        if let (Some(cert_file), Some(key_file)) = (cert_file, key_file) {
            let cert_file = &mut BufReader::new(File::open(cert_file).context("Can't read HTTPS cert.")?);
            let key_file = &mut BufReader::new(File::open(key_file).context("Can't read HTTPS key.")?);
            let cert_chain = certs(cert_file).collect::<Result<Vec<_>, _>>()
                .context("Can't parse HTTPS certs chain.")?;
            let key = pkcs8_private_keys(key_file)
                .next().transpose()?.ok_or(anyhow!("No private key in the file."))?;
            proxy_server.bind_rustls_0_23(
                proxy_server_url,
                ServerConfig::builder().with_no_client_auth()
                    .with_single_cert(cert_chain, rustls::pki_types::PrivateKeyDer::Pkcs8(key))?
            )
        } else {
            bail!("No SSL certificate or key in config");
        }
    } else {
        proxy_server.bind(proxy_server_url)
    }?
        .run();
    let (cert_file, key_file) = (config2.cert_file.clone(), config2.key_file.clone());
    let api_server = HttpServer::new(move || {
        let builder = ClientBuilder::new();
        let state = State {
            client: builder.build().unwrap(), // TODO: unused
            agent: agent2.clone(), // TODO: Can remove clone?
            conn: tokio::sync::Mutex::new(PgConnection::establish(&database_url2).expect("DB connection")),
        };
        App::new()
            .app_data(Data::new(config2.clone())) // TODO: Can remove clone?
            .app_data(Data::new(state))
            .app_data(Data::new(oauth_state.clone()))
            .service(
                web::scope("/api")
                    .route("/authorize", web::route().to(authorize))
            )
            .service(
                web::scope("/auth")
                    .route("/authorize", web::route().to(authorize)) // FIXME
                    .route("/token", web::route().to(token))
                    .route("/refresh", web::route().to(refresh))
                    // .route("/protected", web::route().to(protected_resource)))
                )
    });
    let api = if is_https {
        if let (Some(cert_file), Some(key_file)) = (cert_file, key_file) {
            // TODO: Don't load/parse files second time.
            let cert_file = &mut BufReader::new(File::open(cert_file).context("Can't read HTTPS cert.")?);
            let key_file = &mut BufReader::new(File::open(key_file).context("Can't read HTTPS key.")?);
            let cert_chain = certs(cert_file).collect::<Result<Vec<_>, _>>()
                .context("Can't parse HTTPS certs chain.")?;
            let key = pkcs8_private_keys(key_file)
                .next().transpose()?.ok_or(anyhow!("No private key in the file."))?;
            api_server.bind_rustls_0_23(
                api_server_url,
                ServerConfig::builder().with_no_client_auth()
                    .with_single_cert(cert_chain, rustls::pki_types::PrivateKeyDer::Pkcs8(key))?
            )
        } else {
            bail!("No SSL certificate or key in config");
        }
    } else {
        api_server.bind(api_server_url)
    }?
        .run();
    tokio::try_join!(proxy, api).map_err(|e| MyError::from(e))?;
    Ok(())
}
