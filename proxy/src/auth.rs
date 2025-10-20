// mod support;

use actix::{Actor, Addr, Context, Handler, Message};
use actix_web::{error::ErrorInternalServerError, web, HttpResponse};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use der::Decode;
use elliptic_curve::ALGORITHM_OID;
use ic_agent::export::Principal;
use ic_agent::identity::{Delegation, SignedDelegation};
use ic_ed25519::PublicKey as Ed25519PublicKey;
use k256::ecdsa::signature::Verifier;
use k256::{
    ecdsa::{Signature as K256Signature, VerifyingKey as K256VerifyingKey},
    Secp256k1,
};
use log::{error, warn};
use oxide_auth::primitives::grant::{Extensions, Grant};
use oxide_auth::{
    endpoint::{Endpoint, OwnerConsent, OwnerSolicitor, QueryParameter, Solicitation, WebResponse},
    frontends::simple::endpoint::{ErrorInto, Generic, Vacant},
    primitives::prelude::{
        AuthMap, Client, ClientMap, ClientUrl, IssuedToken, Issuer, RandomGenerator, Registrar,
        Scope, TokenMap,
    },
};
use oxide_auth_actix::{
    Authorize, OAuthMessage, OAuthOperation, OAuthRequest, OAuthResponse, Refresh, Token, WebError,
};
use p256::{
    ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey},
    NistP256,
};
use pkcs8::{spki::SubjectPublicKeyInfoRef, AssociatedOid, ObjectIdentifier};
use rand::rngs::OsRng;
use rand::RngCore;
use sec1::EcParameters;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest as ShaDigest, Sha256};
use std::{
    collections::HashMap,
    convert::TryFrom,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::sync::Mutex as AsyncPgMutex;

use chrono::{Duration as ChronoDuration, Utc};
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::result::Error as DieselError;
use std::borrow::Cow;

use crate::models::NewRefreshToken;
use crate::schema::refresh_tokens::dsl as refresh_tokens_dsl;

pub type DbConn = Arc<AsyncPgMutex<PgConnection>>;

// Based on https://github.com/197g/oxide-auth/blob/master/oxide-auth-actix/examples/actix-example/src/main.rs

pub struct State {
    endpoint: Generic<
        ClientMap,
        AuthMap<RandomGenerator>,
        TokenMap<RandomGenerator>,
        Vacant,
        Vec<Scope>,
        fn() -> OAuthResponse,
    >,
    challenge_store: ChallengeStoreHandle,
}

enum Extras {
    Authorize,
    Nothing,
}

pub struct LookupRefreshGrant {
    pub refresh_token: String,
}

impl Message for LookupRefreshGrant {
    type Result = Result<Option<Grant>, WebError>;
}

pub struct IssueClientCredentialsToken {
    pub request: OAuthRequest,
}

pub enum ClientCredentialsIssueError {
    InvalidRequest(String),
    Internal(WebError),
}

impl Message for IssueClientCredentialsToken {
    type Result = Result<(IssuedToken, Grant), ClientCredentialsIssueError>;
}

const CHALLENGE_LEN: usize = 32;
const CHALLENGE_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Default)]
pub struct ChallengeStore {
    entries: HashMap<Vec<u8>, Instant>,
}

pub type ChallengeStoreHandle = Arc<Mutex<ChallengeStore>>;

impl ChallengeStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn cleanup(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, expires_at| *expires_at > now);
    }

    pub fn generate(&mut self) -> [u8; CHALLENGE_LEN] {
        self.cleanup();

        loop {
            let mut challenge = [0u8; CHALLENGE_LEN];
            OsRng.fill_bytes(&mut challenge);

            if !self.entries.contains_key(&challenge.to_vec()) {
                self.entries
                    .insert(challenge.to_vec(), Instant::now() + CHALLENGE_TTL);
                return challenge;
            }
        }
    }

    pub fn consume(&mut self, challenge: &[u8]) -> bool {
        self.cleanup();
        self.entries.remove(challenge).is_some()
    }
}

#[derive(Debug, Error)]
enum IiAuthError {
    #[error("missing Internet Identity parameter `{0}`")]
    MissingParam(&'static str),
    #[error("invalid encoding for `{0}`")]
    InvalidEncoding(&'static str),
    #[error("invalid hex data for `{0}`")]
    InvalidHex(&'static str),
    #[error("failed to parse delegation payload")]
    InvalidDelegation(#[from] serde_json::Error),
    #[error("delegation expired")]
    DelegationExpired,
    #[error("invalid public key encoding")]
    InvalidPublicKey,
    #[error("unsupported public key algorithm")]
    UnsupportedKeyAlgorithm,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("Internet Identity challenge expired or unknown")]
    UnknownChallenge,
    #[error("challenge store unavailable")]
    ChallengeStorePoisoned,
    #[error("missing signing key in delegation chain")]
    MissingSigningKey,
    #[error("delegation public key mismatch")]
    PublicKeyMismatch,
}

impl IiAuthError {
    fn is_client_error(&self) -> bool {
        matches!(
            self,
            IiAuthError::MissingParam(_)
                | IiAuthError::InvalidEncoding(_)
                | IiAuthError::InvalidHex(_)
                | IiAuthError::InvalidDelegation(_)
                | IiAuthError::DelegationExpired
                | IiAuthError::UnsupportedKeyAlgorithm
                | IiAuthError::InvalidSignature
                | IiAuthError::UnknownChallenge
                | IiAuthError::MissingSigningKey
                | IiAuthError::PublicKeyMismatch
                | IiAuthError::InvalidPublicKey
        )
    }
}

struct InternetIdentityProof {
    challenge: Vec<u8>,
    signature: Vec<u8>,
    public_key: Vec<u8>,
    delegations: Vec<SignedDelegation>,
}

#[derive(Deserialize)]
struct DelegationChainInput {
    #[serde(rename = "publicKey")]
    public_key: String,
    delegations: Vec<SignedDelegationInput>,
}

#[derive(Deserialize)]
struct SignedDelegationInput {
    delegation: DelegationInput,
    signature: String,
}

#[derive(Deserialize)]
struct DelegationInput {
    pubkey: String,
    expiration: String,
    targets: Option<Vec<String>>,
}

fn get_param(req: &OAuthRequest, key: &str) -> Option<String> {
    req.body()
        .and_then(|body| body.unique_value(key).map(|v| v.into_owned()))
        .or_else(|| {
            req.query()
                .and_then(|query| query.unique_value(key).map(|v| v.into_owned()))
        })
}

fn parse_internet_identity_proof(req: &OAuthRequest) -> Result<InternetIdentityProof, IiAuthError> {
    let challenge_b64 =
        get_param(req, "ii_challenge").ok_or(IiAuthError::MissingParam("ii_challenge"))?;
    let signature_hex =
        get_param(req, "ii_signature").ok_or(IiAuthError::MissingParam("ii_signature"))?;
    let public_key_hex =
        get_param(req, "ii_public_key").ok_or(IiAuthError::MissingParam("ii_public_key"))?;
    let delegations_json =
        get_param(req, "ii_delegations").ok_or(IiAuthError::MissingParam("ii_delegations"))?;

    let challenge = URL_SAFE_NO_PAD
        .decode(challenge_b64.as_bytes())
        .map_err(|_| IiAuthError::InvalidEncoding("ii_challenge"))?;
    let signature =
        hex::decode(signature_hex).map_err(|_| IiAuthError::InvalidHex("ii_signature"))?;
    let public_key =
        hex::decode(public_key_hex).map_err(|_| IiAuthError::InvalidHex("ii_public_key"))?;

    let (delegations, declared_public_key) = parse_delegation_chain(&delegations_json)?;
    if declared_public_key != public_key {
        return Err(IiAuthError::PublicKeyMismatch);
    }

    Ok(InternetIdentityProof {
        challenge,
        signature,
        public_key,
        delegations,
    })
}

fn parse_delegation_chain(raw: &str) -> Result<(Vec<SignedDelegation>, Vec<u8>), IiAuthError> {
    let parsed: DelegationChainInput = serde_json::from_str(raw)?;
    let public_key = hex::decode(parsed.public_key)
        .map_err(|_| IiAuthError::InvalidHex("delegations.publicKey"))?;

    let mut delegations = Vec::with_capacity(parsed.delegations.len());
    for signed in parsed.delegations {
        let signature = hex::decode(signed.signature)
            .map_err(|_| IiAuthError::InvalidHex("delegations.signature"))?;
        let delegation_pubkey = hex::decode(signed.delegation.pubkey)
            .map_err(|_| IiAuthError::InvalidHex("delegations.delegation.pubkey"))?;
        let expiration = u64::from_str_radix(&signed.delegation.expiration, 16)
            .map_err(|_| IiAuthError::InvalidEncoding("delegations.delegation.expiration"))?;

        let targets = match signed.delegation.targets {
            Some(values) => {
                let mut principals = Vec::with_capacity(values.len());
                for value in values {
                    let bytes = hex::decode(&value)
                        .map_err(|_| IiAuthError::InvalidHex("delegations.delegation.targets"))?;
                    principals.push(Principal::from_slice(&bytes));
                }
                Some(principals)
            }
            None => None,
        };

        delegations.push(SignedDelegation {
            delegation: Delegation {
                pubkey: delegation_pubkey,
                expiration,
                targets,
            },
            signature,
        });
    }

    Ok((delegations, public_key))
}

fn ensure_not_expired(expiration_ns: u64) -> Result<(), IiAuthError> {
    let expires_at = UNIX_EPOCH
        .checked_add(Duration::from_nanos(expiration_ns))
        .ok_or(IiAuthError::DelegationExpired)?;
    if SystemTime::now() >= expires_at {
        return Err(IiAuthError::DelegationExpired);
    }
    Ok(())
}

fn verify_delegation_chain(
    root_public_key: &[u8],
    delegations: &[SignedDelegation],
) -> Result<Vec<u8>, IiAuthError> {
    if delegations.is_empty() {
        return Err(IiAuthError::MissingSigningKey);
    }

    let mut current_key = root_public_key.to_vec();
    let mut signing_key: Option<Vec<u8>> = None;

    for signed in delegations {
        ensure_not_expired(signed.delegation.expiration)?;

        let message = signed.delegation.signable();
        verify_signature(&current_key, &signed.signature, &message)?;

        if signed.delegation.targets.is_none() {
            signing_key = Some(signed.delegation.pubkey.clone());
        } else {
            break;
        }

        current_key = signed.delegation.pubkey.clone();
    }

    signing_key.ok_or(IiAuthError::MissingSigningKey)
}

fn verify_signature(
    public_key_der: &[u8],
    signature: &[u8],
    message: &[u8],
) -> Result<(), IiAuthError> {
    let spki = SubjectPublicKeyInfoRef::from_der(public_key_der)
        .map_err(|_| IiAuthError::InvalidPublicKey)?;

    if spki.algorithm.oid == ALGORITHM_OID {
        let curve = spki
            .algorithm
            .parameters
            .and_then(|params| params.decode_as::<EcParameters>().ok())
            .and_then(|params| params.named_curve());

        match curve {
            Some(oid) if oid == Secp256k1::OID => {
                verify_k256_key(spki.subject_public_key.raw_bytes(), signature, message)
            }
            Some(oid) if oid == NistP256::OID => {
                verify_p256_key(spki.subject_public_key.raw_bytes(), signature, message)
            }
            _ => fallback_ecc_verification(spki.subject_public_key.raw_bytes(), signature, message),
        }
    } else if spki.algorithm.oid == NistP256::OID
        || spki.algorithm.oid == ObjectIdentifier::new_unwrap("1.3.6.1.4.1.56387.1.1")
        || spki.algorithm.oid == ObjectIdentifier::new_unwrap("1.3.6.1.4.1.56387.1.2")
    {
        verify_p256_key(spki.subject_public_key.raw_bytes(), signature, message)
    } else if spki.algorithm.oid == Secp256k1::OID {
        verify_k256_key(spki.subject_public_key.raw_bytes(), signature, message)
    } else if spki.algorithm.oid == ObjectIdentifier::new_unwrap("1.3.101.112") {
        let vk = Ed25519PublicKey::deserialize_raw(spki.subject_public_key.raw_bytes())
            .map_err(|_| IiAuthError::InvalidPublicKey)?;
        vk.verify_signature(message, signature)
            .map_err(|_| IiAuthError::InvalidSignature)
    } else {
        warn!(
            "Unsupported SPKI algorithm OID {} – attempting fallback verification",
            spki.algorithm.oid
        );
        match fallback_ecc_verification(spki.subject_public_key.raw_bytes(), signature, message) {
            Ok(()) => Ok(()),
            Err(IiAuthError::InvalidPublicKey) => Err(IiAuthError::UnsupportedKeyAlgorithm),
            Err(other) => Err(other),
        }
    }
}

fn verify_p256_key(
    subject_public_key: &[u8],
    signature: &[u8],
    message: &[u8],
) -> Result<(), IiAuthError> {
    let normalized = normalize_sec1_bytes(subject_public_key, CurveKind::P256);

    let vk = P256VerifyingKey::from_sec1_bytes(normalized.as_ref()).map_err(|err| {
        warn!(
            "Failed to parse P-256 public key ({:?}) encoded as {} bytes: {}",
            hex::encode(subject_public_key),
            subject_public_key.len(),
            err
        );
        IiAuthError::InvalidPublicKey
    })?;

    let sig = P256Signature::try_from(signature).map_err(|_| IiAuthError::InvalidSignature)?;
    vk.verify(message, &sig)
        .map_err(|_| IiAuthError::InvalidSignature)
}

fn fallback_ecc_verification(
    subject_public_key: &[u8],
    signature: &[u8],
    message: &[u8],
) -> Result<(), IiAuthError> {
    match verify_p256_key(subject_public_key, signature, message) {
        Ok(()) => return Ok(()),
        Err(IiAuthError::InvalidPublicKey) => {}
        Err(other) => return Err(other),
    }

    match verify_k256_key(subject_public_key, signature, message) {
        Ok(()) => Ok(()),
        Err(IiAuthError::InvalidPublicKey) => {
            warn!("Public key verification failed for both P-256 and secp256k1 fallback paths");
            Err(IiAuthError::UnsupportedKeyAlgorithm)
        }
        Err(other) => Err(other),
    }
}

fn verify_k256_key(
    subject_public_key: &[u8],
    signature: &[u8],
    message: &[u8],
) -> Result<(), IiAuthError> {
    let normalized = normalize_sec1_bytes(subject_public_key, CurveKind::Secp256k1);

    let vk = K256VerifyingKey::from_sec1_bytes(normalized.as_ref()).map_err(|err| {
        warn!(
            "Failed to parse secp256k1 public key ({:?}) encoded as {} bytes: {}",
            hex::encode(subject_public_key),
            subject_public_key.len(),
            err
        );
        IiAuthError::InvalidPublicKey
    })?;

    let sig = K256Signature::try_from(signature).map_err(|_| IiAuthError::InvalidSignature)?;
    vk.verify(message, &sig)
        .map_err(|_| IiAuthError::InvalidSignature)
}

#[derive(Clone, Copy)]
enum CurveKind {
    P256,
    Secp256k1,
}

fn normalize_sec1_bytes(bytes: &[u8], kind: CurveKind) -> Cow<'_, [u8]> {
    if bytes.is_empty() {
        return Cow::Borrowed(bytes);
    }

    match bytes[0] {
        0x02 | 0x03 | 0x04 => Cow::Borrowed(bytes),
        _ if bytes.len() == 64 => convert_raw_xy(bytes),
        prefix if bytes.len() > 1 && (bytes.len() - 1) % 2 == 0 => {
            rebuild_from_compact(bytes, prefix, kind, Endian::Big)
                .or_else(|| rebuild_from_compact(bytes, prefix, kind, Endian::Little))
                .unwrap_or_else(|| Cow::Borrowed(bytes))
        }
        _ => Cow::Borrowed(bytes),
    }
}

fn convert_raw_xy(bytes: &[u8]) -> Cow<'_, [u8]> {
    let mut owned = Vec::with_capacity(65);
    owned.push(0x04);
    owned.extend_from_slice(bytes);
    warn!("Assuming uncompressed SEC1 point with missing prefix (64 bytes -> 65 bytes)");
    Cow::Owned(owned)
}

#[derive(Clone, Copy, Debug)]
enum Endian {
    Big,
    Little,
}

fn rebuild_from_compact(
    bytes: &[u8],
    prefix: u8,
    kind: CurveKind,
    endian: Endian,
) -> Option<Cow<'_, [u8]>> {
    let coord_len = (bytes.len() - 1) / 2;
    if coord_len == 0 || coord_len > 32 {
        warn!(
            "Compact encoding prefix 0x{:02x} with coord_len {} is outside expected bounds",
            prefix, coord_len
        );
        return None;
    }

    let expected_prefix = match kind {
        CurveKind::P256 => 0x0a,
        CurveKind::Secp256k1 => 0x0b,
    };

    if prefix != expected_prefix {
        return None;
    }

    let mut owned = Vec::with_capacity(65);
    owned.push(0x04);
    let (x, y) = bytes[1..].split_at(coord_len);
    owned.extend_from_slice(&expand_coord(x, endian));
    owned.extend_from_slice(&expand_coord(y, endian));
    warn!(
        "Reconstructed SEC1 point from compact encoding (prefix 0x{:02x}, coord_len {}, endian {:?})",
        prefix, coord_len, endian
    );
    Some(Cow::Owned(owned))
}

fn expand_coord(coord: &[u8], endian: Endian) -> [u8; 32] {
    let mut out = [0u8; 32];
    let len = coord.len().min(32);
    match endian {
        Endian::Big => {
            out[32 - len..].copy_from_slice(&coord[coord.len() - len..]);
        }
        Endian::Little => {
            for (i, byte) in coord.iter().take(len).enumerate() {
                out[i] = *byte;
            }
            out[..].reverse();
        }
    }
    out
}

fn verify_internet_identity(
    req: &OAuthRequest,
    store: &ChallengeStoreHandle,
) -> Result<String, IiAuthError> {
    let proof = parse_internet_identity_proof(req)?;

    {
        let mut guard = store
            .lock()
            .map_err(|_| IiAuthError::ChallengeStorePoisoned)?;
        if !guard.consume(&proof.challenge) {
            return Err(IiAuthError::UnknownChallenge);
        }
    }

    let signing_key = verify_delegation_chain(&proof.public_key, &proof.delegations)?;
    verify_signature(&signing_key, &proof.signature, &proof.challenge)?;

    Ok(Principal::self_authenticating(&proof.public_key).to_text())
}

fn owner_consent_from_error(err: IiAuthError) -> OwnerConsent<OAuthResponse> {
    if err.is_client_error() {
        warn!("Internet Identity verification denied: {}", err);
        OwnerConsent::Denied
    } else {
        warn!("Internet Identity verification failed: {}", err);
        OwnerConsent::Error(WebError::InternalError(Some(err.to_string())))
    }
}

fn build_invalid_request_response(message: &str) -> Result<OAuthResponse, WebError> {
    let payload = json!({
        "error": "invalid_request",
        "error_description": message,
    });

    let mut response = OAuthResponse::ok();
    response.client_error()?;
    response = response.content_type("application/json")?;
    Ok(response.body(&payload.to_string()))
}

fn build_client_credentials_response(
    issued: &IssuedToken,
    scope: &Scope,
) -> Result<OAuthResponse, WebError> {
    let expires_in = issued
        .until
        .signed_duration_since(Utc::now())
        .num_seconds()
        .max(0);

    let payload = json!({
        "access_token": issued.token,
        "token_type": "Bearer",
        "expires_in": expires_in,
        "refresh_token": issued.refresh,
        "scope": scope.to_string(),
    });

    let body = serde_json::to_string(&payload)
        .map_err(|err| WebError::InternalError(Some(err.to_string())))?;

    let mut response = OAuthResponse::ok();
    response = response
        .content_type("application/json")
        .map_err(WebError::from)?;
    Ok(response.body(&body))
}

fn extract_refresh_token(response: &OAuthResponse) -> Option<String> {
    response.get_body().and_then(|body| {
        serde_json::from_str::<Value>(&body).ok().and_then(|value| {
            value
                .get("refresh_token")
                .and_then(|v| v.as_str())
                .map(str::to_owned)
        })
    })
}

async fn persist_refresh_token(
    db: &DbConn,
    refresh_token: &str,
    grant: &Grant,
) -> Result<(), DieselError> {
    use refresh_tokens_dsl::{
        client_id as client_id_col, created_at as created_at_col, expires_at as expires_at_col,
        owner_principal as owner_principal_col, refresh_tokens as refresh_tokens_table,
        scope as scope_col, token_hash as token_hash_col,
    };

    let token_hash_bytes = hash_refresh_token(refresh_token);
    let record = NewRefreshToken {
        token_hash: token_hash_bytes.clone(),
        owner_principal: grant.owner_id.clone(),
        client_id: grant.client_id.clone(),
        scope: grant.scope.to_string(),
        expires_at: grant.until,
        created_at: Utc::now(),
    };

    let mut conn = db.lock().await;
    diesel::insert_into(refresh_tokens_table)
        .values(&record)
        .on_conflict(token_hash_col)
        .do_update()
        .set((
            owner_principal_col.eq(&record.owner_principal),
            client_id_col.eq(&record.client_id),
            scope_col.eq(&record.scope),
            expires_at_col.eq(record.expires_at),
            created_at_col.eq(record.created_at),
        ))
        .execute(&mut *conn)?;

    Ok(())
}

async fn delete_refresh_token(db: &DbConn, refresh_token: &str) -> Result<(), DieselError> {
    use refresh_tokens_dsl::{
        refresh_tokens as refresh_tokens_table, token_hash as token_hash_col,
    };

    let hash = hash_refresh_token(refresh_token);
    let mut conn = db.lock().await;
    diesel::delete(refresh_tokens_table.filter(token_hash_col.eq(hash))).execute(&mut *conn)?;
    Ok(())
}

fn hash_refresh_token(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

// pub async fn authorize(
//     (r, req, state): (HttpRequest, OAuthRequest, web::Data<Addr<State>>),
// ) -> Result<OAuthResponse, WebError> {
//     // Some authentication should be performed here in production cases
//     state
//         .send(Authorize(req).wrap(Extras::AuthPost(r.query_string().to_owned())))
//         .await?
// }

// `curl http://localhost:8080/auth/token -H "Content-Type: application/x-www-form-urlencoded" -d 'grant_type=client_credentials'`
pub async fn token(
    (req, state, db): (OAuthRequest, web::Data<Addr<State>>, web::Data<DbConn>),
) -> Result<OAuthResponse, WebError> {
    let grant_type = req
        .body()
        .and_then(|body| body.unique_value("grant_type").map(|v| v.into_owned()));
    let grant_type_str = grant_type.as_deref();

    let old_refresh_token = if grant_type_str == Some("refresh_token") {
        req.body()
            .and_then(|body| body.unique_value("refresh_token").map(|v| v.into_owned()))
    } else {
        None
    };

    let mut new_refresh_for_storage: Option<(String, Grant)> = None;

    let response = match grant_type_str {
        Some("client_credentials") => {
            match state
                .send(IssueClientCredentialsToken { request: req })
                .await
                .map_err(|err| WebError::InternalError(Some(err.to_string())))?
            {
                Ok((issued, grant)) => {
                    if let Some(refresh) = issued.refresh.clone() {
                        new_refresh_for_storage = Some((refresh.clone(), grant.clone()));
                    }
                    build_client_credentials_response(&issued, &grant.scope)?
                }
                Err(ClientCredentialsIssueError::InvalidRequest(message)) => {
                    return build_invalid_request_response(&message)
                }
                Err(ClientCredentialsIssueError::Internal(err)) => return Err(err),
            }
        }
        Some("refresh_token") => state
            .send(Refresh(req).wrap(Extras::Nothing))
            .await
            .map_err(|err| WebError::InternalError(Some(err.to_string())))??,
        _ => state
            .send(Token(req).wrap(Extras::Nothing))
            .await
            .map_err(|err| WebError::InternalError(Some(err.to_string())))??,
    };

    if grant_type_str == Some("refresh_token") {
        if let Some(old_token) = old_refresh_token.as_ref() {
            if let Err(err) = delete_refresh_token(db.get_ref(), old_token).await {
                warn!("failed to delete old refresh token: {err}");
            }
        }
    }

    if new_refresh_for_storage.is_none() {
        if let Some(refresh_token_value) = extract_refresh_token(&response) {
            match state
                .send(LookupRefreshGrant {
                    refresh_token: refresh_token_value.clone(),
                })
                .await
            {
                Ok(Ok(Some(grant))) => {
                    new_refresh_for_storage = Some((refresh_token_value.clone(), grant));
                }
                Ok(Ok(None)) => {
                    warn!("refresh token grant not found in issuer state");
                }
                Ok(Err(err)) => {
                    warn!("failed to recover refresh grant: {err:?}");
                }
                Err(err) => {
                    warn!("actor error while recovering refresh grant: {err}");
                }
            }
        }
    }

    if let Some((refresh_token_value, grant)) = new_refresh_for_storage {
        if let Err(err) = persist_refresh_token(db.get_ref(), &refresh_token_value, &grant).await {
            error!("failed to store refresh token: {err}");
        }
    }

    Ok(response)
}

pub async fn authorize(
    (req, state): (OAuthRequest, web::Data<Addr<State>>),
) -> Result<OAuthResponse, WebError> {
    state.send(Authorize(req).wrap(Extras::Authorize)).await?
}

pub async fn refresh(
    (req, state): (OAuthRequest, web::Data<Addr<State>>),
) -> Result<OAuthResponse, WebError> {
    state.send(Refresh(req).wrap(Extras::Nothing)).await?
}

#[derive(Serialize)]
struct ChallengeResponseBody {
    challenge: String,
    expires_in: u64,
}

pub async fn challenge(
    store: web::Data<ChallengeStoreHandle>,
) -> Result<HttpResponse, actix_web::Error> {
    let mut guard = store
        .lock()
        .map_err(|_| ErrorInternalServerError("Challenge store is unavailable"))?;
    let challenge_bytes = guard.generate();
    drop(guard);

    let response = ChallengeResponseBody {
        challenge: URL_SAFE_NO_PAD.encode(challenge_bytes),
        expires_in: CHALLENGE_TTL.as_secs(),
    };

    Ok(HttpResponse::Ok().json(response))
}

impl State {
    pub fn preconfigured(challenge_store: ChallengeStoreHandle) -> Self {
        State {
            endpoint: Generic {
                // registrar: Vec::new()
                // FIXME
                registrar: vec![Client::public(
                    "LocalClient",
                    "http://localhost:8000/redirect"
                        .parse::<url::Url>()
                        .unwrap()
                        .into(),
                    "default offline_access".parse().unwrap(),
                )
                .with_additional_redirect_uris(vec![
                    "http://localhost:8021/endpoint"
                        .parse::<url::Url>()
                        .unwrap()
                        .into(),
                ])]
                .into_iter()
                .collect(),
                // Authorization tokens are 16 byte random keys to a memory hash map.
                authorizer: AuthMap::new(RandomGenerator::new(16)),
                // Bearer tokens are also random generated but 256-bit tokens, since they live longer
                // and this example is somewhat paranoid.
                //
                // We could also use a `TokenSigner::ephemeral` here to create signed tokens which can
                // be read and parsed by anyone, but not maliciously created. However, they can not be
                // revoked and thus don't offer even longer lived refresh tokens.
                issuer: TokenMap::new(RandomGenerator::new(16)),

                solicitor: Vacant,

                // Scopes enabled for the endpoint
                scopes: vec![
                    "default".parse().unwrap(),
                    "offline_access".parse().unwrap(),
                ],

                response: OAuthResponse::ok,
            },
            challenge_store,
        }
    }

    pub fn with_solicitor<'a, S>(
        &'a mut self,
        solicitor: S,
    ) -> impl Endpoint<OAuthRequest, Error = WebError> + 'a
    where
        S: OwnerSolicitor<OAuthRequest> + 'static,
    {
        ErrorInto::new(Generic {
            authorizer: &mut self.endpoint.authorizer,
            registrar: &mut self.endpoint.registrar,
            issuer: &mut self.endpoint.issuer,
            solicitor,
            scopes: &mut self.endpoint.scopes,
            response: OAuthResponse::ok,
        })
    }
}

impl Actor for State {
    type Context = Context<Self>;
}

impl Handler<LookupRefreshGrant> for State {
    type Result = Result<Option<Grant>, WebError>;

    fn handle(&mut self, msg: LookupRefreshGrant, _: &mut Self::Context) -> Self::Result {
        self.endpoint
            .issuer
            .recover_refresh(&msg.refresh_token)
            .map_err(|_| WebError::InternalError(Some("failed to recover refresh token".into())))
    }
}

impl Handler<IssueClientCredentialsToken> for State {
    type Result = Result<(IssuedToken, Grant), ClientCredentialsIssueError>;

    fn handle(&mut self, msg: IssueClientCredentialsToken, _: &mut Self::Context) -> Self::Result {
        let IssueClientCredentialsToken { request } = msg;

        let owner_principal = verify_internet_identity(&request, &self.challenge_store)
            .map_err(|err| ClientCredentialsIssueError::InvalidRequest(err.to_string()))?;

        let client_id =
            get_param(&request, "client_id").unwrap_or_else(|| "LocalClient".to_string());
        let scope_text =
            get_param(&request, "scope").unwrap_or_else(|| "default offline_access".to_string());
        let scope: Scope = scope_text
            .parse()
            .map_err(|_| ClientCredentialsIssueError::InvalidRequest("invalid scope".into()))?;

        let bound = self.endpoint.registrar.bound_redirect(ClientUrl {
            client_id: Cow::Owned(client_id.clone()),
            redirect_uri: None,
        });
        let bound_client = bound
            .map_err(|_| ClientCredentialsIssueError::InvalidRequest("unknown client".into()))?;
        let redirect_registered = bound_client.redirect_uri.into_owned();
        let redirect_uri: url::Url = redirect_registered.into();

        let grant_template = Grant {
            owner_id: owner_principal,
            client_id: client_id.clone(),
            scope: scope.clone(),
            redirect_uri,
            until: Utc::now() + ChronoDuration::hours(1),
            extensions: Extensions::default(),
        };

        let issued = self
            .endpoint
            .issuer
            .issue(grant_template.clone())
            .map_err(|_| {
                ClientCredentialsIssueError::Internal(WebError::InternalError(Some(
                    "failed to issue token".into(),
                )))
            })?;

        let stored_grant = if let Some(refresh) = issued.refresh.as_ref() {
            match self.endpoint.issuer.recover_refresh(refresh) {
                Ok(Some(grant)) => grant,
                Ok(None) => grant_template.clone(),
                Err(_) => {
                    return Err(ClientCredentialsIssueError::Internal(
                        WebError::InternalError(Some("failed to recover refresh".into())),
                    ))
                }
            }
        } else {
            grant_template.clone()
        };

        Ok((issued, stored_grant))
    }
}

struct InternetIdentitySolicitor {
    challenge_store: ChallengeStoreHandle,
}

impl InternetIdentitySolicitor {
    fn new(challenge_store: ChallengeStoreHandle) -> Self {
        Self { challenge_store }
    }
}

impl OwnerSolicitor<OAuthRequest> for InternetIdentitySolicitor {
    fn check_consent(
        &mut self,
        request: &mut OAuthRequest,
        _: Solicitation,
    ) -> OwnerConsent<OAuthResponse> {
        match verify_internet_identity(request, &self.challenge_store) {
            Ok(principal) => OwnerConsent::Authorized(principal),
            Err(err) => owner_consent_from_error(err),
        }
    }
}

impl<Op> Handler<OAuthMessage<Op, Extras>> for State
where
    Op: OAuthOperation,
{
    type Result = Result<Op::Item, Op::Error>;

    fn handle(&mut self, msg: OAuthMessage<Op, Extras>, _: &mut Self::Context) -> Self::Result {
        let (op, ex) = msg.into_inner();

        match ex {
            Extras::Authorize => op.run(
                self.with_solicitor(InternetIdentitySolicitor::new(self.challenge_store.clone())),
            ),
            _ => op.run(&mut self.endpoint),
        }
    }
}

// pub fn consent_page_html(route: &str, solicitation: Solicitation) -> String {
//     macro_rules! template {
//         () => {
//             "<html>'{0:}' (at {1:}) is requesting permission for '{2:}'
// <form method=\"post\">
//     <input type=\"submit\" value=\"Accept\" formaction=\"{4:}?{3:}&allow=true\">
//     <input type=\"submit\" value=\"Deny\" formaction=\"{4:}?{3:}&deny=true\">
// </form>
// </html>"
//         };
//     }

//     let grant = solicitation.pre_grant();
//     let state = solicitation.state();

//     let mut extra = vec![
//         ("response_type", "code"),
//         ("client_id", grant.client_id.as_str()),
//         ("redirect_uri", grant.redirect_uri.as_str()),
//     ];

//     if let Some(state) = state {
//         extra.push(("state", state));
//     }

//     format!(
//         template!(),
//         grant.client_id,
//         grant.redirect_uri,
//         grant.scope,
//         serde_urlencoded::to_string(extra).unwrap(),
//         &route,
//     )
// }
