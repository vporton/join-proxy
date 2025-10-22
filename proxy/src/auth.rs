use actix::{Actor, Addr, Context, Handler, Message};
use actix_web::{error::ErrorInternalServerError, web, HttpResponse};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
// use blsttc::{G1Projective, G2Projective};
use der::Decode;
use elliptic_curve::ALGORITHM_OID;
use ic_agent::export::Principal;
use ic_agent::identity::{Delegation, SignedDelegation};
use ic_ed25519::PublicKey as Ed25519PublicKey;
use k256::ecdsa::signature::hazmat::PrehashVerifier as _;
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
use sha2::{Digest, Sha256};
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
    root_key: Vec<u8>,
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
const IC_REQUEST_DOMAIN: &[u8] = b"\x0Aic-request";

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
    #[error("invalid public key encoding")] // FIXME@P2: It is the error, when signature was not verified, not its name.
    InvalidPublicKey,
    #[error("unsupported public key algorithm")]
    UnsupportedKeyAlgorithm,
    #[error("invalid public key")]
    InvalidKey,
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
    #[error("invalid public key length: {0}")]
    KeyLength(usize),
    #[error("invalid signature length: {0}")]
    SignatureLength(usize),
    #[error("signature verification failed")]
    VerificationFailed,
}

impl IiAuthError {
    fn is_client_error(&self) -> bool {
        matches!(
            self,
            IiAuthError::MissingParam(_)
                | IiAuthError::InvalidEncoding(_) // TODO@P2
                | IiAuthError::InvalidHex(_)
                | IiAuthError::InvalidDelegation(_)
                | IiAuthError::DelegationExpired
                | IiAuthError::UnsupportedKeyAlgorithm
                | IiAuthError::InvalidSignature
                | IiAuthError::UnknownChallenge
                | IiAuthError::MissingSigningKey
                | IiAuthError::PublicKeyMismatch
                | IiAuthError::InvalidPublicKey
                | IiAuthError::VerificationFailed
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
        return Ok(root_public_key.to_vec());
    }

    let mut issuer_key = root_public_key;

    for signed in delegations {
        ensure_not_expired(signed.delegation.expiration)?;

        let message = signed.delegation.signable();
        verify_signature(issuer_key, &signed.signature, &message)?;
        issuer_key = &signed.delegation.pubkey;
    }

    delegations
        .last()
        .map(|signed| signed.delegation.pubkey.clone())
        .ok_or(IiAuthError::MissingSigningKey)
}

fn verify_signature(
    public_key_der: &[u8],
    signature: &[u8],
    message: &[u8],
) -> Result<(), IiAuthError> {
    let spki = SubjectPublicKeyInfoRef::from_der(public_key_der)
        .map_err(|_| IiAuthError::InvalidPublicKey)?;

    let algorithm = determine_signature_algorithm(&spki)?;
    warn!("ALGORITHM: {:?}", algorithm);    
    let key_bytes = spki.subject_public_key.raw_bytes();

    match algorithm {
        SignatureAlgorithm::Ed25519 => {
            let vk = Ed25519PublicKey::deserialize_raw(key_bytes)
                .map_err(|_| IiAuthError::InvalidPublicKey)?;
            vk.verify_signature(message, signature)
                .map_err(|_| IiAuthError::InvalidSignature)
        }
        SignatureAlgorithm::EcdsaP256 => {
            let digest = Sha256::digest(message);
            let mut hash = [0u8; 32];
            hash.copy_from_slice(digest.as_slice());
            verify_p256_signature(key_bytes, signature, hash)
        }
        SignatureAlgorithm::EcdsaSecp256k1 => {
            let digest = Sha256::digest(message);
            let mut hash = [0u8; 32];
            hash.copy_from_slice(digest.as_slice());
            verify_k256_signature(key_bytes, signature, hash)
        }
        SignatureAlgorithm::BLS => {
            // use simple_asn1::{ASN1Block, from_der};
            // let asn1 = from_der(&public_key_der).unwrap();
            // if let ASN1Block::Sequence(_, items) = &asn1[0] {
            //     if let ASN1Block::BitString(_, _, key_bytes) = &items[1] {
            //         println!("Raw key len: {}", key_bytes.len()); // should be 48
            //     }
            // }

            // use blsttc::{PublicKey, Signature};
            use blst::{BLST_ERROR, min_sig::{PublicKey, Signature}}; // no idea why this combination of imports // FIXME@P2: May be different `min_{sig,pk}` on mainnet
            let signed: serde_cbor::Value = serde_cbor::from_slice(&signature[3..]).map_err(|_| IiAuthError::InvalidSignature)?;
            let certificate = &if let serde_cbor::Value::Map(map) = signed {
                // Find the "certificate" key
                let cert_bytes = map.iter()
                    .find_map(|(k, v)| {
                        if let serde_cbor::Value::Text(t) = k {
                            if t == "certificate" {
                                if let serde_cbor::Value::Bytes(b) = v {
                                    return Some(b.clone());
                                }
                            }
                        }
                        None
                    })
                        .expect("certificate field not found"); // FIXME
                // Optional: save to file or parse further
                cert_bytes
            } else {
                // anyhow::bail!("Top-level CBOR is not a map");
                return Err(IiAuthError::InvalidSignature)
            };
            let cert_val: serde_cbor::Value = serde_cbor::from_slice(&certificate).map_err(|_| IiAuthError::InvalidSignature)?;
            let sig_bytes = if let serde_cbor::Value::Map(ref map) = cert_val {
                map.iter()
                    .find_map(|(k, v)| {
                        if let serde_cbor::Value::Text(t) = k {
                            if t == "signature" {
                                if let serde_cbor::Value::Bytes(b) = v {
                                    return Some(b.clone());
                                }
                            }
                        }
                        None
                    })
                        .expect("❌ signature not found in certificate") // FIXME
            } else {
                return Err(IiAuthError::InvalidSignature)
            };
            let signature = sig_bytes.as_slice();
            let tree = if let serde_cbor::Value::Map(ref map) = cert_val {
                map.iter()
                    .find_map(|(k, v)| {
                        if let serde_cbor::Value::Text(t) = k {
                            if t == "tree" {
                                return Some(v.clone()); // TODO@P3: Can `clone` be removed?
                                // if let serde_cbor::Value::Bytes(b) = v {
                                //     return Some(b.clone());
                                // }
                            }
                        }
                        None
                    })
                        .expect("❌ signature not found in certificate") // FIXME@P1: `unwrap`
            } else {
                return Err(IiAuthError::InvalidSignature)
            };
            // println!("✅ Extracted signature length: {}", signature.len()); // should be 96
            // FIXME@P1: https://chatgpt.com/s/t_68f81ff6ff9c819187584d046550103e
            
            let root_hash = hash_tree(&tree); // 32 bytes

            // 2. Domain separation prefix
            let prefix = b"\x0dic-state-root";
            let mut message = Vec::with_capacity(prefix.len() + root_hash.len());
            message.extend_from_slice(prefix);
            message.extend_from_slice(&root_hash);
            

            warn!("sig = {} bytes, pubkey = {} bytes", signature.len(), key_bytes.len());
            let pk = PublicKey::from_bytes(key_bytes).map_err(|err| {warn!("{:?}", err); IiAuthError::InvalidKey})?;
            let sig = Signature::from_bytes(&signature).map_err(|err| {warn!("{:?}", err); IiAuthError::InvalidSignature})?;
            // TODO@P1: For mainnet: b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
            let dst = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"; // DFINITY's dst // FIXME@P1: different for mainnet and local?
            let aug = b"";
            let result = sig.verify(
                true,
                message.as_slice(), // &blst::blst_scalar::hash_to(message, dst).unwrap().b, // FIXME@P2: `unwrap`
                dst,
                aug,
                &pk,
                true,
            );
            warn!("result = {:?}", result);
            if result != BLST_ERROR::BLST_SUCCESS {
                return Err(IiAuthError::VerificationFailed);
            }
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum SignatureAlgorithm {
    Ed25519,
    EcdsaP256,
    EcdsaSecp256k1,
    BLS,
}

fn determine_signature_algorithm(
    spki: &SubjectPublicKeyInfoRef<'_>,
) -> Result<SignatureAlgorithm, IiAuthError> {
    warn!("{}", spki.algorithm.oid);
    if spki.algorithm.oid == ObjectIdentifier::new_unwrap("1.3.101.112") {
        return Ok(SignatureAlgorithm::Ed25519);
    } else if spki.algorithm.oid == ObjectIdentifier::new_unwrap("1.3.6.1.4.1.44668.5.3.1.2.1") { // TODO: Why not standard BLS 1.3.6.1.4.1.44668.5.3.1.1?
        return Ok(SignatureAlgorithm::/*EcdsaSecp256k1*/BLS); // FIXME@P1: `local` network algorithm seems to be Secp256k1
    }

    if spki.algorithm.oid == ALGORITHM_OID {
        let params = spki
            .algorithm
            .parameters
            .ok_or(IiAuthError::UnsupportedKeyAlgorithm)?;
        let curve_oid = params
            .decode_as::<EcParameters>()
            .map_err(|_| IiAuthError::InvalidPublicKey)?
            .named_curve()
            .ok_or(IiAuthError::UnsupportedKeyAlgorithm)?;

        return match curve_oid {
            oid if oid == NistP256::OID => Ok(SignatureAlgorithm::EcdsaP256),
            oid if oid == Secp256k1::OID => Ok(SignatureAlgorithm::EcdsaSecp256k1),
            _ => Err(IiAuthError::UnsupportedKeyAlgorithm),
        };
    }

    if spki.algorithm.oid == NistP256::OID
        || spki.algorithm.oid == ObjectIdentifier::new_unwrap("1.3.6.1.4.1.56387.1.1")
        || spki.algorithm.oid == ObjectIdentifier::new_unwrap("1.3.6.1.4.1.56387.1.2")
    {
        return Ok(SignatureAlgorithm::EcdsaP256);
    }

    if spki.algorithm.oid == Secp256k1::OID {
        return Ok(SignatureAlgorithm::EcdsaSecp256k1);
    }

    Err(IiAuthError::UnsupportedKeyAlgorithm)
}

fn verify_p256_signature(
    subject_public_key: &[u8],
    signature: &[u8],
    message_hash: [u8; 32],
) -> Result<(), IiAuthError> {
    let candidates = generate_sec1_candidates(subject_public_key, CurveKind::P256);
    let sig = P256Signature::try_from(signature).map_err(|_| IiAuthError::InvalidSignature)?;

    for (idx, candidate) in candidates.iter().enumerate() {
        match P256VerifyingKey::from_sec1_bytes(candidate) {
            Ok(vk) => match vk.verify_prehash(&message_hash, &sig) {
                Ok(()) => {
                    if idx > 0 {
                        warn!(
                            "Using alternate SEC1 interpretation for P-256 public key (candidate #{})",
                            idx
                        );
                    }
                    return Ok(());
                }
                Err(err) => warn!(
                    "P-256 SEC1 candidate #{idx} parsed but signature verification failed: {}",
                    err
                ),
            },
            Err(err) => warn!("P-256 SEC1 candidate #{idx} failed to parse: {}", err),
        }
    }

    Err(IiAuthError::VerificationFailed)
}

fn verify_k256_signature(
    subject_public_key: &[u8],
    signature: &[u8],
    message_hash: [u8; 32],
) -> Result<(), IiAuthError> {
    let candidates = generate_sec1_candidates(subject_public_key, CurveKind::Secp256k1);
    let sig = K256Signature::try_from(signature).map_err(|_| IiAuthError::InvalidSignature)?;

    for (idx, candidate) in candidates.iter().enumerate() {
        match K256VerifyingKey::from_sec1_bytes(candidate) {
            Ok(vk) => match vk.verify_prehash(&message_hash, &sig) {
                Ok(()) => {
                    if idx > 0 {
                        warn!(
                            "Using alternate SEC1 interpretation for secp256k1 public key (candidate #{})",
                            idx
                        );
                    }
                    return Ok(());
                }
                Err(err) => warn!(
                    "secp256k1 SEC1 candidate #{idx} parsed but signature verification failed: {}",
                    err
                ),
            },
            Err(err) => warn!("secp256k1 SEC1 candidate #{idx} failed to parse: {}", err),
        }
    }

    Err(IiAuthError::VerificationFailed)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CurveKind {
    P256,
    Secp256k1,
}

#[derive(Clone, Copy, Debug)]
enum Endian {
    Big,
    Little,
}

fn generate_sec1_candidates(bytes: &[u8], kind: CurveKind) -> Vec<Vec<u8>> {
    let mut candidates: Vec<Vec<u8>> = Vec::new();
    {
        let mut push_candidate = |data: Vec<u8>| {
            if !candidates
                .iter()
                .any(|existing| existing.as_slice() == data.as_slice())
            {
                candidates.push(data);
            }
        };

        if let Some(first) = bytes.first() {
            if matches!(first, 0x02 | 0x03 | 0x04) {
                push_candidate(bytes.to_vec());
                return candidates;
            }
        }

        if bytes.len() == 64 {
            let mut owned = Vec::with_capacity(65);
            owned.push(0x04);
            owned.extend_from_slice(bytes);
            warn!("Assuming uncompressed SEC1 point with missing prefix (64 bytes -> 65 bytes)");
            push_candidate(owned);
        }

        if let Some(candidate) = reconstruct_truncated_vec(bytes, kind, Endian::Big) {
            push_candidate(candidate);
        }
        if let Some(candidate) = reconstruct_truncated_vec(bytes, kind, Endian::Little) {
            push_candidate(candidate);
        }

        if let Some(candidate) = rebuild_from_compact_vec(bytes, kind, Endian::Big) {
            push_candidate(candidate);
        }
        if let Some(candidate) = rebuild_from_compact_vec(bytes, kind, Endian::Little) {
            push_candidate(candidate);
        }

        let needs_default = candidates.is_empty();
        if needs_default {
            if !candidates
                .iter()
                .any(|existing| existing.as_slice() == bytes)
            {
                candidates.push(bytes.to_vec());
            }
        }
    }

    candidates
}

fn reconstruct_truncated_vec(bytes: &[u8], kind: CurveKind, endian: Endian) -> Option<Vec<u8>> {
    if kind != CurveKind::P256 || bytes.len() < 3 {
        return None;
    }

    let prefix = bytes[0];
    if prefix != 0x0a {
        return None;
    }

    let remainder = &bytes[1..];
    if remainder.len() < 4 {
        return None;
    }

    let split = remainder.len() / 2;
    let (x_bytes, y_bytes) = remainder.split_at(split);
    let x_full = expand_coord_with_endian(x_bytes, endian)?;
    let y_full = expand_coord_with_endian(y_bytes, endian)?;

    let mut owned = Vec::with_capacity(65);
    owned.push(0x04);
    owned.extend_from_slice(&x_full);
    owned.extend_from_slice(&y_full);

    warn!(
        "Reconstructed SEC1 point from truncated vendor encoding (prefix 0x{:02x}, x_len {}, y_len {}, endian {:?})",
        prefix,
        x_bytes.len(),
        y_bytes.len(),
        endian
    );

    Some(owned)
}

fn rebuild_from_compact_vec(bytes: &[u8], kind: CurveKind, endian: Endian) -> Option<Vec<u8>> {
    if bytes.len() <= 1 {
        return None;
    }

    let prefix = bytes[0];
    let expected_prefix = match kind {
        CurveKind::P256 => 0x0a,
        CurveKind::Secp256k1 => 0x0b,
    };

    if prefix != expected_prefix {
        return None;
    }

    let remainder = &bytes[1..];
    if remainder.len() % 2 != 0 {
        return None;
    }

    let coord_len = remainder.len() / 2;
    if coord_len == 0 || coord_len > 32 {
        warn!(
            "Compact encoding prefix 0x{:02x} with coord_len {} is outside expected bounds",
            prefix, coord_len
        );
        return None;
    }

    let (x_bytes, y_bytes) = remainder.split_at(coord_len);
    let x_full = expand_coord_with_endian(x_bytes, endian)?;
    let y_full = expand_coord_with_endian(y_bytes, endian)?;

    let mut owned = Vec::with_capacity(65);
    owned.push(0x04);
    owned.extend_from_slice(&x_full);
    owned.extend_from_slice(&y_full);

    warn!(
        "Reconstructed SEC1 point from compact encoding (prefix 0x{:02x}, coord_len {}, endian {:?})",
        prefix,
        coord_len,
        endian
    );

    Some(owned)
}

fn expand_coord_with_endian(coord: &[u8], endian: Endian) -> Option<[u8; 32]> {
    if coord.len() > 32 {
        return None;
    }

    let mut out = [0u8; 32];
    match endian {
        Endian::Big => {
            out[32 - coord.len()..].copy_from_slice(coord);
        }
        Endian::Little => {
            for (i, byte) in coord.iter().enumerate() {
                out[i] = *byte;
            }
            out[..].reverse();
        }
    }

    Some(out)
}

fn verify_internet_identity(
    req: &OAuthRequest,
    store: &ChallengeStoreHandle,
    root_key: &[u8],
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

    // root key, TODO@P3: Move to config.
    // FIXME: This is for ICP mainnet ("unsupported public key algorithm"):
    // let root_key = hex::decode("308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100814c0e6ec71fab583b08bd81373c255c3c371b2e84863c98a4f1e08b74235d14fb5d9c0cd546d9685f913a0c0b2cc5341583bf4b4392e467db96d65b9bb4cb717112f8472e0d5a4d14505ffd7484b01291091c5f87b98883463f98091a0baaae").unwrap();
    let signing_key = verify_delegation_chain(/*&proof.public_key*/root_key, &proof.delegations)?;
    let mut signed_message = Vec::with_capacity(IC_REQUEST_DOMAIN.len() + proof.challenge.len());
    // signed_message.extend_from_slice(IC_REQUEST_DOMAIN); // TODO@P2: It has been tested to work with this commented, despite specs?
    signed_message.extend_from_slice(&proof.challenge);
    verify_signature(&signing_key, &proof.signature, &signed_message)?;

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
    pub fn preconfigured(challenge_store: ChallengeStoreHandle, root_key: Vec<u8>) -> Self {
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
            root_key,
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

        let owner_principal = verify_internet_identity(&request, &self.challenge_store, self.root_key.as_slice())
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
    root_key: Vec<u8>,
}

impl InternetIdentitySolicitor {
    fn new(challenge_store: ChallengeStoreHandle, root_key: Vec<u8>) -> Self {
        Self { challenge_store, root_key }
    }
}

impl OwnerSolicitor<OAuthRequest> for InternetIdentitySolicitor {
    fn check_consent(
        &mut self,
        request: &mut OAuthRequest,
        _: Solicitation,
    ) -> OwnerConsent<OAuthResponse> {
        match verify_internet_identity(request, &self.challenge_store, self.root_key.as_slice()) {
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
                self.with_solicitor(InternetIdentitySolicitor::new(self.challenge_store.clone(), self.root_key.clone())), // TODO@P3: `clone()`
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


fn hash_tree(node: &serde_cbor::Value) -> [u8; 32] {
    use serde_cbor::Value;

    match node {
        // Empty node
        Value::Integer(0) => {
            let mut h = Sha256::new();
            h.update(b"ic-hashtree-empty");
            h.finalize().into()
        }

        // Fork
        Value::Array(items) if items.len() == 3 && items[0] == Value::Integer(1) => {
            let left = hash_tree(&items[1]);
            let right = hash_tree(&items[2]);
            let mut h = Sha256::new();
            h.update(b"ic-hashtree-fork");
            h.update(left);
            h.update(right);
            h.finalize().into()
        }

        // Labeled
        Value::Array(items) if items.len() == 3 && items[0] == Value::Integer(2) => {
            let label = if let Value::Bytes(b) = &items[1] { b } else { panic!("bad label") };
            let sub = hash_tree(&items[2]);
            let mut h = Sha256::new();
            h.update(b"ic-hashtree-labeled");
            h.update(label);
            h.update(sub);
            h.finalize().into()
        }

        // Leaf
        Value::Array(items) if items.len() == 2 && items[0] == Value::Integer(3) => {
            let data = if let Value::Bytes(b) = &items[1] { b } else { panic!("bad leaf") };
            let mut h = Sha256::new();
            h.update(b"ic-hashtree-leaf");
            h.update(data);
            h.finalize().into()
        }

        // Pruned
        Value::Array(items) if items.len() == 2 && items[0] == Value::Integer(4) => {
            if let Value::Bytes(b) = &items[1] {
                let mut digest = [0u8; 32];
                digest.copy_from_slice(b);
                digest
            } else {
                panic!("bad pruned digest") // FIXME@P2
            }
        }

        _ => panic!("unexpected tree format: {:?}", node), // FIXME@P2
    }
}