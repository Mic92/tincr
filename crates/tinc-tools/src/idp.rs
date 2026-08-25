//! OIDC identity provider backed by mesh identity. Operator
//! documentation lives in `docs/AUTH.md`.
//!
//! HTTP-agnostic: handlers take parsed request pieces and return
//! [`HttpResponse`]. The binary maps `tiny_http` requests onto them,
//! tests call them directly.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::str;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use rand_core::Rng;
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rsa::sha2::{Digest, Sha256};
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use serde::Deserialize;
use serde_json::{Value, json};
use subtle::ConstantTimeEq;
use tinc_crypto::os_rng;

pub const DEFAULT_ID_TOKEN_TTL: Duration = Duration::from_mins(5);
pub const DEFAULT_ACCESS_TOKEN_TTL: Duration = Duration::from_hours(1);
const CODE_TTL: Duration = Duration::from_mins(5);
const NBF_SKEW: u64 = 5 * 60;

pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    fn json(status: u16, v: &Value) -> Self {
        Self {
            status,
            headers: vec![("Content-Type", "application/json".into())],
            body: v.to_string().into_bytes(),
        }
    }

    fn json_cors(status: u16, v: &Value) -> Self {
        let mut r = Self::json(status, v);
        r.headers.push(("Access-Control-Allow-Origin", "*".into()));
        r.headers
            .push(("Access-Control-Allow-Methods", "GET, OPTIONS".into()));
        r
    }

    fn text(status: u16, msg: &str) -> Self {
        Self {
            status,
            headers: vec![("Content-Type", "text/plain".into())],
            body: msg.as_bytes().to_vec(),
        }
    }

    fn redirect(location: String) -> Self {
        Self {
            status: 302,
            headers: vec![("Location", location)],
            body: Vec::new(),
        }
    }

    fn oauth_error(status: u16, error: &str, desc: &str) -> Self {
        Self::json(
            status,
            &json!({ "error": error, "error_description": desc }),
        )
    }
}

#[derive(Deserialize)]
pub struct Client {
    pub id: String,
    pub secret: String,
    pub redirect_uris: Vec<String>,
}

pub struct Config {
    pub issuer: String,
    pub netname: String,
    pub clients: Vec<Client>,
    pub groups: HashMap<String, Vec<String>>,
    pub email_domain: Option<String>,
    pub id_token_ttl: Duration,
    pub access_token_ttl: Duration,
}

/// Node identity as established by the subnet whois. `user` is the
/// account the node maps to, which is the node name itself unless a
/// `--map` file says otherwise.
pub struct Node {
    pub name: String,
    pub user: String,
    pub subnet: String,
}

/// `Err(())` means the control socket is unavailable. Fail closed.
pub type Whois = Result<Option<Node>, ()>;

struct AuthCode {
    node: String,
    user: String,
    subnet: String,
    client_id: String,
    redirect_uri: String,
    nonce: Option<String>,
    pkce_s256: Option<String>,
    expires: u64,
}

struct AccessGrant {
    claims: Value,
    expires: u64,
}

#[derive(Default)]
struct State {
    codes: HashMap<String, AuthCode>,
    tokens: HashMap<String, AccessGrant>,
}

pub struct Idp {
    config: Config,
    signer: SigningKey<Sha256>,
    kid: String,
    jwks: Value,
    state: Mutex<State>,
}

/// Loads the RSA-2048 signing key, generating it on first start.
///
/// # Errors
/// On io, keygen, or PEM failure.
pub fn load_or_create_key(path: &Path) -> Result<RsaPrivateKey, String> {
    if path.exists() {
        let pem = fs::read_to_string(path).map_err(|e| e.to_string())?;
        return RsaPrivateKey::from_pkcs8_pem(&pem).map_err(|e| e.to_string());
    }
    let key = RsaPrivateKey::new(&mut os_rng(), 2048).map_err(|e| e.to_string())?;
    let pem = key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| e.to_string())?;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| e.to_string())?;
    f.write_all(pem.as_bytes()).map_err(|e| e.to_string())?;
    Ok(key)
}

#[must_use]
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn random_token() -> String {
    let mut b = [0u8; 32];
    os_rng().fill_bytes(&mut b);
    URL_SAFE_NO_PAD.encode(b)
}

fn ct_eq(a: &str, b: &str) -> bool {
    let ha = Sha256::digest(a.as_bytes());
    let hb = Sha256::digest(b.as_bytes());
    ha.ct_eq(&hb).into()
}

fn percent_decode(s: &str) -> String {
    let mut out = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 3 <= bytes.len() => {
                let hex = str::from_utf8(&bytes[i + 1..i + 3]).ok();
                if let Some(v) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    out.push(v);
                    i += 3;
                    continue;
                }
                out.push(b'%');
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

/// Parses `a=b&c=d` with percent-decoding. Later keys win.
#[must_use]
pub fn parse_form(s: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for pair in s.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        out.insert(percent_decode(k), percent_decode(v));
    }
    out
}

fn append_query(uri: &str, params: &[(&str, &str)]) -> String {
    let mut out = uri.to_owned();
    let mut sep = if uri.contains('?') { '&' } else { '?' };
    for (k, v) in params {
        let _ = write!(out, "{sep}{k}={}", percent_encode(v));
        sep = '&';
    }
    out
}

fn parse_basic_auth(header: Option<&str>) -> Option<(String, String)> {
    let b64 = header?.strip_prefix("Basic ")?;
    let raw = STANDARD.decode(b64.trim()).ok()?;
    let s = String::from_utf8(raw).ok()?;
    let (id, secret) = s.split_once(':')?;
    Some((percent_decode(id), percent_decode(secret)))
}

impl Idp {
    #[must_use]
    pub fn new(config: Config, key: RsaPrivateKey) -> Self {
        let kid_digest = Sha256::digest(key.n().to_be_bytes_trimmed_vartime());
        let kid = URL_SAFE_NO_PAD.encode(&kid_digest[..8]);
        let jwks = json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": kid,
                "n": URL_SAFE_NO_PAD.encode(key.n().to_be_bytes_trimmed_vartime()),
                "e": URL_SAFE_NO_PAD.encode(key.e().to_be_bytes_trimmed_vartime()),
            }]
        });
        Self {
            config,
            signer: SigningKey::<Sha256>::new(key),
            kid,
            jwks,
            state: Mutex::new(State::default()),
        }
    }

    pub fn discovery(&self) -> HttpResponse {
        let iss = &self.config.issuer;
        HttpResponse::json_cors(
            200,
            &json!({
                "issuer": iss,
                "authorization_endpoint": format!("{iss}/authorize"),
                "token_endpoint": format!("{iss}/token"),
                "userinfo_endpoint": format!("{iss}/userinfo"),
                "jwks_uri": format!("{iss}/.well-known/jwks.json"),
                "scopes_supported": ["openid", "profile", "email"],
                "response_types_supported": ["code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "token_endpoint_auth_methods_supported":
                    ["client_secret_basic", "client_secret_post"],
                "claims_supported": ["sub", "aud", "exp", "iat", "iss", "jti", "nbf",
                    "nonce", "preferred_username", "email", "groups",
                    "tinc_net", "tinc_subnet"],
                "code_challenge_methods_supported": ["S256"],
            }),
        )
    }

    pub fn jwks(&self) -> HttpResponse {
        HttpResponse::json_cors(200, &self.jwks)
    }

    pub fn authorize(&self, query: &str, whois: Whois, now: u64) -> HttpResponse {
        let q = parse_form(query);
        let Some(client) = q
            .get("client_id")
            .and_then(|id| self.config.clients.iter().find(|c| c.id == *id))
        else {
            return HttpResponse::text(400, "unknown client_id");
        };
        let Some(redirect_uri) = q
            .get("redirect_uri")
            .filter(|u| client.redirect_uris.iter().any(|r| r == *u))
        else {
            return HttpResponse::text(400, "redirect_uri not registered for client");
        };

        let state = q.get("state").map(String::as_str);
        let err = |error: &str, desc: &str| {
            let mut params = vec![("error", error), ("error_description", desc)];
            if let Some(s) = state {
                params.push(("state", s));
            }
            HttpResponse::redirect(append_query(redirect_uri, &params))
        };

        if q.get("response_type").map(String::as_str) != Some("code") {
            return err("unsupported_response_type", "only code is supported");
        }
        let pkce_s256 = match q.get("code_challenge_method").map(String::as_str) {
            None | Some("S256") => q.get("code_challenge").cloned(),
            Some(_) => return err("invalid_request", "only S256 is supported"),
        };
        let node = match whois {
            Err(()) => return err("temporarily_unavailable", "tincd unreachable"),
            Ok(None) => return err("access_denied", "source address is not a mesh node"),
            Ok(Some(n)) => n,
        };

        let code = random_token();
        self.state().codes.insert(
            code.clone(),
            AuthCode {
                node: node.name,
                user: node.user,
                subnet: node.subnet,
                client_id: client.id.clone(),
                redirect_uri: redirect_uri.clone(),
                nonce: q.get("nonce").cloned(),
                pkce_s256,
                expires: now + CODE_TTL.as_secs(),
            },
        );

        let mut params = vec![("code", code.as_str())];
        if let Some(s) = state {
            params.push(("state", s));
        }
        HttpResponse::redirect(append_query(redirect_uri, &params))
    }

    pub fn token(&self, body: &str, authorization: Option<&str>, now: u64) -> HttpResponse {
        let f = parse_form(body);
        if f.get("grant_type").map(String::as_str) != Some("authorization_code") {
            return HttpResponse::oauth_error(
                400,
                "unsupported_grant_type",
                "only authorization_code is supported",
            );
        }
        let Some(code) = f.get("code") else {
            return HttpResponse::oauth_error(400, "invalid_request", "code is required");
        };
        let Some(ac) = self.state().codes.remove(code) else {
            return HttpResponse::oauth_error(400, "invalid_grant", "unknown code");
        };
        if ac.expires <= now {
            return HttpResponse::oauth_error(400, "invalid_grant", "code expired");
        }

        let (client_id, client_secret) = match parse_basic_auth(authorization) {
            Some(pair) => pair,
            None => match (f.get("client_id"), f.get("client_secret")) {
                (Some(i), Some(s)) => (i.clone(), s.clone()),
                _ => {
                    return HttpResponse::oauth_error(
                        401,
                        "invalid_client",
                        "client credentials required",
                    );
                }
            },
        };
        let secret_ok = self
            .config
            .clients
            .iter()
            .find(|c| c.id == client_id)
            .is_some_and(|c| ct_eq(&c.secret, &client_secret));
        if client_id != ac.client_id || !secret_ok {
            return HttpResponse::oauth_error(401, "invalid_client", "bad client credentials");
        }

        if f.get("redirect_uri") != Some(&ac.redirect_uri) {
            return HttpResponse::oauth_error(400, "invalid_grant", "redirect_uri mismatch");
        }
        if let Some(challenge) = &ac.pkce_s256 {
            let ok = f.get("code_verifier").is_some_and(|v| {
                let d = Sha256::digest(v.as_bytes());
                ct_eq(&URL_SAFE_NO_PAD.encode(d), challenge)
            });
            if !ok {
                return HttpResponse::oauth_error(400, "invalid_grant", "PKCE verification failed");
            }
        }

        let id_token = self.sign_id_token(&ac, now);
        let access = random_token();
        self.state().tokens.insert(
            access.clone(),
            AccessGrant {
                claims: self.claims_for(&ac.node, &ac.user, &ac.subnet),
                expires: now + self.config.access_token_ttl.as_secs(),
            },
        );
        HttpResponse::json(
            200,
            &json!({
                "access_token": access,
                "token_type": "Bearer",
                "expires_in": self.config.access_token_ttl.as_secs(),
                "id_token": id_token,
            }),
        )
    }

    pub fn userinfo(&self, authorization: Option<&str>, now: u64) -> HttpResponse {
        let token = authorization.and_then(|h| h.strip_prefix("Bearer "));
        let st = self.state();
        match token.and_then(|t| st.tokens.get(t)) {
            Some(g) if g.expires > now => HttpResponse::json(200, &g.claims),
            _ => {
                let mut r =
                    HttpResponse::oauth_error(401, "invalid_token", "unknown or expired token");
                r.headers
                    .push(("WWW-Authenticate", "Bearer error=\"invalid_token\"".into()));
                r
            }
        }
    }

    pub fn sweep(&self, now: u64) {
        let mut st = self.state();
        st.codes.retain(|_, c| c.expires > now);
        st.tokens.retain(|_, t| t.expires > now);
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn claims_for(&self, node: &str, user: &str, subnet: &str) -> Value {
        let mut v = json!({
            "sub": user,
            "preferred_username": user,
            "tinc_node": node,
            "tinc_net": self.config.netname,
            "tinc_subnet": subnet,
            "groups": self.config.groups.get(user).cloned().unwrap_or_default(),
        });
        if let Some(d) = &self.config.email_domain {
            v["email"] = json!(format!("{user}@{d}"));
        }
        v
    }

    fn sign_id_token(&self, ac: &AuthCode, now: u64) -> String {
        let header = json!({ "alg": "RS256", "typ": "JWT", "kid": self.kid });
        let mut claims = self.claims_for(&ac.node, &ac.user, &ac.subnet);
        claims["iss"] = json!(self.config.issuer);
        claims["aud"] = json!(ac.client_id);
        claims["iat"] = json!(now);
        claims["nbf"] = json!(now.saturating_sub(NBF_SKEW));
        claims["exp"] = json!(now + self.config.id_token_ttl.as_secs());
        claims["jti"] = json!(random_token());
        if let Some(n) = &ac.nonce {
            claims["nonce"] = json!(n);
        }
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string()),
        );
        let sig = self.signer.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }
}

#[cfg(test)]
mod tests;
