use super::*;
use rsa::RsaPublicKey;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use std::sync::OnceLock;

const NOW: u64 = 1_700_000_000;

fn test_key() -> &'static RsaPrivateKey {
    static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
    KEY.get_or_init(|| RsaPrivateKey::new(&mut OsRng, 2048).unwrap())
}

fn test_idp() -> Idp {
    let config = Config {
        issuer: "http://idp.mesh:8443".into(),
        netname: "mesh".into(),
        clients: vec![Client {
            id: "grafana".into(),
            secret: "s3cret".into(),
            redirect_uris: vec![
                "http://grafana.mesh/login/oidc".into(),
                "http://grafana.mesh/cb?tenant=1".into(),
            ],
        }],
        groups: HashMap::from([("alice".into(), vec!["admin".into()])]),
        email_domain: Some("example.com".into()),
        id_token_ttl: DEFAULT_ID_TOKEN_TTL,
        access_token_ttl: DEFAULT_ACCESS_TOKEN_TTL,
    };
    Idp::new(config, test_key().clone())
}

#[allow(clippy::unnecessary_wraps)] // Whois is the API type
fn alice() -> Whois {
    Ok(Some(Node {
        name: "alice".into(),
        subnet: "10.0.0.2/32".into(),
    }))
}

fn location(r: &HttpResponse) -> &str {
    assert_eq!(r.status, 302);
    &r.headers.iter().find(|(k, _)| *k == "Location").unwrap().1
}

fn body_json(r: &HttpResponse) -> Value {
    serde_json::from_slice(&r.body).unwrap()
}

fn authorize_code(idp: &Idp, extra: &str) -> String {
    let q = format!(
        "response_type=code&client_id=grafana&redirect_uri=http%3A%2F%2Fgrafana.mesh%2Flogin%2Foidc{extra}"
    );
    let r = idp.authorize(&q, alice(), NOW);
    let loc = location(&r).to_owned();
    let (_, query) = loc.split_once('?').unwrap();
    parse_form(query).remove("code").unwrap()
}

fn token_body(code: &str) -> String {
    format!(
        "grant_type=authorization_code&code={code}\
         &redirect_uri=http%3A%2F%2Fgrafana.mesh%2Flogin%2Foidc\
         &client_id=grafana&client_secret=s3cret"
    )
}

fn decode_jwt(token: &str) -> (Value, Value) {
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);
    let verifier = VerifyingKey::<Sha256>::new(RsaPublicKey::from(test_key()));
    let sig = Signature::try_from(URL_SAFE_NO_PAD.decode(parts[2]).unwrap().as_slice()).unwrap();
    let signed = format!("{}.{}", parts[0], parts[1]);
    verifier.verify(signed.as_bytes(), &sig).unwrap();
    let header = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
    let claims = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    (header, claims)
}

#[test]
fn discovery_has_required_fields() {
    let idp = test_idp();
    let v = body_json(&idp.discovery());
    assert_eq!(v["issuer"], "http://idp.mesh:8443");
    assert_eq!(v["jwks_uri"], "http://idp.mesh:8443/.well-known/jwks.json");
    assert_eq!(v["subject_types_supported"][0], "public");
    assert_eq!(v["id_token_signing_alg_values_supported"][0], "RS256");
    assert_eq!(
        v["token_endpoint_auth_methods_supported"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let cors = &idp.discovery().headers;
    assert!(
        cors.iter()
            .any(|(k, v)| *k == "Access-Control-Allow-Origin" && v == "*")
    );
}

#[test]
fn full_code_flow() {
    let idp = test_idp();
    let code = authorize_code(&idp, "&state=xyz&nonce=n0nce");

    let r = idp.token(&token_body(&code), None, NOW);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let v = body_json(&r);
    assert_eq!(v["token_type"], "Bearer");
    assert!(v.get("refresh_token").is_none());

    let (header, claims) = decode_jwt(v["id_token"].as_str().unwrap());
    assert_eq!(header["alg"], "RS256");
    assert_eq!(claims["iss"], "http://idp.mesh:8443");
    assert_eq!(claims["sub"], "alice");
    assert_eq!(claims["aud"], "grafana");
    assert_eq!(claims["nonce"], "n0nce");
    assert_eq!(claims["nbf"], NOW - 300);
    assert_eq!(claims["exp"], NOW + 300);
    assert_eq!(claims["groups"][0], "admin");
    assert_eq!(claims["email"], "alice@example.com");
    assert_eq!(claims["tinc_net"], "mesh");
    assert_eq!(claims["tinc_subnet"], "10.0.0.2/32");

    let access = v["access_token"].as_str().unwrap();
    let r = idp.userinfo(Some(&format!("Bearer {access}")), NOW);
    assert_eq!(r.status, 200);
    let u = body_json(&r);
    assert_eq!(u["sub"], "alice");
    assert_eq!(u["preferred_username"], "alice");
}

#[test]
fn state_round_trips_and_query_merges() {
    let idp = test_idp();
    let q = "response_type=code&client_id=grafana\
             &redirect_uri=http%3A%2F%2Fgrafana.mesh%2Fcb%3Ftenant%3D1&state=a%2Bb";
    let r = idp.authorize(q, alice(), NOW);
    let loc = location(&r);
    assert!(
        loc.starts_with("http://grafana.mesh/cb?tenant=1&code="),
        "{loc}"
    );
    assert!(loc.ends_with("&state=a%2Bb"), "{loc}");
}

#[test]
fn authorize_rejects_before_redirect_validation() {
    let idp = test_idp();
    let r = idp.authorize(
        "client_id=nope&redirect_uri=http%3A%2F%2Fevil",
        alice(),
        NOW,
    );
    assert_eq!(r.status, 400);
    let r = idp.authorize(
        "client_id=grafana&redirect_uri=http%3A%2F%2Fevil",
        alice(),
        NOW,
    );
    assert_eq!(r.status, 400);
}

#[test]
fn authorize_errors_redirect_after_validation() {
    let idp = test_idp();
    let base = "client_id=grafana&redirect_uri=http%3A%2F%2Fgrafana.mesh%2Flogin%2Foidc&state=s";
    for (extra, whois, want) in [
        ("&response_type=token", alice(), "unsupported_response_type"),
        (
            "&response_type=code&code_challenge_method=plain&code_challenge=x",
            alice(),
            "invalid_request",
        ),
        ("&response_type=code", Err(()), "temporarily_unavailable"),
        ("&response_type=code", Ok(None), "access_denied"),
    ] {
        let r = idp.authorize(&format!("{base}{extra}"), whois, NOW);
        let loc = location(&r);
        assert!(loc.contains(&format!("error={want}")), "{loc}");
        assert!(loc.contains("state=s"), "{loc}");
    }
}

#[test]
fn code_is_single_use_and_expires() {
    let idp = test_idp();
    let code = authorize_code(&idp, "");
    assert_eq!(idp.token(&token_body(&code), None, NOW).status, 200);
    let r = idp.token(&token_body(&code), None, NOW);
    assert_eq!(body_json(&r)["error"], "invalid_grant");

    let code = authorize_code(&idp, "");
    let r = idp.token(&token_body(&code), None, NOW + CODE_TTL.as_secs());
    assert_eq!(body_json(&r)["error"], "invalid_grant");
}

#[test]
fn token_client_auth() {
    let idp = test_idp();
    let code = authorize_code(&idp, "");
    let bad = token_body(&code).replace("s3cret", "wrong");
    let r = idp.token(&bad, None, NOW);
    assert_eq!(r.status, 401);
    assert_eq!(body_json(&r)["error"], "invalid_client");

    // same code is gone: single-use even on failed client auth
    let code = authorize_code(&idp, "");
    let body = format!(
        "grant_type=authorization_code&code={code}\
         &redirect_uri=http%3A%2F%2Fgrafana.mesh%2Flogin%2Foidc"
    );
    let basic = format!("Basic {}", STANDARD.encode("grafana:s3cret"));
    let r = idp.token(&body, Some(&basic), NOW);
    assert_eq!(r.status, 200);
}

#[test]
fn token_redirect_uri_must_match_code() {
    let idp = test_idp();
    let code = authorize_code(&idp, "");
    let body = token_body(&code).replace("%2Flogin%2Foidc", "%2Fother");
    let r = idp.token(&body, None, NOW);
    assert_eq!(body_json(&r)["error"], "invalid_grant");
}

#[test]
fn pkce_s256() {
    let idp = test_idp();
    let verifier = "some-code-verifier-string-43-chars-minimum-x";
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let code = authorize_code(
        &idp,
        &format!("&code_challenge_method=S256&code_challenge={challenge}"),
    );
    let r = idp.token(
        &format!("{}&code_verifier={verifier}", token_body(&code)),
        None,
        NOW,
    );
    assert_eq!(r.status, 200);

    let code = authorize_code(
        &idp,
        &format!("&code_challenge_method=S256&code_challenge={challenge}"),
    );
    let r = idp.token(
        &format!("{}&code_verifier=wrong", token_body(&code)),
        None,
        NOW,
    );
    assert_eq!(body_json(&r)["error"], "invalid_grant");
}

#[test]
fn userinfo_rejects_expired_and_unknown() {
    let idp = test_idp();
    let r = idp.userinfo(Some("Bearer nope"), NOW);
    assert_eq!(r.status, 401);
    assert!(r.headers.iter().any(|(k, _)| *k == "WWW-Authenticate"));

    let code = authorize_code(&idp, "");
    let v = body_json(&idp.token(&token_body(&code), None, NOW));
    let access = v["access_token"].as_str().unwrap();
    let later = NOW + DEFAULT_ACCESS_TOKEN_TTL.as_secs();
    let r = idp.userinfo(Some(&format!("Bearer {access}")), later);
    assert_eq!(r.status, 401);
}

#[test]
fn sweep_drops_expired_state() {
    let idp = test_idp();
    let _ = authorize_code(&idp, "");
    let code = authorize_code(&idp, "");
    let _ = body_json(&idp.token(&token_body(&code), None, NOW));
    idp.sweep(NOW + 2 * DEFAULT_ACCESS_TOKEN_TTL.as_secs());
    let st = idp
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert!(st.codes.is_empty());
    assert!(st.tokens.is_empty());
}

#[test]
fn form_parsing_decodes() {
    let f = parse_form("a=1%2B2&b=x+y&empty&pct=%zz");
    assert_eq!(f["a"], "1+2");
    assert_eq!(f["b"], "x y");
    assert_eq!(f["empty"], "");
    assert_eq!(f["pct"], "%zz");
}
