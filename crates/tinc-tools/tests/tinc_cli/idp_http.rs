//! The OIDC provider half of `tinc-auth`, over real HTTP. The subnet
//! dump assigns 127.0.0.1 to alice so both the bind check and the
//! `/authorize` whois succeed on loopback.

use super::{AuthDaemon, Conf, HttpResponse};
use base64::Engine;
use std::io::Write;
use std::net::TcpStream;

fn serve_subnets(conf: &Conf) {
    conf.serve_forever(|ctl| {
        ctl.expect("18 5");
        ctl.send("18 5 127.0.0.1/32 alice");
        ctl.send("18 5 10.0.0.0/24 bob");
        ctl.send("18 5");
    });
}

fn start_idp(conf: &Conf) -> (AuthDaemon, u16) {
    conf.write("tinc.conf", "Name = alice\n");
    let clients = conf.dir().join("clients.json");
    std::fs::write(
        &clients,
        r#"[{"id":"app","secret":"hunter2","redirect_uris":["http://app.mesh/cb"]}]"#,
    )
    .unwrap();
    let groups = conf.dir().join("groups.json");
    std::fs::write(&groups, r#"{"ajones":["admin"]}"#).unwrap();
    let map = conf.dir().join("map.json");
    std::fs::write(&map, r#"{"alice":"ajones"}"#).unwrap();
    let mut idp = AuthDaemon::spawn(
        conf,
        &[
            "--idp-listen",
            "127.0.0.1:0",
            "--issuer",
            "http://idp.mesh",
            "--clients",
            clients.to_str().unwrap(),
            "--groups",
            groups.to_str().unwrap(),
            "--map",
            map.to_str().unwrap(),
            "--email-domain",
            "example.com",
        ],
    );
    let port = idp.wait_ready().expect("IdP port");
    (idp, port)
}

fn http(port: u16, request: &str) -> HttpResponse {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    HttpResponse::read(stream)
}

fn get(port: u16, path: &str) -> HttpResponse {
    http(
        port,
        &format!("GET {path} HTTP/1.1\r\nHost: idp\r\nConnection: close\r\n\r\n"),
    )
}

fn post_form(port: u16, path: &str, body: &str) -> HttpResponse {
    http(
        port,
        &format!(
            "POST {path} HTTP/1.1\r\nHost: idp\r\nConnection: close\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: {}\r\n\r\n{body}",
            body.len()
        ),
    )
}

#[test]
fn idp_full_flow_over_http() {
    let conf = Conf::bare();
    serve_subnets(&conf);
    let (_idp, port) = start_idp(&conf);

    let disco = get(port, "/.well-known/openid-configuration");
    assert_eq!(disco.status, 200);
    let d = disco.json();
    assert_eq!(d["issuer"], "http://idp.mesh");

    let jwks = get(port, "/.well-known/jwks.json").json();
    assert_eq!(jwks["keys"][0]["alg"], "RS256");

    let auth = get(
        port,
        "/authorize?response_type=code&client_id=app\
         &redirect_uri=http%3A%2F%2Fapp.mesh%2Fcb&state=st&nonce=nn",
    );
    assert_eq!(auth.status, 302);
    let loc = auth.header("Location").unwrap();
    assert!(loc.starts_with("http://app.mesh/cb?code="), "{loc}");
    let code = loc
        .split_once("code=")
        .unwrap()
        .1
        .split('&')
        .next()
        .unwrap()
        .to_owned();

    let tok = post_form(
        port,
        "/token",
        &format!(
            "grant_type=authorization_code&code={code}\
             &redirect_uri=http%3A%2F%2Fapp.mesh%2Fcb\
             &client_id=app&client_secret=hunter2"
        ),
    );
    assert_eq!(tok.status, 200, "{}", String::from_utf8_lossy(&tok.body));
    let t = tok.json();
    let id_token = t["id_token"].as_str().unwrap();
    let claims: serde_json::Value = {
        let payload = id_token.split('.').nth(1).unwrap();
        serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(payload)
                .unwrap(),
        )
        .unwrap()
    };
    // --map rewrites node alice to account ajones
    assert_eq!(claims["sub"], "ajones");
    assert_eq!(claims["aud"], "app");
    assert_eq!(claims["nonce"], "nn");
    assert_eq!(claims["email"], "ajones@example.com");
    assert_eq!(claims["groups"][0], "admin");
    assert_eq!(claims["tinc_node"], "alice");
    assert_eq!(claims["tinc_subnet"], "127.0.0.1/32");

    let access = t["access_token"].as_str().unwrap();
    let ui = http(
        port,
        &format!(
            "GET /userinfo HTTP/1.1\r\nHost: idp\r\nConnection: close\r\n\
             Authorization: Bearer {access}\r\n\r\n"
        ),
    );
    assert_eq!(ui.status, 200);
    assert_eq!(ui.json()["preferred_username"], "ajones");

    // replay is refused
    let replay = post_form(
        port,
        "/token",
        &format!(
            "grant_type=authorization_code&code={code}\
             &redirect_uri=http%3A%2F%2Fapp.mesh%2Fcb\
             &client_id=app&client_secret=hunter2"
        ),
    );
    assert_eq!(replay.status, 400);
    assert_eq!(replay.json()["error"], "invalid_grant");
}

/// 10.0.0.1 is bob's per the dump; alice may not serve the `IdP` there.
#[test]
fn idp_refuses_foreign_bind() {
    let conf = Conf::bare();
    serve_subnets(&conf);
    conf.write("tinc.conf", "Name = alice\n");
    let clients = conf.dir().join("clients.json");
    std::fs::write(&clients, "[]").unwrap();
    AuthDaemon::spawn(
        &conf,
        &[
            "--idp-listen",
            "10.0.0.1:0",
            "--issuer",
            "http://x",
            "--clients",
            clients.to_str().unwrap(),
        ],
    )
    .wait_output()
    .fails_with("refusing");
}
