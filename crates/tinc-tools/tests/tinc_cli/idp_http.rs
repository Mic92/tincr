#![cfg(unix)]

use super::bin;
use super::fake_daemon::{fake_daemon_setup, serve_greeting};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Idp {
    child: Child,
    port: u16,
}

impl Drop for Idp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Serves subnet dumps forever. The dump claims 127.0.0.1 for
/// `alice` so the bind check and /authorize whois both succeed
/// against a loopback listener.
fn serve_dumps(listener: std::os::unix::net::UnixListener, cookie: String) {
    std::thread::spawn(move || {
        while let Ok((stream, _)) = listener.accept() {
            let cookie = cookie.clone();
            std::thread::spawn(move || {
                let (mut br, mut w) = serve_greeting(&stream, &cookie);
                let mut req = String::new();
                br.read_line(&mut req).unwrap();
                assert_eq!(req.trim_end(), "18 5");
                writeln!(w, "18 5 127.0.0.1/32 alice").unwrap();
                writeln!(w, "18 5 10.0.0.0/24 bob").unwrap();
                writeln!(w, "18 5").unwrap();
            });
        }
    });
}

fn spawn_idp(dir: &std::path::Path, cb: &str, pf: &str, port: u16) -> Idp {
    std::fs::write(format!("{cb}/tinc.conf"), "Name = alice\n").unwrap();
    let clients = dir.join("clients.json");
    std::fs::write(
        &clients,
        r#"[{"id":"app","secret":"hunter2","redirect_uris":["http://app.mesh/cb"]}]"#,
    )
    .unwrap();
    let groups = dir.join("groups.json");
    std::fs::write(&groups, r#"{"ajones":["admin"]}"#).unwrap();
    let map = dir.join("map.json");
    std::fs::write(&map, r#"{"alice":"ajones"}"#).unwrap();

    let child = Command::new(bin("tinc-auth"))
        .args([
            "-c",
            cb,
            "-n",
            "mesh",
            "--pidfile",
            pf,
            "--idp-listen",
            &format!("127.0.0.1:{port}"),
            "--issuer",
            &format!("http://127.0.0.1:{port}"),
            "--clients",
            clients.to_str().unwrap(),
            "--groups",
            groups.to_str().unwrap(),
            "--map",
            map.to_str().unwrap(),
            "--email-domain",
            "example.com",
        ])
        .env_remove("LISTEN_PID")
        .env_remove("LISTEN_FDS")
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_mins(1);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        assert!(Instant::now() < deadline, "idp never came up");
        std::thread::sleep(Duration::from_millis(50));
    }
    Idp { child, port }
}

struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}

fn http(port: u16, request: &str) -> Response {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(request.as_bytes()).unwrap();

    let mut br = BufReader::new(s);
    let mut line = String::new();
    br.read_line(&mut line).unwrap();
    let status: u16 = line.split_whitespace().nth(1).unwrap().parse().unwrap();

    let mut headers = Vec::new();
    loop {
        line.clear();
        br.read_line(&mut line).unwrap();
        if line == "\r\n" || line == "\n" || line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_owned(), v.trim().to_owned()));
        }
    }
    let len: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .map_or(0, |(_, v)| v.parse().unwrap());
    let mut body = vec![0; len];
    br.read_exact(&mut body).unwrap();
    Response {
        status,
        headers,
        body,
    }
}

fn get(port: u16, path: &str) -> Response {
    http(
        port,
        &format!("GET {path} HTTP/1.1\r\nHost: idp\r\nConnection: close\r\n\r\n"),
    )
}

fn post_form(port: u16, path: &str, body: &str) -> Response {
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
    let (dir, cb, pf, listener, cookie) = fake_daemon_setup();
    serve_dumps(listener, cookie);
    let port = free_port();
    let idp = spawn_idp(dir.path(), &cb, &pf, port);

    let disco = get(idp.port, "/.well-known/openid-configuration");
    assert_eq!(disco.status, 200);
    let d = disco.json();
    assert_eq!(d["issuer"], format!("http://127.0.0.1:{port}"));

    let jwks = get(idp.port, "/.well-known/jwks.json").json();
    assert_eq!(jwks["keys"][0]["alg"], "RS256");

    let auth = get(
        idp.port,
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
        idp.port,
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
        use base64::Engine;
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
        idp.port,
        &format!(
            "GET /userinfo HTTP/1.1\r\nHost: idp\r\nConnection: close\r\n\
             Authorization: Bearer {access}\r\n\r\n"
        ),
    );
    assert_eq!(ui.status, 200);
    assert_eq!(ui.json()["preferred_username"], "ajones");

    // replay is refused
    let replay = post_form(
        idp.port,
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

#[test]
fn idp_refuses_foreign_bind() {
    let (dir, cb, pf, listener, cookie) = fake_daemon_setup();
    serve_dumps(listener, cookie);
    std::fs::write(format!("{cb}/tinc.conf"), "Name = bob\n").unwrap();
    let clients = dir.path().join("clients.json");
    std::fs::write(&clients, "[]").unwrap();

    let out = Command::new(bin("tinc-auth"))
        .args([
            "-c",
            &cb,
            "--pidfile",
            &pf,
            "--idp-listen",
            &format!("127.0.0.1:{}", free_port()),
            "--issuer",
            "http://x",
            "--clients",
            clients.to_str().unwrap(),
        ])
        .env_remove("LISTEN_PID")
        .env_remove("LISTEN_FDS")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("refusing"), "{stderr}");
}
