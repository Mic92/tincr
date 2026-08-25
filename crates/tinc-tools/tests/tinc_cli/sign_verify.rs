use super::{Conf, Run};
use std::fs;
use std::str;

fn body(run: Run) -> Vec<u8> {
    assert!(run.success, "{}", run.stderr);
    run.raw_stdout
}

/// `Signature = NAME TIME SIG86` header, then the body byte-exact;
/// `verify` (own name `.`, any `*`, explicit) emits the body again.
#[test]
fn sign_verify_roundtrip() {
    let conf = Conf::init("alice");
    let data: &[u8] = b"hello world\nbinary: \x00\xff\n";
    let payload = conf.dir().join("payload");
    fs::write(&payload, data).unwrap();

    let signed = body(conf.tinc(&["sign", payload.to_str().unwrap()]));
    let newline = signed.iter().position(|&b| b == b'\n').unwrap();
    let header: Vec<&str> = str::from_utf8(&signed[..newline])
        .unwrap()
        .split(' ')
        .collect();
    let [_, _, _, time, sig] = header[..] else {
        panic!("{header:?}");
    };
    assert_eq!(header[..3], ["Signature", "=", "alice"]);
    assert!(time.parse::<i64>().unwrap() > 1_700_000_000);
    assert_eq!(sig.len(), 86);
    assert_eq!(&signed[newline + 1..], data);

    let signed_path = conf.dir().join("signed");
    fs::write(&signed_path, &signed).unwrap();
    assert_eq!(
        body(conf.tinc(&["verify", ".", signed_path.to_str().unwrap()])),
        data
    );
    for signer in [".", "*", "alice"] {
        assert_eq!(
            body(conf.tinc_stdin(&["verify", signer], &signed)),
            data,
            "{signer}"
        );
    }
    let run = conf.tinc_stdin(&["verify", "bob"], &signed);
    assert_eq!(run.stdout, "");
    run.fails_with("Signature is not made by bob");
}

#[test]
fn sign_verify_need_config_and_signer() {
    let conf = Conf::bare();
    conf.tinc(&["verify"]).fails_with("No signer given");
    conf.tinc(&["sign"]).fails_with("tinc.conf");
}

/// The deployment pattern: alice signs, bob verifies against
/// `hosts/alice` in his own confbase.
#[test]
fn verify_on_another_node() {
    let alice = Conf::init("alice");
    let bob = Conf::init("bob");
    fs::copy(alice.host("alice"), bob.host("alice")).unwrap();
    let data = b"cross-node payload";
    let signed = body(alice.tinc_stdin(&["sign"], data));
    for signer in ["*", "alice"] {
        assert_eq!(body(bob.tinc_stdin(&["verify", signer], &signed)), data);
    }
}
