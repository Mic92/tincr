use tinc_tools::cmd::join::finalize_join;
use tinc_tools::names::{Paths, PathsInput};

const SEP: &str = "#---------------------------------------------------------------#";

fn paths_in(tmp: &tempfile::TempDir) -> Paths {
    Paths::for_cli(&PathsInput {
        confbase: Some(tmp.path().to_path_buf()),
        ..Default::default()
    })
}

#[test]
fn chunk2_self_name_guard_is_case_insensitive() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = paths_in(&tmp);
    // own name `bob`, chunk-2 `Name = Bob` (same inode on case-folding FS)
    let blob =
        format!("Name = bob\n{SEP}\nName = Bob\nProxy = exec /bin/evil\nAddress = 1.2.3.4\n");
    let err = finalize_join(blob.as_bytes(), &paths, false).unwrap_err();
    assert!(format!("{err:?}").contains("overwrite"), "got {err:?}");
    assert!(!paths.host_file("Bob").exists());
}

#[test]
fn chunk2_drops_dangerous_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let paths = paths_in(&tmp);
    let blob = format!(
        "Name = bob\n{SEP}\n\
         Name = alice\n\
         Address = 1.2.3.4\n\
         Port = 655\n\
         Proxy = exec /bin/sh -c id\n\
         ScriptsInterpreter = /bin/sh\n\
         Ed25519PublicKeyFile = /etc/shadow\n\
         ed25519privatekeyfile = /etc/shadow\n\
         PublicKeyFile = /etc/shadow\n\
         PrivateKeyFile = /etc/shadow\n\
         Ed25519PublicKey = abc\n\
         # comment\n\
         Subnet = 10.0.0.0/24\n"
    );
    let res = finalize_join(blob.as_bytes(), &paths, false).unwrap();
    assert_eq!(res.hosts_written, vec!["alice".to_owned()]);
    let alice = std::fs::read_to_string(paths.host_file("alice")).unwrap();
    for s in ["Proxy", "Interpreter", "KeyFile", "/etc/shadow", "/bin/sh"] {
        assert!(!alice.contains(s), "should drop {s:?}; got:\n{alice}");
    }
    for s in [
        "Address = 1.2.3.4",
        "Port = 655",
        "Ed25519PublicKey = abc",
        "# comment",
        "Subnet = 10.0.0.0/24",
    ] {
        assert!(alice.contains(s), "should keep {s:?}; got:\n{alice}");
    }
}
