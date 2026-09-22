# Cross-implementation SPTPS capability-negotiation test (cap.rs
# extension). Four nodes: alpha/beta run tincr with the post-quantum
# pair (SPTPSKex = x25519-mlkem768, SPTPSCipher = aes-256-gcm), pre
# runs nixpkgs tinc_pre (1.1pre18: fixed x25519 +
# chacha20-poly1305, no SPTPSKex keyword at all) and stable runs
# tinc 1.0.37 (pure legacy RSA, no SPTPS anywhere in its source).
#
# Before the extension, a tincr configured for the hybrid pair sent a
# 1249-byte KEX body to pre, which expects 65: `BadKex` on every
# attempt, no tunnel, forever. The fix rides capability tokens on the
# ID line and REQ_KEY; a peer that doesn't echo/parse one pins both
# directions to the C-compatible defaults (x25519 +
# chacha20-poly1305), which is exactly what tinc_pre speaks.
#
# Topology: pre is the hub — alpha and beta ConnectTo it, and stable
# (1.0.37 has no ConnectTo) auto-dials every addressed node, which is
# only pre: alpha/beta host files carry no Address. tincr cannot
# meta-connect to tinc 1.0 (no RSA on our side) and tinc 1.0 cannot
# authenticate to tincr uninvited, so alpha/beta <-> stable has no
# data path at all; it is a documented limitation, asserted via the
# warn log instead of a ping.
#
# Host-file layout per receiver:
#  - tincr nodes see no PEM blocks (their parser is strict) and no
#    Ed25519 key for stable — send_req_key then warns "No Ed25519 key
#    known for stable" instead of firing hybrid REQ_KEY lines that
#    tinc 1.0 would mis-parse and tear the pre<->stable conn down on.
#  - pre sees stable's RSA public key (legacy AUTH) and the Ed25519
#    keys of alpha/beta (SPTPS). The absence of an Ed25519 key is
#    what makes pre choose the legacy dialect toward stable.
#  - stable sees pre's RSA public key (SPKI: 1.0.37's net_setup.c:146
#    reads PEM_read_PUBKEY first) and silently ignores the Ed25519
#    keys it cannot use.
#
# Self-subnets come from tinc.conf `Subnet` on the C nodes (the
# module writes settings verbatim); the tincr nodes announce theirs
# through the module-managed host files.
{
  testers,
  tincd, # our Rust build (alpha, beta)
  tincrModule,
  tinc_pre,
  tinc,
}:
let
  keys = import ./snakeoil-keys.nix;

  # Generated offline with `openssl genrsa`, PKCS#1 private PEMs so
  # both tinc 1.0.37's PEM_read_PrivateKey (net_setup.c:298) and
  # tinc-pre's reader accept them; public PEMs are SPKI, which
  # tinc 1.0.37 reads first and tinc-pre falls back to.
  rsa = {
    stable = {
      priv = ''
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEAp9vIfoBtJEAvwh0qa3Xb1Z0U4/y/8RadDs33QU7B7Dye10gn
        ql417RBT1PkhPPb7URkBoGn5Gq+OvykRh1WNPngq4pKQoakqj6AnG1wa5WaV3YEk
        twVvPOb7eEK8Shsr7+rB7vFifg684/yXrtoYSPLMSXTvNYTfIWJVBvHIKaq7g1p5
        7c5rpMFqLs9BNa/sVdWxyCGb0dAb4rLfGEPEtHLvypmUqBPJ9xoW4lBSa9CHafaL
        UEnC99EL2j6934yzSPgwX9Qav5km9+1+p/Da0jP0AGTO+NNQ2OAVyyj5FLw/irVw
        2WY4y4fVwUpmAfup0IRJkZXiDalslnfAZ2BaUwIDAQABAoIBAAP5oHXedLc3Dep6
        5lZFJD+ayLPdeG4tKur+1awmQVFm3hwbCVVvhbdne5S/kZnv/2OcQ/2YhN2s6qR8
        RH3/+KhSEDHtZp9tciSUllh/heOI2mO0ezoaVtgKYEooymy22AOGe7E85ig2ESMV
        CEKLx6dymIPk0QVjcCVKPtk7QJI7/v7FdkLziY2ckxlOte1KRmQ0zH2c4x7r4fRJ
        ucRq9Oroctyp4ONS3e6Agze4sQdXpYAdKQXcLKKsPFdgXBw9/CriFt2nVTXB90K9
        dCjfUBaYJu/H2EPsMI0+U2KER3nBiF6D1xGzGAcqBIFxQiqmHF4hPPKQz1IAZfah
        m6ss4gECgYEA3CsW912EH7ValY7p8c1huLmAQTFUhLGCFttDmletyhXnzNPdEm32
        X8oIKDhe8+EWLYsyuBQuYYmZRRS73TPKPvz13GB+dUmNlU+6u03TYskA/eMt/z0+
        huY8k0JPEGKh/eybKF4yYu/CCQ4oGn82EYDYqLjNF8xXTO91zCLMwCMCgYEAwy1N
        PI6shc64hx5HFgFYJqpSr4gO8t59YV89ceysMRMaBRbxsjGT+Hc5PHscyr4UmpHK
        PE25UckgL74jSsxnVc2dwD74zYdV9SthIVGf8xpQZkpH9WEdSbYfco+BKv/KuwME
        P6ZkYArwvZ0R3VcuAS3Bjb7DM1vCS1vcoFhHiBECgYEAlwRzb19U1k8WAEoUDAjd
        g9CxuYX1vELpwXXKzB5iFaCq6+NS22ZTvWad68Cm2M/G35yAQKWPHtY8LJdJOTRi
        AIyQtAX4F8lI9WbH5dw/J55KMNvYXCANOIjKehPcmZeeF8doserS0uw0AvQT7ADf
        /GeNtUV1YGKIazxBZ7FjElMCgYAuC3DuOWaABr3Hup/glB6cuI/bM0j7iPuhThur
        1b7lsPDxhHEurb2P32iUWSL4vZEUyhIg2eE/Zyh9uuiOi9xRBLoTkYeWzTe9KCe4
        +Y23h1yyVRHW1LtZGWsf1rUNVN0Z82M8NN/3PH2A7h45zohe5NGFxBw+8IXMy3Yo
        KctuUQKBgQCDgjjiji+e6GLesogVNl8Gg8F3YX4sGEYePULRFJ/z97flnaZKTxmb
        DTNIOxriTtsg1WTeyUhti2uIIP2pAel8dgrC59RUnCoFOjFX8a0+qMy9Zoj58Q/y
        vcyWjp7xqroqFf6ifolcyL9NEr3fbNT86CMXzfxaWh11PEsan932JA==
        -----END RSA PRIVATE KEY-----
      '';
      pub = ''
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp9vIfoBtJEAvwh0qa3Xb
        1Z0U4/y/8RadDs33QU7B7Dye10gnql417RBT1PkhPPb7URkBoGn5Gq+OvykRh1WN
        Pngq4pKQoakqj6AnG1wa5WaV3YEktwVvPOb7eEK8Shsr7+rB7vFifg684/yXrtoY
        SPLMSXTvNYTfIWJVBvHIKaq7g1p57c5rpMFqLs9BNa/sVdWxyCGb0dAb4rLfGEPE
        tHLvypmUqBPJ9xoW4lBSa9CHafaLUEnC99EL2j6934yzSPgwX9Qav5km9+1+p/Da
        0jP0AGTO+NNQ2OAVyyj5FLw/irVw2WY4y4fVwUpmAfup0IRJkZXiDalslnfAZ2Ba
        UwIDAQAB
        -----END PUBLIC KEY-----
      '';
    };
    pre = {
      priv = ''
        -----BEGIN RSA PRIVATE KEY-----
        MIIEogIBAAKCAQEAq2ylQgJmQqlQPg/RIFixPZ2zK4mGtA9tmgLMpsNmNkteE8kE
        scruBKVoqfgT4GorojR/4Bxn6ATTQD9p8xTZicNsVIxtP3/ZRX2XlZtNRuJjWSG+
        iQSQgW76po0d6dhcSK6+9TQVezlgWgjb5OHiwH1kAkxfSNRUaay4H1Z4AQdKLOZP
        R7JyrTjR1FtJP/N7rjxSuB20NAeynAdaKevU6qccq/DYzinjGJLgLGCqnkNYH7y+
        d1Xixnw3A7zPWQEqEP2ZCHT2l0z/x8ohNZZxt3/d4X6yh5xtjVSf67+Ie9yDmERQ
        EF1kcg14JMkPVdVrYaZzCFFb0gt9tXq6/P8xxQIDAQABAoIBADaYkR9vVTNI6mIB
        tpiHNtfJaH1mvQyO11jUKGq6U8zZ/xntDT40w86eAbIUbPwtxDzSXKG7Wkp2cvOE
        3tEI5GmwYEmjOc4eAUxU/hirUBbR1lNWYHESD5XxiwnNaugFvQp3ASFmF6tZsDqs
        lKAWYxnsNZRXz4cJ/OJ1HGT6rJiivKgUkIrbuHu8KbzOWQjIqFOBbCLQa/WyAiDd
        YdIWslQLrj/dzYI2B9dkQS9/C0kk3DE7aMNJa5Huh9geqwf9s29lZmjbdHnGDoY5
        fA38yVCWApGnIKOVbKGsZAg6529AkjeBfj9GNeNzHUCSxTW180KDzoNXzuvQzoaK
        k89QMccCgYEA2siGksvaElJJVf2CGVa0I5vqyyE6qBG0Dk+4M5ZRSN2ZcuwCMGer
        8cBQL08074nVMd3CiWkYp/HAqLrkEfnE1m4J9pbfGhww4fb82RutmZ3R5bWg9QM4
        vla2wQYCwE+tWe7/5QnuTSpmpBapexk0rRTb2Eg4MyfH6HBKAGNI648CgYEAyJXB
        jDQqaZKnP+zmUypC9GeWYh+MXiFCk8ju4YHFL+ntLP8NmpJLtHTXwHyFMBQzmtEE
        GVcwVcEdFuCbU8sfEdDGieqyfVt6Z9sLAfboSEoPj0YAF0BBwcgBSays8iQs1sLy
        jXfLDr9mgJu77dauA67kSXTeCE8EI3QXGNVU82sCgYBeCXzWUeqMn3PIEyu9Smgp
        OhYkc0bsAJf84sUQ31ZW1HDlVY3nUlg0k+2jOA9PulW5llDMkTC41w9xNsta8plp
        dWiw5c5FQcK9DVVG2D+43H3glz30sgrMvSbWNoguMtEW68RvpOIZptTxSJBWSdI7
        ZtDL2NbXHg0t2j3khshL/wKBgCe4kDVldyik4/3iudGqQswHX15bBP728yo01ilN
        +3B7kH4im90KL3ey067Iec+FkJqN3ZPvEiFJNqt7GwdC6AotH8Pb+DCe1uSOGeXv
        sRvvnpkusYHpNZxcMPUX/r+MrlxxCns9R7bJ7FB3hoWYx6jvD0IEpJtcmmMy8Af4
        5vO1AoGAKz0SE9mvXfJQmAu+2+IxKzoNXjk6dPKr/kR0Fvfd9WLZJ4Jk1dkxecPq
        7hIMEUMMyX2HfO0zcHiEvhtM1H4xARs+Q/pZlbo/jjJHs9oyL8Jjhm5JoHXo2Q8n
        wU3Y9gDblep/JcznoSM31iisarOa2I3t1TxI6Zt8i0Tn3+gj5vY=
        -----END RSA PRIVATE KEY-----
      '';
      pub = ''
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq2ylQgJmQqlQPg/RIFix
        PZ2zK4mGtA9tmgLMpsNmNkteE8kEscruBKVoqfgT4GorojR/4Bxn6ATTQD9p8xTZ
        icNsVIxtP3/ZRX2XlZtNRuJjWSG+iQSQgW76po0d6dhcSK6+9TQVezlgWgjb5OHi
        wH1kAkxfSNRUaay4H1Z4AQdKLOZPR7JyrTjR1FtJP/N7rjxSuB20NAeynAdaKevU
        6qccq/DYzinjGJLgLGCqnkNYH7y+d1Xixnw3A7zPWQEqEP2ZCHT2l0z/x8ohNZZx
        t3/d4X6yh5xtjVSf67+Ie9yDmERQEF1kcg14JMkPVdVrYaZzCFFb0gt9tXq6/P8x
        xQIDAQAB
        -----END PUBLIC KEY-----
      '';
    };
  };

  # The pair under test: tincr nodes advertise post-quantum.
  pqConfig = ''
    SPTPSKex = x25519-mlkem768
    SPTPSCipher = aes-256-gcm
    PingInterval = 3
  '';

  # Host files as the tincr nodes see them: no PEM blocks anywhere
  # (strict parser), no Ed25519 key for stable (1.0 cannot answer a
  # REQ_KEY exchange; without a key send_req_key warns and stalls,
  # which is the documented gap). `Address` only on pre, so the
  # ConnectTo-dial set is exactly {pre}. Autoconnect still dials
  # alpha/beta/stable from addresses learned via ADD_EDGE gossip —
  # those conns are expected to fail AUTH at stable (no RSA on our
  # side) and stay idle between alpha/beta; harmless churn.
  hostsTincr = {
    alpha = ''
      Subnet = 10.22.0.1/32
      Ed25519PublicKey = ${keys.alpha.ed25519Public}
    '';
    beta = ''
      Subnet = 10.22.0.2/32
      Ed25519PublicKey = ${keys.beta.ed25519Public}
    '';
    pre = ''
      Address = pre
      Subnet = 10.22.0.3/32
      Ed25519PublicKey = ${keys.pre.ed25519Public}
    '';
    stable = ''
      Subnet = 10.22.0.4/32
    '';
  };

  # pre's view: SPTPS toward the tincr nodes (their Ed25519 keys),
  # legacy toward stable (RSA pub present, Ed25519 absent).
  hostsPre =
    hostsTincr
    // {
      stable = ''
        Address = stable
        Subnet = 10.22.0.4/32
        ${rsa.stable.pub}
      '';
    };

  # stable's view: RSA for its only AUTH peer (pre); the Ed25519
  # lines are unknown keys that 1.0.37 stores and never reads.
  hostsStable = {
    alpha = ''
      Subnet = 10.22.0.1/32
      Ed25519PublicKey = ${keys.alpha.ed25519Public}
    '';
    beta = ''
      Subnet = 10.22.0.2/32
      Ed25519PublicKey = ${keys.beta.ed25519Public}
    '';
    pre = ''
      Address = pre
      Subnet = 10.22.0.3/32
      Ed25519PublicKey = ${keys.pre.ed25519Public}
      ${rsa.pre.pub}
    '';
    stable = ''
      Subnet = 10.22.0.4/32
    '';
  };

  # tincr side (services.tincr module). ConnectTo = pre is the only
  # dial-out: the module writes `ConnectTo` into tinc.conf and the
  # service is wantedBy multi-user, so no manual start.
  mkTincrNode =
    self:
    { pkgs, ... }:
    {
      imports = [ tincrModule ];
      services.tincr.package = tincd;
      services.tincr.networks.mesh = {
        nodeName = self;
        addresses = [ "10.22.0.${if self == "alpha" then "1" else "2"}/24" ];
        ed25519PrivateKeyFile = "/etc/tinc/mesh/ed25519_key.priv";
        hosts = hostsTincr;
        connectTo = [ "pre" ];
        openFirewall = false;
        extraConfig = pqConfig;
      };
      environment.etc."tinc/mesh/ed25519_key.priv" = {
        text = keys.${self}.ed25519Private;
        mode = "0400";
        user = "tincr";
        group = "tincr";
      };
      networking.useDHCP = false;
      networking.firewall.enable = false;
      environment.systemPackages = [ tincd ];
    };

  # C side (upstream services.tinc module; `package` selects the
  # dialect). Store-path key files are world-readable: both daemons
  # log an insecure-permissions warning but load them under -U
  # tinc-mesh. Self-subnets are announced from tinc.conf `Subnet`
  # (tinc 1.0.37: net_setup.c:570; tinc-pre the same).
  mkCNode =
    self:
    {
      pkg,
      hosts,
      meshIp,
      rsaPriv,
      ed25519File ? null,
    }:
    {
      services.tinc.networks.mesh = {
        name = self;
        package = pkg;
        chroot = false;
        ed25519PrivateKeyFile = ed25519File;
        rsaPrivateKeyFile = rsaPriv;
        inherit hosts;
        settings = {
          DeviceType = "tun";
          Subnet = "${meshIp}/32";
        };
      };
      # Pre-create the TUN iface with the mesh address; the ordering
      # avoids the tincd-creates-iface-before-address-is-set race
      # (same pattern as nixos-test.nix).
      networking.interfaces."tinc.mesh" = {
        virtual = true;
        virtualType = "tun";
        ipv4.addresses = [
          {
            address = meshIp;
            prefixLength = 24;
          }
        ];
      };
      systemd.services."tinc.mesh" = {
        after = [ "network-addresses-tinc.mesh.service" ];
        requires = [ "network-addresses-tinc.mesh.service" ];
      };
      networking.useDHCP = false;
      networking.firewall.enable = false;
      environment.systemPackages = [ pkg ];
    };
in
testers.runNixOSTest {
  name = "tincr-sptps-fallback";

  nodes = {
    alpha = { imports = [ (mkTincrNode "alpha") ]; };
    beta = { imports = [ (mkTincrNode "beta") ]; };
    pre = {
      imports = [
        (mkCNode "pre" {
          pkg = tinc_pre;
          hosts = hostsPre;
          meshIp = "10.22.0.3";
          rsaPriv = builtins.toFile "rsa_pre.priv" rsa.pre.priv;
          ed25519File = builtins.toFile "ed25519_pre.priv" keys.pre.ed25519Private;
        })
      ];
    };
    stable = {
      imports = [
        (mkCNode "stable" {
          pkg = tinc;
          hosts = hostsStable;
          meshIp = "10.22.0.4";
          rsaPriv = builtins.toFile "rsa_stable.priv" rsa.stable.priv;
        })
      ];
    };
  };

  testScript = ''
    start_all()

    alpha.wait_for_unit("tincr-mesh.service")
    beta.wait_for_unit("tincr-mesh.service")
    pre.wait_for_unit("tinc.mesh.service")
    stable.wait_for_unit("tinc.mesh.service")

    # ---------- gossip convergence ----------
    # tincr's CLI defaults to /var/run/tinc.mesh.pid; the service
    # writes /run/tincr/mesh.pid, so dump needs the explicit
    # --pidfile. tinc-pre finds its own /run/tinc.mesh.pid by probe.
    # tinc 1.0.37 ships no CLI binary at all: its convergence is
    # proven by the alpha ping below (a forwarded packet requires
    # the routing-table entry gossip installed).
    for m in (alpha, beta):
        for peer in ("alpha", "beta", "pre", "stable"):
            if m.name != peer:
                m.wait_until_succeeds(
                    "tinc -n mesh --pidfile /run/tincr/mesh.pid dump nodes "
                    "| grep -qw %s" % peer,
                    timeout=90,
                )
    for peer in ("alpha", "beta", "stable"):
        pre.wait_until_succeeds(
            "tinc -n mesh dump nodes | grep -qw %s" % peer, timeout=90
        )

    # ---------- C <-> C baseline (pre <-> stable, legacy RSA) ----------
    # Sanity anchor: if this fails the fixture (keys/subnets) is
    # broken, not the code under test.
    pre.wait_until_succeeds("ping -c1 -W2 10.22.0.4", timeout=120)
    stable.wait_until_succeeds("ping -c1 -W2 10.22.0.3", timeout=60)

    # ---------- tincr <-> tincr (hybrid <-> hybrid, relayed) ----------
    # No direct alpha<->beta conn exists: the REQ_KEY/ANS_KEY exchange
    # (with the cap stamp riding the REQ_KEY line) is relayed by pre.
    alpha.wait_until_succeeds("ping -c1 -W2 10.22.0.2", timeout=120)
    beta.wait_until_succeeds("ping -c1 -W2 10.22.0.1", timeout=60)

    # ---------- tincr <-> pre (the bug: hybrid config, C peer) ----------
    # Both directions, since each node runs its own SPTPS session per
    # direction: alpha-initiated (ID-line echo absent -> demote) and
    # pre-initiated REQ_KEY toward alpha (no stamp -> demote).
    alpha.wait_until_succeeds("ping -c1 -W2 10.22.0.3", timeout=120)
    alpha.succeed("ping -c5 -W2 10.22.0.3")
    pre.wait_until_succeeds("ping -c1 -W2 10.22.0.1", timeout=60)
    beta.wait_until_succeeds("ping -c1 -W2 10.22.0.3", timeout=120)
    pre.wait_until_succeeds("ping -c1 -W2 10.22.0.2", timeout=60)

    # ---------- tincr <-> tinc 1.0: documented gap ----------
    # stable has no Ed25519 key for the tincr nodes and no RSA for
    # them either, so no tunnel can exist. alpha's ping must stall
    # cleanly on the missing key (warn log), not fire hybrid REQ_KEY
    # lines that stable would mis-parse and tear down its pre
    # connection on. (docs/COMPAT.md.)
    alpha.execute("ping -c3 -W2 10.22.0.4")
    alpha.wait_until_succeeds(
        "journalctl -u tincr-mesh.service --no-pager "
        "| grep -q 'No Ed25519 key known for stable'",
        timeout=60,
    )
    # The gap must not poison the working links: alpha's stalled
    # REQ_KEY storm toward stable must leave the pre-relayed tunnels
    # intact. (stable cannot originate toward alpha: its reply path
    # hits the same missing-key stall, and 1.0.37 has no CLI to
    # inspect its table.)
    alpha.succeed("ping -c3 -W2 10.22.0.3")
    pre.succeed("ping -c3 -W2 10.22.0.4")

    # The regression guard: a tincr peer pair must never surface
    # BadKex, and the tincr<->pre links must have demoted explicitly.
    for m in (alpha, beta):
        out = m.succeed("journalctl -u tincr-mesh.service --no-pager")
        assert "BadKex" not in out, "%s logged BadKex:\n%s" % (m.name, out)
        assert "falling back to C-compatible defaults" in out, (
            "%s never fell back toward pre:\n%s" % (m.name, out)
        )

    # pre negotiated the fixed defaults it knows and saw no trouble.
    out = pre.succeed("journalctl -u tinc.mesh.service --no-pager")
    assert "Got bad" not in out, out
  '';
}
