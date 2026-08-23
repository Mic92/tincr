# Passwordless Authelia login from mesh identity, on the container
# backend: tincd runs with DeviceType=dummy and node alpha claims
# 127.0.0.1/32, so a local curl resolves to node alpha through the
# whois socket. Authelia is patched with
# contrib/authelia-first-factor-network*.patch and maps that to the
# file backend user alpha. curl from 127.0.0.2 is off-mesh and must
# stay unauthenticated.
{
  authelia,
  testers,
  tincd,
}:
let
  inherit (import ./test-mesh.nix { inherit tincd; }) mkTincAuth;
  keys = import ./snakeoil-keys.nix;

  autheliaPatched =
    (authelia.override {
      authelia-web = authelia.web.overrideAttrs (old: {
        patches = (old.patches or [ ]) ++ [ ../contrib/authelia-first-factor-network-web.patch ];
        patchFlags = [ "-p2" ]; # the web build roots in web/
      });
    }).overrideAttrs
      (old: {
        patches = (old.patches or [ ]) ++ [ ../contrib/authelia-first-factor-network.patch ];
        doCheck = false;
      });
in
testers.runNixOSTest {
  name = "tinc-auth-authelia";

  containers.solo = {
    services.tinc.networks.mesh = {
      name = "alpha";
      package = tincd;
      ed25519PrivateKeyFile = builtins.toFile "ed25519.priv" keys.alpha.ed25519Private;
      hostSettings.alpha = {
        subnets = [ { address = "127.0.0.1"; } ];
        settings.Ed25519PublicKey = keys.alpha.ed25519Public;
      };
      settings.DeviceType = "dummy";
      chroot = false;
    };

    imports = [ (mkTincAuth [ ]) ];

    networking.hosts."127.0.0.1" = [ "auth.mesh.test" ];

    services.authelia.instances.mesh = {
      enable = true;
      package = autheliaPatched;
      secrets.storageEncryptionKeyFile = "/etc/authelia/storageEncryptionKeyFile";
      secrets.jwtSecretFile = "/etc/authelia/jwtSecretFile";
      settings = {
        server.address = "tcp://127.0.0.1:9091";
        first_factor_network = {
          enable = true;
          socket = "/run/tinc-auth.sock";
        };
        authentication_backend.file.path = "/etc/authelia/users_database.yml";
        access_control.default_policy = "one_factor";
        session.domain = "mesh.test";
        storage.local.path = "/tmp/db.sqlite3";
        notifier.filesystem.filename = "/tmp/notifications.txt";
      };
    };
    # Plain test secrets. Real deployments load these differently.
    environment.etc."authelia/storageEncryptionKeyFile" = {
      mode = "0400";
      text = "you_must_generate_a_random_string_of_more_than_twenty_chars";
    };
    environment.etc."authelia/jwtSecretFile" = {
      mode = "0400";
      text = "a_very_important_secret";
    };
    # The node name is the join key: node alpha logs in as user
    # alpha. The password hash is "password", unused here.
    environment.etc."authelia/users_database.yml" = {
      mode = "0400";
      user = "authelia-mesh";
      text = ''
        users:
          alpha:
            disabled: false
            displayname: Alice
            password: $argon2id$v=19$m=65536,t=3,p=4$2ohUAfh9yetl+utr4tLcCQ$AsXx0VlwjvNnCsa70u4HKZvFkC8Gwajr2pHGKcND/xs
            email: alice@mesh.test
            groups:
              - admin
      '';
    };
    systemd.services.authelia-mesh = {
      requires = [ "tinc-auth.service" ];
      after = [ "tinc-auth.service" ];
    };
  };

  testScript = ''
    import json

    start_all()
    solo.wait_for_unit("tinc.mesh.service")
    solo.wait_for_unit("tinc-auth.service")
    solo.wait_for_unit("authelia-mesh.service")
    solo.wait_for_open_port(9091)

    url = "http://auth.mesh.test:9091"
    hdr = "-H 'Content-Type: application/json' -H 'X-Original-URL: https://auth.mesh.test'"

    # The subnet table needs a moment after tincd starts. Poll
    # until the whois resolves 127.0.0.1 and the login succeeds,
    # capturing the session cookie by hand: it is marked Secure and
    # a cookie jar would withhold it over plain http.
    solo.wait_until_succeeds(
        f"curl -fsS -D /tmp/headers {hdr} -d '{{}}' {url}/api/firstfactor/network",
        timeout=30,
    )
    cookie = solo.succeed(
        "grep -oPi '(?<=set-cookie: )authelia_session=[^;]+' /tmp/headers"
    ).strip()

    state = json.loads(solo.succeed(f"curl -fsS -H 'Cookie: {cookie}' {url}/api/state"))
    assert state["data"]["authentication_level"] == 1, state

    info = json.loads(solo.succeed(f"curl -fsS -H 'Cookie: {cookie}' {url}/api/user/info"))
    assert info["data"]["display_name"] == "Alice", info

    # Off-mesh: 127.0.0.2 is outside the claimed subnet, tinc-auth
    # answers 401 and the login must fail.
    solo.fail(
        f"curl -fsS --interface 127.0.0.2 {hdr} -d '{{}}' {url}/api/firstfactor/network"
    )
  '';
}
