# Container-backend probe: nspawn containers cannot provide
# /dev/net/tun inside the build sandbox, so tincd runs with
# DeviceType=dummy and the node claims 127.0.0.1/32. That is enough
# for everything tinc-auth needs (control socket + subnet table),
# so the whole OIDC surface is testable without a VM.
{
  testers,
  tincd,
}:
let
  keys = import ./snakeoil-keys.nix;

  clients = builtins.toFile "clients.json" (
    builtins.toJSON [
      {
        id = "app";
        secret = "snakeoil";
        redirect_uris = [ "http://app.example/cb" ];
      }
    ]
  );
in
testers.runNixOSTest {
  name = "tinc-auth-container";

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

    systemd.services.tinc-auth = {
      wantedBy = [ "multi-user.target" ];
      requires = [ "tinc.mesh.service" ];
      after = [ "tinc.mesh.service" ];
      serviceConfig = {
        ExecStart = ''
          ${tincd}/bin/tinc-auth -n mesh --pidfile /run/tinc.mesh.pid \
            --idp-listen 127.0.0.1:8443 \
            --issuer http://127.0.0.1:8443 \
            --clients ${clients}
        '';
        Restart = "on-failure";
        RestartSec = "1s";
      };
    };
  };

  testScript = ''
    import json

    start_all()
    solo.wait_for_unit("tinc.mesh.service")
    solo.wait_for_unit("tinc-auth.service")
    solo.wait_for_open_port(8443)

    disco = json.loads(solo.succeed(
        "curl -fsS http://127.0.0.1:8443/.well-known/openid-configuration"
    ))
    assert disco["issuer"] == "http://127.0.0.1:8443", disco

    loc = solo.succeed(
        "curl -fsS -o /dev/null -w '%{redirect_url}' "
        "'http://127.0.0.1:8443/authorize?response_type=code&client_id=app"
        "&redirect_uri=http%3A%2F%2Fapp.example%2Fcb&state=s'"
    )
    assert "code=" in loc and "state=s" in loc, loc
    code = loc.split("code=")[1].split("&")[0]

    tok = json.loads(solo.succeed(
        "curl -fsS -X POST http://127.0.0.1:8443/token "
        f"-d grant_type=authorization_code -d code={code} "
        "-d redirect_uri=http%3A%2F%2Fapp.example%2Fcb "
        "-d client_id=app -d client_secret=snakeoil"
    ))
    assert tok["token_type"] == "Bearer", tok

    ui = json.loads(solo.succeed(
        "curl -fsS -H 'Authorization: Bearer " + tok["access_token"] + "' "
        "http://127.0.0.1:8443/userinfo"
    ))
    assert ui["sub"] == "alpha", ui
  '';
}
