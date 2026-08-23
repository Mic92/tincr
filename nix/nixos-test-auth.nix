# tinc-auth integration test, both modes:
#   auth_request: nginx → tinc-auth → 204 + Tinc-Node → upstream
#   OIDC IdP:     gitea on beta logs alpha in via the mesh IdP
#
# alpha = the client (curl from here), beta = tincd + tinc-auth +
# nginx + origin + gitea. Off-mesh requests (127.0.0.1) must fail.
{
  lib,
  testers,
  tincd,
  writers,
}:
let
  inherit (import ./test-mesh.nix { inherit tincd; }) mkNode mkTincAuth;
  idpUrl = "http://10.20.0.2:8443";
  giteaUrl = "http://10.20.0.2:3000";

  clients = builtins.toFile "clients.json" (
    builtins.toJSON [
      {
        id = "gitea";
        secret = "snakeoil-oidc-secret";
        redirect_uris = [ "${giteaUrl}/user/oauth2/tinc/callback" ];
      }
    ]
  );

  # Echoes X-Tinc-Node back in the body so curl can grep it.
  origin = writers.writePython3 "origin" { } ''
    from http.server import HTTPServer, BaseHTTPRequestHandler


    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            node = self.headers.get("X-Tinc-Node", "")
            body = f"node={node}".encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass


    HTTPServer(("127.0.0.1", 8081), H).serve_forever()
  '';
in
testers.runNixOSTest {
  name = "tinc-auth-nixos";

  nodes = {
    alpha = mkNode "alpha" "beta";

    beta =
      { pkgs, config, ... }:
      {
        imports = [
          (mkNode "beta" "alpha")
          (mkTincAuth [
            "--idp-listen 10.20.0.2:8443"
            "--issuer ${idpUrl}"
            "--clients ${clients}"
            "--email-domain mesh.test"
          ])
        ];

        # nginx auth_request → tinc-auth → origin. Same shape as
        # nixpkgs' tailscale-auth.nix with the headers renamed.
        services.nginx = {
          enable = true;
          virtualHosts.default = {
            listen = [
              {
                addr = "0.0.0.0";
                port = 80;
              }
            ];
            locations."/auth" = {
              extraConfig = ''
                internal;
                proxy_pass http://unix:/run/tinc-auth.sock;
                proxy_pass_request_body off;
                proxy_set_header Content-Length "";
                proxy_set_header Remote-Addr $remote_addr;
              '';
            };
            locations."/" = {
              proxyPass = "http://127.0.0.1:8081";
              extraConfig = ''
                auth_request /auth;
                auth_request_set $tinc_node $upstream_http_tinc_node;
                auth_request_set $tinc_net  $upstream_http_tinc_net;
                proxy_set_header X-Tinc-Node $tinc_node;
                proxy_set_header X-Tinc-Net  $tinc_net;
              '';
            };
          };
        };

        services.gitea = {
          enable = true;
          settings = {
            server = {
              HTTP_ADDR = "0.0.0.0";
              HTTP_PORT = 3000;
              ROOT_URL = "${giteaUrl}/";
            };
            # nickname = the preferred_username claim, i.e. the
            # node name.
            oauth2_client = {
              ENABLE_AUTO_REGISTRATION = true;
              USERNAME = "nickname";
              ACCOUNT_LINKING = "auto";
            };
          };
        };
        systemd.services.gitea-oauth-setup = {
          wantedBy = [ "multi-user.target" ];
          requires = [ "gitea.service" ];
          after = [ "gitea.service" ];
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
            User = "gitea";
          };
          script = ''
            ${lib.getExe config.services.gitea.package} \
              --config /var/lib/gitea/custom/conf/app.ini \
              admin auth add-oauth \
              --name tinc \
              --provider openidConnect \
              --key gitea \
              --secret snakeoil-oidc-secret \
              --auto-discover-url ${idpUrl}/.well-known/openid-configuration
          '';
        };

        networking.firewall.allowedTCPPorts = [
          80
          3000
          8443
        ];

        systemd.services.origin = {
          wantedBy = [ "multi-user.target" ];
          serviceConfig.ExecStart = origin;
        };
        # ncat: hand-built HTTP against the unix socket.
        environment.systemPackages = [ pkgs.nmap ];
      };
  };

  testScript = ''
    import json

    start_all()

    alpha.wait_for_unit("tinc.mesh.service")
    beta.wait_for_unit("tinc.mesh.service")
    beta.wait_for_unit("nginx.service")
    beta.wait_for_unit("origin.service")
    beta.wait_for_unit("tinc-auth.service")
    beta.wait_for_file("/run/tinc-auth.sock")

    alpha.wait_until_succeeds("ping -c1 -W2 10.20.0.2", timeout=30)

    # Subnet gossip can lag the data path. Poll until alpha is in
    # beta's table.
    alpha.wait_until_succeeds("curl -fsS http://10.20.0.2/ | grep -x node=alpha", timeout=30)

    # allow path: origin sees the header nginx threaded through
    out = alpha.succeed("curl -fsS http://10.20.0.2/")
    assert out == "node=alpha", f"expected node=alpha, got {out!r}"

    beta.succeed(
        "printf 'GET / HTTP/1.1\\r\\nRemote-Addr: 10.20.0.1\\r\\n\\r\\n' "
        "| ncat -U /run/tinc-auth.sock | grep -i '^tinc-net: mesh'"
    )

    # deny path: 127.0.0.1 is not in any tinc subnet
    beta.fail("curl -fsS http://127.0.0.1/")
    code = beta.succeed("curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1/").strip()
    assert code == "401", f"expected 401 for off-mesh request, got {code}"

    # garbage Remote-Addr is "unknown client" (401), not 400
    beta.succeed(
        "printf 'GET / HTTP/1.1\\r\\nRemote-Addr: not-an-ip\\r\\n\\r\\n' "
        "| ncat -U /run/tinc-auth.sock | head -1 | grep '401'"
    )

    # ─── OIDC: gitea logs alpha in via the IdP ───
    beta.wait_for_unit("gitea.service")
    beta.wait_for_unit("gitea-oauth-setup.service")
    beta.wait_for_open_port(8443, addr="10.20.0.2")

    disco = json.loads(alpha.succeed(
        "curl -fsS ${idpUrl}/.well-known/openid-configuration"
    ))
    assert disco["issuer"] == "${idpUrl}", disco

    # Full code flow through gitea: /user/oauth2/tinc redirects to
    # the IdP, which redirects straight back with a code, and gitea
    # exchanges it and auto-registers the node as a user.
    alpha.succeed(
        "curl -fsSL -c /tmp/jar -b /tmp/jar ${giteaUrl}/user/oauth2/tinc -o /tmp/login.html"
    )
    # /user/settings is only reachable with a session
    alpha.succeed("curl -fsS -b /tmp/jar ${giteaUrl}/user/settings -o /dev/null")
    who = alpha.succeed("curl -fsS -b /tmp/jar ${giteaUrl}/user/settings | grep -o 'value=\"alpha\"' | head -1")
    assert 'alpha' in who, f"expected user alpha in settings, got {who!r}"

    # beta reaches its own gitea from 10.20.0.2, so the same flow
    # identifies it as node beta: accounts follow node identity.
    beta.succeed("curl -fsSL -c /tmp/jar2 -b /tmp/jar2 ${giteaUrl}/user/oauth2/tinc -o /dev/null")
    who = beta.succeed("curl -fsS -b /tmp/jar2 ${giteaUrl}/user/settings | grep -o 'value=\"beta\"' | head -1")
    assert 'beta' in who, f"expected user beta in settings, got {who!r}"
  '';
}
