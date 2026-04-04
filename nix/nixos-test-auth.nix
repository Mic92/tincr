# tinc-auth integration test: nginx auth_request → tinc-auth →
# tincd control socket → 204 + Tinc-Node header → upstream sees it.
#
# Unlike nixos-test.nix this isn't proving wire compat with the C —
# tinc-auth has no C equivalent. This proves the deployment surface:
# socket activation works, the unit can read tincd's pidfile, the
# header reaches the proxied app, and an off-mesh request 401s.
#
# Two nodes:
#   alpha = the client (curl from here)
#   beta  = tincd + tinc-auth + nginx + a trivial origin
#
# beta also has a non-tinc loopback path to nginx so we can prove
# the deny case in the same VM (a request from 127.0.0.1, which
# isn't in any tinc subnet, must 401).
{
  testers,
  tincd,
  writers,
}:
let
  keys = import ./snakeoil-keys.nix;

  # Same shape as nixos-test.nix's mkNode but stripped to what both
  # nodes need. The auth machinery is beta-only and bolted on below.
  mkNode =
    self: peer:
    { ... }:
    {
      services.tinc.networks.mesh = {
        name = self;
        package = tincd;
        ed25519PrivateKeyFile = builtins.toFile "ed25519.priv" keys.${self}.ed25519Private;
        hostSettings = {
          alpha = {
            subnets = [ { address = "10.20.0.1"; } ];
            settings.Ed25519PublicKey = keys.alpha.ed25519Public;
          };
          beta = {
            subnets = [ { address = "10.20.0.2"; } ];
            settings.Ed25519PublicKey = keys.beta.ed25519Public;
            addresses = [ { address = peer; } ];
          };
        };
        settings = {
          DeviceType = "tun";
          ConnectTo = peer;
        };
        chroot = false;
      };

      networking.interfaces."tinc.mesh" = {
        virtual = true;
        virtualType = "tun";
        ipv4.addresses = [
          {
            address = if self == "alpha" then "10.20.0.1" else "10.20.0.2";
            prefixLength = 24;
          }
        ];
      };
      systemd.services."tinc.mesh" = {
        after = [ "network-addresses-tinc.mesh.service" ];
        requires = [ "network-addresses-tinc.mesh.service" ];
      };

      networking.useDHCP = false;
      networking.firewall.allowedTCPPorts = [ 655 ];
      networking.firewall.allowedUDPPorts = [ 655 ];

      environment.systemPackages = [ tincd ];
    };

  # Origin: echoes X-Tinc-Node back in the body so curl can grep it.
  # BaseHTTPRequestHandler does the framing (CRLF, Content-Length,
  # case-insensitive header lookup); we just read one header and
  # write it back. Single-threaded HTTPServer is fine — the test
  # sends two requests, sequentially.
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

        # Silence the per-request log line. ruff (which
        # writePython3 runs at build time) wants the override
        # not to shadow names with unused params; *_ absorbs them.
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
      { pkgs, lib, ... }:
      {
        imports = [ (mkNode "beta" "alpha") ];

        # ─── tinc-auth: socket-activated, talks to tincd's control
        # socket. Runs as root because the pidfile is mode 0600
        # written before the daemon's `-U tinc-mesh` privdrop
        # (tincd.c:658 setup_network → init_control vs :687
        # drop_privs). Same constraint `tinc -n mesh dump` has —
        # this binary doesn't make the perm model worse, it just
        # inherits it.
        systemd.sockets.tinc-auth = {
          wantedBy = [ "sockets.target" ];
          listenStreams = [ "/run/tinc-auth.sock" ];
          socketConfig = {
            # 0666: the test nginx runs as `nginx`, and we don't
            # want to plumb group membership through a single-
            # purpose VM. A real deployment would 0660 + add
            # nginx to a group; that's NixOS module territory,
            # not what we're testing here.
            SocketMode = "0666";
          };
        };
        systemd.services.tinc-auth = {
          requires = [ "tinc-auth.socket" ];
          after = [ "tinc.mesh.service" ];
          serviceConfig = {
            ExecStart = "${tincd}/bin/tinc-auth -n mesh --pidfile /run/tinc.mesh.pid";
            # Exit-on-idle is unimplemented (single-threaded accept
            # loop with no SIGTERM handler). systemd's default
            # SIGTERM kills it; socket activation restarts on next
            # connect. "Let it crash" — Tailscale's nginx-auth.go:112
            # does the same.
            Restart = "on-failure";
          };
        };

        # ─── nginx: auth_request → tinc-auth, then proxy to origin.
        # Shape lifted from nixpkgs nginx/tailscale-auth.nix with
        # the header names swapped.
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
                # nginx lowercases response header names and
                # underscores: Tinc-Node → $upstream_http_tinc_node.
                auth_request_set $tinc_node $upstream_http_tinc_node;
                auth_request_set $tinc_net  $upstream_http_tinc_net;
                proxy_set_header X-Tinc-Node $tinc_node;
                proxy_set_header X-Tinc-Net  $tinc_net;
              '';
            };
          };
        };
        networking.firewall.allowedTCPPorts = [ 80 ];

        systemd.services.origin = {
          wantedBy = [ "multi-user.target" ];
          serviceConfig.ExecStart = origin;
        };
        # nmap for the test script's direct ncat probes against
        # /run/tinc-auth.sock (curl --unix-socket would work too
        # but mangles the request line; printf | ncat is the
        # honest way to send a hand-built HTTP request).
        environment.systemPackages = [ pkgs.nmap ];
      };
  };

  testScript = ''
    start_all()

    alpha.wait_for_unit("tinc.mesh.service")
    beta.wait_for_unit("tinc.mesh.service")
    beta.wait_for_unit("nginx.service")
    beta.wait_for_unit("origin.service")
    beta.wait_for_file("/run/tinc-auth.sock")

    # Tunnel up first. Same poll-until-ping as nixos-test.nix —
    # the SPTPS handshake is a few round trips after the units
    # report active.
    alpha.wait_until_succeeds("ping -c1 -W2 10.20.0.2", timeout=30)

    # Subnet gossip might lag the data path by a packet or two:
    # ADD_SUBNET arrives over the meta connection, ping just needs
    # the route. Poll the auth path; first 401 (alpha not yet in
    # beta's subnet table) is fine, settle on 204.
    alpha.wait_until_succeeds("curl -fsS http://10.20.0.2/ | grep -x node=alpha", timeout=30)

    # ─── allow path: alpha (10.20.0.1) → beta's nginx
    # The origin echoes X-Tinc-Node. `node=alpha` proves: tinc-auth
    # answered 204, the header was Tinc-Node: alpha, nginx threaded
    # it through auth_request_set → proxy_set_header → origin saw it.
    out = alpha.succeed("curl -fsS http://10.20.0.2/")
    assert out == "node=alpha", f"expected node=alpha, got {out!r}"

    # Tinc-Net too. curl -D dumps response headers; we want the
    # auth subrequest's headers, but those don't reach the client
    # (nginx consumes them). The proxy_set_header X-Tinc-Net path
    # would prove it, but origin only echoes X-Tinc-Node. Direct
    # check: hit the auth socket from beta, where Remote-Addr is a
    # known tinc IP, and read the response headers.
    beta.succeed(
        "printf 'GET / HTTP/1.1\\r\\nRemote-Addr: 10.20.0.1\\r\\n\\r\\n' "
        "| ncat -U /run/tinc-auth.sock | grep -i '^tinc-net: mesh'"
    )

    # ─── deny path: beta → its own nginx via 127.0.0.1
    # 127.0.0.1 isn't in any tinc subnet → tinc-auth 401 → nginx
    # auth_request maps non-2xx to 401 → curl sees 401. -f makes
    # curl exit nonzero on 4xx, hence `fail`.
    beta.fail("curl -fsS http://127.0.0.1/")
    # And confirm it's specifically 401, not a 500 from a broken
    # auth backend.
    code = beta.succeed("curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1/").strip()
    assert code == "401", f"expected 401 for off-mesh request, got {code}"

    # ─── direct deny path: garbage Remote-Addr → 401 not 400
    # nginx's $remote_addr is always a valid IP for INET listeners,
    # but someone poking the socket directly (or nginx accepting on
    # a unix listener, where $remote_addr is "unix:") should be
    # "unknown client" (401) not "you misconfigured nginx" (400).
    beta.succeed(
        "printf 'GET / HTTP/1.1\\r\\nRemote-Addr: not-an-ip\\r\\n\\r\\n' "
        "| ncat -U /run/tinc-auth.sock | head -1 | grep '401'"
    )
  '';
}
