# End-to-end test for services.tincr: declarative config, hardened
# socket-activated unit, and the DNS stub wired through networkd +
# resolved. Two nodes mesh on 10.21.0.0/16. resolved routes `*.mesh`
# to DNSAddress 10.21.0.53 on the TUN, where tincd answers.
{
  testers,
  tincd,
  tincrModule,
}:
let
  keys = import ./snakeoil-keys.nix;

  hosts = {
    alpha = ''
      Subnet = 10.21.0.1/32
      Ed25519PublicKey = ${keys.alpha.ed25519Public}
    '';
    beta = ''
      Address = beta
      Subnet = 10.21.0.2/32
      Ed25519PublicKey = ${keys.beta.ed25519Public}
      Alias = web
    '';
  };

  mkNode =
    self: addr: extraNet:
    { pkgs, ... }:
    {
      imports = [ tincrModule ];

      services.tincr.package = tincd;
      services.tincr.networks.mesh = {
        nodeName = self;
        addresses = [ "${addr}/16" ];
        ed25519PrivateKeyFile = "/etc/tinc/mesh/ed25519_key.priv";
        hosts = {
          inherit (hosts) alpha beta;
        };
        dns = {
          enable = true;
          suffix = "mesh";
          address4 = "10.21.0.53";
        };
        openFirewall = false;
      }
      // extraNet;

      # The module does not own the key bytes. tincd runs as `tincr`.
      environment.etc."tinc/mesh/ed25519_key.priv" = {
        text = keys.${self}.ed25519Private;
        mode = "0400";
        user = "tincr";
        group = "tincr";
      };

      networking.useDHCP = false;
      networking.firewall.enable = false;

      environment.systemPackages = [ pkgs.dig ];
    };
in
testers.runNixOSTest {
  name = "tincr-module";

  nodes = {
    alpha = mkNode "alpha" "10.21.0.1" { connectTo = [ "beta" ]; };
    beta = mkNode "beta" "10.21.0.2" { };
  };

  testScript = ''
    start_all()

    dig = "dig +short +tries=1 +time=3 @127.0.0.53"

    with subtest("module brings up the hardened socket-activated unit"):
        # Beta stays inactive until alpha's first dial triggers socket
        # activation. wait_for_unit would fail fast on inactive+no-job.
        for m in (alpha, beta):
            m.wait_for_unit("tincr-mesh.socket")
        alpha.systemctl("start tincr-mesh.service")
        alpha.wait_for_unit("tincr-mesh.service")
        beta.wait_until_succeeds(
            "systemctl is-active tincr-mesh.service", timeout=30
        )

        out = alpha.succeed(
            "systemctl show -p User,CapabilityBoundingSet,NoNewPrivileges,"
            "ProtectSystem tincr-mesh.service"
        )
        assert "User=tincr" in out, out
        assert "NoNewPrivileges=yes" in out, out
        assert "ProtectSystem=strict" in out, out
        # CAP_NET_ADMIN must NOT be in the bounding set: the tun
        # device is pre-created by networkd with TUNSETOWNER=tincr.
        assert "cap_net_admin" not in out.lower(), out
        assert "cap_net_bind_service" in out.lower(), out

        for m in (alpha, beta):
            listeners = m.succeed(
                "systemctl show -p Listen tincr-mesh.socket"
            )
            assert "0.0.0.0:655" in listeners, listeners
            assert "[::]:655" in listeners, listeners

    with subtest("data path: direct UDP over the mesh"):
        import re

        alpha.wait_until_succeeds("ping -c1 -W2 10.21.0.2", timeout=30)
        beta.succeed("ping -c1 -W2 10.21.0.1")
        for m, peer in ((alpha, "beta"), (beta, "alpha")):
            row = m.wait_until_succeeds(
                "tinc --pidfile=/run/tincr/mesh.pid -n mesh dump nodes "
                f"| grep '^{peer} '",
                timeout=30,
            )
            status = int(re.search(r"status ([0-9a-f]+)", row).group(1), 16)
            assert status & 0x80, row

    with subtest("DNS stub answers via systemd-resolved per-link routing"):
        for m in (alpha, beta):
            m.wait_for_unit("systemd-resolved.service")
            out = m.succeed("resolvectl domain tinc-mesh")
            assert "mesh" in out, out

        beta_ip = alpha.wait_until_succeeds(
            f"{dig} beta.mesh A", timeout=15
        ).strip()
        assert beta_ip == "10.21.0.2", f"unexpected: {beta_ip!r}"

        alpha_ip = beta.succeed(f"{dig} alpha.mesh A").strip()
        assert alpha_ip == "10.21.0.1", f"unexpected: {alpha_ip!r}"

        # Alias = web in hosts/beta answers like the node name.
        web_ip = alpha.succeed(f"{dig} web.mesh A").strip()
        assert web_ip == "10.21.0.2", f"unexpected: {web_ip!r}"

        # PTR not asserted. resolved's mDNS responder answers first.
        # PTR is unit-tested in crates/tincd/src/dns.rs.

    with subtest("clean stop"):
        alpha.systemctl("stop tincr-mesh.service")
        alpha.wait_until_succeeds(
            "systemctl show -p ActiveState tincr-mesh.service "
            "| grep -x ActiveState=inactive",
            timeout=10,
        )
  '';
}
