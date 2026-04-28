# End-to-end test for services.tincr: declarative tinc.conf + hosts/,
# hardened Type=notify unit, .socket activation, and the TUN-intercept
# DNS stub wired through systemd-networkd + resolved.
#
# Two nodes mesh on 10.21.0.0/16. The module sets DNSAddress=10.21.0.53
# + DNSSuffix=mesh and emits a .network unit with DNS=/Domains=~mesh,
# so `dig beta.mesh` from alpha is routed by resolved to 10.21.0.53,
# leaves via the tunnel, and is answered by tincd on beta from beta's
# Subnet.
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
      } // extraNet;

      # The module declares Ed25519PrivateKeyFile but does not own
      # the bytes (stateful by design); supply them inline. tincd
      # runs as `tincr`, so the key must be group-readable.
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

    with subtest("module brings up the hardened socket-activated unit"):
        # Beta's service stays inactive until alpha's first dial
        # triggers socket activation; poll instead of wait_for_unit
        # which would fail fast on inactive+no-job.
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

    with subtest("data path: ping over the mesh"):
        alpha.wait_until_succeeds("ping -c1 -W2 10.21.0.2", timeout=30)
        beta.succeed("ping -c1 -W2 10.21.0.1")

    with subtest("DNS stub answers via systemd-resolved per-link routing"):
        for m in (alpha, beta):
            m.wait_for_unit("systemd-resolved.service")
            out = m.succeed("resolvectl domain tinc-mesh")
            assert "mesh" in out, out

        # 127.0.0.53 is resolved's stub; it routes `*.mesh` to
        # 10.21.0.53 on tinc-mesh, the packet hits the TUN, tincd
        # answers with the peer's /32 Subnet.
        beta_ip = alpha.wait_until_succeeds(
            "dig +short +tries=1 +time=3 @127.0.0.53 beta.mesh A",
            timeout=15,
        ).strip()
        assert beta_ip == "10.21.0.2", f"unexpected: {beta_ip!r}"

        alpha_ip = beta.succeed(
            "dig +short +tries=1 +time=3 @127.0.0.53 alpha.mesh A"
        ).strip()
        assert alpha_ip == "10.21.0.1", f"unexpected: {alpha_ip!r}"

        # PTR not asserted: resolved's mDNS responder beats the
        # stub with `<name>.local`. PTR has unit-test coverage in
        # crates/tincd/src/dns.rs.

    with subtest("clean stop"):
        alpha.systemctl("stop tincr-mesh.service")
        alpha.wait_until_succeeds(
            "systemctl show -p ActiveState tincr-mesh.service "
            "| grep -x ActiveState=inactive",
            timeout=10,
        )
  '';
}
