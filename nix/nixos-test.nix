# Two-node test under the upstream `services.tinc.networks` module.
# tests/netns.rs proves the data path; this proves the deployment
# surface: argv compat, /etc/tinc layout, control socket location.
#
# Trimmed from nixpkgs/nixos/tests/tinc: 2 nodes not 3, Ed25519 only.
{
  lib,
  dnsutils,
  testers,
  tincd, # our build, the thing being tested
  tincd-c ? null, # set → beta runs C, proving wire compat at deploy level
}:
let
  keys = import ./snakeoil-keys.nix;

  crossimpl = tincd-c != null;

  mkNode =
    self: peer: pkg:
    { config, lib, ... }:
    {
      services.tinc.networks.mesh = {
        name = self;
        package = pkg;

        # rsaPrivateKeyFile is nullOr; null → tinc.conf omits PrivateKeyFile.
        ed25519PrivateKeyFile = builtins.toFile "ed25519.priv" keys.${self}.ed25519Private;

        # /etc/tinc/mesh/hosts/{alpha,beta}. Both nodes need both.
        hostSettings = {
          alpha = {
            subnets = [ { address = "10.20.0.1"; } ];
            settings.Ed25519PublicKey = keys.alpha.ed25519Public;
          };
          beta = {
            subnets = [ { address = "10.20.0.2"; } ];
            settings.Ed25519PublicKey = keys.beta.ed25519Public;
            # Test driver puts node names in /etc/hosts.
            addresses = [ { address = peer; } ];
          };
        };

        # DeviceType=tun: our autodetect-from-Mode isn't ported yet.
        # DNSAddress/DNSSuffix: alpha only, our build only — the C
        # tincd silently ignores unknown keys (they sit unread in
        # the config tree), but when crossimpl swaps beta to C, we
        # don't want to be probing whether that's still true.
        settings = {
          DeviceType = "tun";
          ConnectTo = peer;
        }
        // lib.optionalAttrs (self == "alpha" && !crossimpl) {
          # 10.20.0.53: inside the /24 on tinc.mesh (kernel routes
          # it to the TUN), not any node's /32. The intercept
          # matches dst==this && dport==53; no `ip addr add` here.
          # That's the chicken-and-egg the intercept design avoids:
          # bind() would need the address on an iface BEFORE setup()
          # finishes, but networking.interfaces configures ADDRESSES
          # AFTER tinc.mesh.service is ordered to start.
          DNSAddress = "10.20.0.53";
          DNSSuffix = "tinc.internal";
        };

        # -R cuts off /nix/store; tinc-up's shebang lives there.
        chroot = false;
      };

      # Pre-create the TUN iface; ordering below avoids the
      # tincd-creates-iface-before-address-is-set race.
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

      # Module only puts package in the unit's PATH, not the system's.
      # dnsutils: the testScript runs dig against the stub.
      environment.systemPackages = [
        pkg
        dnsutils
      ];
    };
in
testers.runNixOSTest {
  name = if crossimpl then "tincd-nixos-crossimpl" else "tincd-nixos";

  nodes = {
    alpha = mkNode "alpha" "beta" tincd;
    beta = mkNode "beta" "alpha" (if crossimpl then tincd-c else tincd);
  };

  testScript = ''
    start_all()

    alpha.wait_for_unit("tinc.mesh.service")
    beta.wait_for_unit("tinc.mesh.service")

    # Handshake takes a moment after "active"; poll with backoff.
    alpha.wait_until_succeeds("ping -c1 -W2 10.20.0.2", timeout=30)
    beta.wait_until_succeeds("ping -c1 -W2 10.20.0.1", timeout=30)

    # 5 packets, all arrive: steady-state UDP, not TCP fallback.
    alpha.succeed("ping -c5 10.20.0.2")
    beta.succeed("ping -c5 10.20.0.1")

    # Control socket at /run/tinc.mesh.socket — derived from --pidfile.
    # Proves the daemon's derivation matches what the CLI computes.
    alpha.succeed("tinc -n mesh dump nodes | grep -w beta")
    beta.succeed("tinc -n mesh dump nodes | grep -w alpha")

    ${lib.optionalString (!crossimpl) ''
      # ─── DNS stub: dig against the TUN intercept ──────────────────
      # tests/netns.rs covers wire-format-vs-kernel-checksum already
      # (single bwrap'd netns, dig). Here we prove what netns CAN'T:
      # the NixOS module's freeform settings type passes DNSAddress/
      # DNSSuffix through to /etc/tinc/mesh/tinc.conf unmolested,
      # under the real systemd unit's /run/ layout, with the iface
      # configured by networking.interfaces (not `ip addr` in a
      # script). Same dig assertions; what's tested is the plumbing.

      with subtest("DNS config plumbed through NixOS module"):
          # DNSAddress sits in the generated tinc.conf, not silently
          # filtered by some module-level allowlist. Direct file
          # check — the daemon reading it is proven by dig below.
          alpha.succeed("grep -F 'DNSAddress=10.20.0.53' /etc/tinc/mesh/tinc.conf")
          alpha.succeed("grep -F 'DNSSuffix=tinc.internal' /etc/tinc/mesh/tinc.conf")

      with subtest("DNS stub: A record"):
          out = alpha.succeed(
              "dig @10.20.0.53 +short +tries=1 +timeout=2 beta.tinc.internal A"
          ).strip()
          assert out == "10.20.0.2", f"expected beta's /32, got {out!r}"

      with subtest("DNS stub: PTR"):
          # `dig -x 10.20.0.2` → 2.0.20.10.in-addr.arpa PTR. Our
          # PTR lookup walks the same subnet tree as route(); if
          # ADD_SUBNET-from-gossip didn't land in the tree, this is
          # NXDOMAIN. Proves DNS sees the live table, not a snapshot.
          out = alpha.succeed(
              "dig @10.20.0.53 +short +tries=1 +timeout=2 -x 10.20.0.2"
          ).strip()
          assert out == "beta.tinc.internal.", f"got {out!r}"

      with subtest("DNS stub: NXDOMAIN, no forward"):
          # Not in our suffix → NXDOMAIN immediately. If the daemon
          # tried to forward, dig would time out (the test VMs have
          # no real upstream).
          out = alpha.succeed(
              "dig @10.20.0.53 +tries=1 +timeout=2 google.com A"
          )
          assert "NXDOMAIN" in out, f"expected NXDOMAIN; got:\n{out}"
    ''}
  '';
}
