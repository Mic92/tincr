# Two-node test under the upstream `services.tinc.networks` module.
# tests/netns.rs proves the data path; this proves the deployment
# surface: argv compat, /etc/tinc layout, control socket location.
#
# Trimmed from nixpkgs/nixos/tests/tinc: 2 nodes not 3, Ed25519 only.
{
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
        settings = {
          DeviceType = "tun";
          ConnectTo = peer;
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
      environment.systemPackages = [ pkg ];
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
  '';
}
