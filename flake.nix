{
  description = "tinc Rust rewrite — Phase 0: bespoke crypto KAT harness";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
  };

  outputs =
    {
      self,
      nixpkgs,
      treefmt-nix,
      crane,
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      eachSystem = f: nixpkgs.lib.genAttrs systems (system: f system nixpkgs.legacyPackages.${system});
      treefmt = eachSystem (_: pkgs: treefmt-nix.lib.evalModule pkgs ./nix/treefmt.nix);
    in
    {
      packages = eachSystem (
        _: pkgs: {
          kat-vectors = pkgs.callPackage ./nix/kat-vectors.nix { };
          kat-graph = pkgs.callPackage ./nix/kat-graph.nix { };
          kat-checksum = pkgs.callPackage ./nix/kat-checksum.nix { };
          kat-node-id = pkgs.callPackage ./nix/kat-node-id.nix { };
          sptps-test-c = pkgs.callPackage ./nix/sptps-test-c.nix { };
          tincd-c = pkgs.callPackage ./nix/tincd-c.nix { };
          tincd = pkgs.callPackage ./nix/tincd.nix {
            craneLib = crane.mkLib pkgs;
          };
          # TODO: hermetic `checks.cross-impl` derivation. Needs
          # `rustPlatform.buildRustPackage` to vendor deps; a naive
          # `runCommand` + `cargo test --offline` dies in the sandbox
          # (no registry index). For now CI runs the cross-impl tests
          # via the devshell — see crates/tinc-tools/tests/self_roundtrip.rs
          # module doc for the invocation.
        }
      );

      devShells = eachSystem (
        system: pkgs: {
          default = pkgs.callPackage ./nix/devshell.nix {
            inherit (self.packages.${system}) tincd-c sptps-test-c;
          };
        }
      );

      # VM tests. Linux-only (runNixOSTest boots qemu).
      checks = eachSystem (
        system: pkgs:
        let
          inherit (self.packages.${system}) tincd tincd-c;
        in
        {
          formatting = treefmt.${system}.config.build.check self;
        }
        // pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          # Rust↔Rust: argv/config-layout compat with the module.
          nixos-tinc = pkgs.callPackage ./nix/nixos-test.nix { inherit tincd; };

          # Rust↔C: deployment-level wire compat.
          nixos-tinc-crossimpl = pkgs.callPackage ./nix/nixos-test.nix { inherit tincd tincd-c; };

          # tinc-auth: nginx auth_request → control socket lookup.
          # No C equivalent (nginx-auth is a Rust-side feature),
          # so no crossimpl variant. Proves socket activation +
          # the header reaches the proxied origin + off-mesh 401s.
          nixos-tinc-auth = pkgs.callPackage ./nix/nixos-test-auth.nix { inherit tincd; };

          # Tier-0 NAT punch: two leaves behind iptables MASQUERADE,
          # one relay. Asserts the leaves go direct (not via relay)
          # within 30s. The two-node test above can't exercise this —
          # both nodes there have static `Address=`; the punch path
          # never fires.
          nixos-tinc-nat = pkgs.callPackage ./nix/nixos-test-nat.nix { inherit tincd; };

          # Type=notify + WatchdogSec + socket activation. The other
          # VM tests run under the upstream module (Type=simple, no
          # .socket); this one mirrors contrib/tincd@.{service,socket}
          # so sd_notify, the event-loop watchdog timer, and
          # adopt_listeners are exercised end-to-end.
          nixos-tinc-systemd = pkgs.callPackage ./nix/nixos-test-systemd.nix { inherit tincd; };

          # Tier-2a/2b DHT discovery: 6 VMs (relay + 10-node DHT
          # swarm + 2 NAT'd leaves + 1 cold-start node). Asserts
          # the port-probe learns the NAT mapping for tincd's
          # socket through real iptables MASQUERADE, the BEP 44
          # publish carries it, and a node with `ConnectTo=relay`
          # but no `Address=relay` can connect via DHT resolve.
          # Slowest VM test (~65s); the unit-test Testnet covers
          # the same wire format much faster, this proves the
          # config plumbing + NAT path.
          nixos-tinc-dht = pkgs.callPackage ./nix/nixos-test-dht.nix { inherit tincd; };
        }
      );

      formatter = eachSystem (system: _: treefmt.${system}.config.build.wrapper);
    };
}
