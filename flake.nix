{
  description = "tinc Rust rewrite";

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
        }
      );

      devShells = eachSystem (
        system: pkgs: {
          default = pkgs.callPackage ./nix/devshell.nix {
            inherit (self.packages.${system}) tincd-c sptps-test-c;
          };
        }
      );

      # VM tests are Linux-only; runNixOSTest boots qemu.
      checks = eachSystem (
        system: pkgs:
        let
          inherit (self.packages.${system}) tincd tincd-c;
        in
        {
          formatting = treefmt.${system}.config.build.check self;
        }
        // pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          # Rust↔Rust under upstream services.tinc.
          nixos-tinc = pkgs.callPackage ./nix/nixos-test.nix { inherit tincd; };
          # Rust↔C deployment-level wire compat.
          nixos-tinc-crossimpl = pkgs.callPackage ./nix/nixos-test.nix { inherit tincd tincd-c; };
          nixos-tinc-auth = pkgs.callPackage ./nix/nixos-test-auth.nix { inherit tincd; };
          nixos-tinc-nat = pkgs.callPackage ./nix/nixos-test-nat.nix { inherit tincd; };
          nixos-tinc-systemd = pkgs.callPackage ./nix/nixos-test-systemd.nix { inherit tincd; };
          nixos-tinc-dht = pkgs.callPackage ./nix/nixos-test-dht.nix { inherit tincd; };
          nixos-tincr = pkgs.callPackage ./nix/nixos-test-tincr.nix {
            inherit tincd;
            tincrModule = ./nix/module.nix;
          };
        }
      );

      formatter = eachSystem (system: _: treefmt.${system}.config.build.wrapper);

      nixosModules.tincr =
        { pkgs, ... }:
        {
          imports = [ ./nix/module.nix ];
          services.tincr.package = self.packages.${pkgs.stdenv.hostPlatform.system}.tincd;
        };
    };
}
