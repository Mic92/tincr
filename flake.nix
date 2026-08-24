{
  description = "tinc Rust rewrite";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      treefmt-nix,
      crane,
      fenix,
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
        "riscv64-linux"
      ];
      eachSystem = f: nixpkgs.lib.genAttrs systems (system: f system nixpkgs.legacyPackages.${system});
      # androidenv needs the unfree SDK license accepted.
      androidPkgsFor =
        system:
        import nixpkgs {
          inherit system;
          config = {
            allowUnfree = true;
            android_sdk.accept_license = true;
          };
        };
      treefmt = eachSystem (_: pkgs: treefmt-nix.lib.evalModule pkgs ./nix/treefmt.nix);
    in
    {
      packages = eachSystem (
        system: pkgs:
        {
          default = self.packages.${system}.tincd;
          kat-vectors = pkgs.callPackage ./nix/kat-vectors.nix { };
          kat-graph = pkgs.callPackage ./nix/kat-graph.nix { };
          kat-checksum = pkgs.callPackage ./nix/kat-checksum.nix { };
          kat-node-id = pkgs.callPackage ./nix/kat-node-id.nix { };
          sptps-test-c = pkgs.callPackage ./nix/sptps-test-c.nix { };
          tincd-c = pkgs.callPackage ./nix/tincd-c.nix { };
          tincd = pkgs.callPackage ./nix/tincd.nix {
            craneLib = crane.mkLib pkgs;
            tincd-c = self.packages.${system}.tincd-c;
            sptps-test-c = self.packages.${system}.sptps-test-c;
          };
          # Pre-Haswell x86_64 (no AVX2). See baselineCpu in tincd.nix.
          tincd-compat = self.packages.${system}.tincd.override { baselineCpu = true; };
        }
        // nixpkgs.lib.optionalAttrs (system == "x86_64-linux") {
          tincd-android =
            let
              pkgs' = androidPkgsFor system;
            in
            pkgs'.callPackage ./nix/tincd-android.nix {
              craneLib = crane.mkLib pkgs';
              fenix = fenix.packages.${system};
            };
          tincd-android-x86_64 = self.packages.${system}.tincd-android.override {
            target = "x86_64-linux-android";
          };
          tincr-app = (androidPkgsFor system).callPackage ./nix/android-app.nix {
            inherit (self.packages.${system}) tincd-android;
          };
        }
      );

      devShells = eachSystem (
        system: pkgs:
        {
          default = pkgs.callPackage ./nix/devshell.nix {
            inherit (self.packages.${system}) tincd-c sptps-test-c;
          };
        }
        // nixpkgs.lib.optionalAttrs (system == "x86_64-linux") {
          android = (androidPkgsFor system).callPackage ./nix/devshell-android.nix {
            fenix = fenix.packages.${system};
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
          inherit tincd;
          tincd-test = tincd.tests;
        }
        // pkgs.lib.optionalAttrs (system == "x86_64-linux") {
          inherit (self.packages.${system}) tincd-android tincd-android-x86_64 tincr-app;
          android-mesh = (androidPkgsFor system).callPackage ./nix/android-mesh-check.nix {
            inherit (self.packages.${system}) tincr-app;
          };
        }
        // pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          # Rust↔Rust under upstream services.tinc.
          nixos-tinc = pkgs.callPackage ./nix/nixos-test.nix { inherit tincd; };
          # Rust↔C deployment-level wire compat.
          nixos-tinc-crossimpl = pkgs.callPackage ./nix/nixos-test.nix { inherit tincd tincd-c; };
          nixos-tinc-auth = pkgs.callPackage ./nix/nixos-test-auth.nix { inherit tincd; };
          nixos-tinc-auth-container = pkgs.callPackage ./nix/nixos-test-auth-container.nix { inherit tincd; };
          nixos-tinc-authelia = pkgs.callPackage ./nix/nixos-test-authelia.nix { inherit tincd; };
          nixos-tinc-nat = pkgs.callPackage ./nix/nixos-test-nat.nix { inherit tincd; };
          nixos-tinc-systemd = pkgs.callPackage ./nix/nixos-test-systemd.nix { inherit tincd; };
          nixos-tincr = pkgs.callPackage ./nix/nixos-test-tincr.nix {
            inherit tincd;
            tincrModule = self.nixosModules.tincr;
          };
        }
      );

      formatter = eachSystem (system: _: treefmt.${system}.config.build.wrapper);

      nixosModules.tincr = nixpkgs.lib.modules.importApply ./nix/module.nix { inherit crane; };
    };
}
