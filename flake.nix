{
  description = "tinc Rust rewrite — Phase 0: bespoke crypto KAT harness";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [ inputs.treefmt-nix.flakeModule ];
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];

      perSystem =
        { pkgs, ... }:
        {
          # Dev shell: enough to run `make -f kat/Makefile && cargo test`.
          # The C toolchain is needed for KAT regeneration, not for the
          # Rust build itself (no build.rs/cc yet — that comes with the
          # SPTPS FFI harness in Phase 0b).
          devShells.default = pkgs.mkShell {
            packages = with pkgs; [
              cargo
              rustc
              clippy
              rustfmt
              gcc
              gnumake
              jq # vectors.json sanity-checking
            ];
          };

          # KAT vectors as a derivation: content-addressed, so any change to
          # the C crypto sources produces a different store hash. Diffing this
          # output across commits is the cheapest possible "did the wire
          # format change?" check — no Rust toolchain needed.
          packages.kat-vectors =
            pkgs.runCommandCC "tinc-kat-vectors"
              {
                # Only the files the generator actually reads. The src/*.h
                # entries are needed even though their *content* is suppressed
                # by -D guard defines: the preprocessor still has to open the
                # file to discover the guard. Keeping this set minimal means
                # unrelated src/ churn doesn't invalidate the cache.
                src = pkgs.lib.fileset.toSource {
                  root = ./.;
                  fileset = pkgs.lib.fileset.unions [
                    (pkgs.lib.fileset.fileFilter (f: f.hasExt "c" || f.hasExt "h") ./kat)
                    ./kat/Makefile
                    ./src/chacha-poly1305
                    ./src/ed25519
                    ./src/nolegacy/prf.c
                    ./src/system.h
                    ./src/utils.h
                    ./src/xalloc.h
                    ./src/prf.h
                  ];
                };
                # Nix's hardening wrapper sets -D_FORTIFY_SOURCE which warns
                # at -O0. We don't care about hardening a test-vector generator.
                hardeningDisable = [ "fortify" ];
                nativeBuildInputs = [ pkgs.gnumake ];
              }
              ''
                # Makefile writes the binary next to the sources, so we need
                # a mutable copy. cp -r preserves the layout the Makefile's
                # relative paths expect.
                cp -r $src build
                chmod -R u+w build
                make -C build -f kat/Makefile OUT_JSON=$out
              '';

          treefmt = {
            projectRootFile = "flake.nix";
            programs = {
              rustfmt.enable = true;
              nixfmt.enable = true;
              # The C side stays under astyle (upstream's choice); don't
              # fight it from here.
            };
            settings.global.excludes = [
              "src/**" # upstream C, not ours to reformat
              "Cargo.lock"
              "*.json"
            ];
          };
        };
    };
}
