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
              # tinc-tools cross-impl test wants a C sptps_test to talk
              # to. Building via meson is the path of least resistance —
              # the build graph is already correct. Nolegacy mode means
              # no openssl dep; same crypto subset tinc-crypto ported.
              meson
              ninja
              pkg-config
              # netns integration tests (crates/tincd/tests/netns.rs).
              # bwrap re-execs the test binary inside an unprivileged
              # user+net namespace; ip/unshare/mount build a child
              # netns for one TUN device so ping doesn't shortcut.
              bubblewrap
              iproute2
              iputils # ping
              util-linux # unshare(1), mount(8)
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

          # The C sptps_test/sptps_keypair binaries, built with meson in
          # nolegacy mode (no openssl/gcrypt — same crypto subset as
          # tinc-crypto). nixpkgs#tinc_pre doesn't ship these; they're
          # build_by_default=false in src/meson.build.
          #
          # This is what `TINC_C_SPTPS_TEST` points to for the cross-impl
          # tests in tinc-tools/tests/self_roundtrip.rs. Set it in the
          # devshell shellHook? No — leave it explicit. The cross-impl
          # tests are #[ignore]'d and you opt in by setting the env var,
          # because rebuilding the C binary on every Rust-only change is
          # noise. CI sets it; local dev doesn't have to.
          packages.sptps-test-c = pkgs.stdenv.mkDerivation {
            pname = "tinc-sptps-test-c";
            version = "1.1pre18";
            # Fileset: meson needs the whole src/ tree (the meson.build
            # files reference each other), plus the top-level meson
            # config. No point being clever about minimizing this —
            # it's ~500 small files, derivation rebuild is cheap, and
            # any src/ change SHOULD invalidate it (that's the point of
            # cross-impl: test against the C-that-is, not the C-that-was).
            src = pkgs.lib.fileset.toSource {
              root = ./.;
              fileset = pkgs.lib.fileset.unions [
                ./meson.build
                ./meson_options.txt
                ./src
                # subdir() in the top-level meson.build is unconditional
                # for these. Easier to ship them than to patch them out.
                # The bash_completion.d one just installs a file; the
                # doc one is gated by -Ddocs (we disable). systemd is
                # gated by opt_systemd (we disable). test is gated by
                # opt_tests (we disable). But meson opens the build file
                # *before* checking the gate for `subdir`, so they have
                # to exist.
                ./bash_completion.d
                ./doc/meson.build
                ./systemd/meson.build
              ];
            };
            nativeBuildInputs = with pkgs; [
              meson
              ninja
              pkg-config
            ];
            mesonFlags = [
              # No openssl, no gcrypt. Disables the legacy protocol
              # entirely. SPTPS doesn't need it.
              "-Dcrypto=nolegacy"
              # Silence everything optional. We only want two binaries.
              "-Dminiupnpc=disabled"
              "-Dcurses=disabled"
              "-Dreadline=disabled"
              "-Dzlib=disabled"
              "-Dlzo=disabled"
              "-Dlz4=disabled"
              "-Dvde=disabled"
              "-Ddocs=disabled"
              "-Dtests=disabled"
              "-Dsystemd=disabled"
            ];
            # build_by_default=false — ask for them explicitly.
            ninjaFlags = [
              "src/sptps_test"
              "src/sptps_keypair"
            ];
            # mesonInstallPhase wants to install everything; we only
            # built two targets. Override.
            installPhase = ''
              mkdir -p $out/bin
              install -m755 src/sptps_test src/sptps_keypair $out/bin/
            '';
          };

          # KAT JSON for tinc-graph: real splay_tree.c + list.c, copies of
          # mst_kruskal/sssp_bfs from graph.c. Separate derivation from
          # kat-vectors because the file set is disjoint and we don't want
          # crypto-side changes to dirty the graph KAT cache (or vice versa).
          packages.kat-graph =
            pkgs.runCommandCC "tinc-kat-graph"
              {
                src = pkgs.lib.fileset.toSource {
                  root = ./.;
                  fileset = pkgs.lib.fileset.unions [
                    ./kat_graph/gen_graph.c
                    ./src/splay_tree.h
                    ./src/splay_tree.c
                    ./src/list.h
                    ./src/list.c
                    # splay_tree.c does `#include "system.h"`. Quoted include
                    # searches the .c's own directory first — i.e. src/. The
                    # -DTINC_SYSTEM_H from gen_graph.c guards it out, but the
                    # preprocessor still has to open the file to find the guard.
                    # Same for xalloc.h via list.c.
                    ./src/system.h
                    ./src/xalloc.h
                  ];
                };
                hardeningDisable = [ "fortify" ];
              }
              ''
                $CC -std=c11 -O1 $src/kat_graph/gen_graph.c -o gen
                ./gen > $out
              '';

          # KAT JSON for inet_checksum (route.c:63-86). Standalone
          # TU; the function is copy-pasted verbatim into the
          # generator so the only fileset entry is the generator
          # itself. Vectors are embedded as a literal table in
          # crates/tincd/src/packet.rs; this derivation is the
          # ground truth to diff against if the C ever changes.
          packages.kat-checksum =
            pkgs.runCommandCC "tinc-kat-checksum"
              {
                src = ./kat/gen_checksum.c;
                hardeningDisable = [ "fortify" ];
              }
              ''
                $CC -std=c11 -O1 -Wall -Werror $src -o gen
                ./gen > $out
              '';

          # node.c:125-128: sha512(name, strlen(name), buf), keep first 6
          # bytes. The 6-byte node ID prefixes every UDP packet (SRCID/
          # DSTID, net.h:92-93). Links the actual src/ed25519/sha512.c
          # (LibTomCrypt) so the vectors are ground truth, not a second
          # SHA-512 implementation we hope agrees. Vectors inlined in
          # crates/tincd/src/node_id.rs::tests::from_name_kat.
          packages.kat-node-id =
            pkgs.runCommandCC "tinc-kat-node-id"
              {
                src = pkgs.lib.fileset.toSource {
                  root = ./.;
                  fileset = pkgs.lib.fileset.unions [
                    ./kat/gen_node_id.c
                    ./src/ed25519/sha512.c
                    ./src/ed25519/sha512.h
                    ./src/ed25519/fixedint.h
                  ];
                };
                hardeningDisable = [ "fortify" ];
              }
              ''
                $CC -std=c11 -O1 -Wall -Werror \
                  $src/kat/gen_node_id.c $src/src/ed25519/sha512.c -o gen
                ./gen > $out
              '';

          # TODO: hermetic `checks.cross-impl` derivation. Needs
          # `rustPlatform.buildRustPackage` to vendor deps; a naive
          # `runCommand` + `cargo test --offline` dies in the sandbox
          # (no registry index). For now CI runs the cross-impl tests
          # via the devshell — see crates/tinc-tools/tests/self_roundtrip.rs
          # module doc for the invocation. Tracked in RUST_REWRITE_PLAN.md.

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
