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
        {
          pkgs,
          self',
          lib,
          system,
          ...
        }:
        {
          # Dev shell: enough to run `make -f kat/Makefile && cargo test`.
          # The C toolchain is needed for KAT regeneration, not for the
          # Rust build itself (no build.rs/cc yet — that comes with the
          # SPTPS FFI harness in Phase 0b).
          devShells.default = pkgs.mkShell {
            # Cross-impl tests (crates/tincd/tests/crossimpl.rs and
            # crates/tinc-tools/tests/self_roundtrip.rs) gate on these
            # env vars: unset → SKIP. The earlier comment at the
            # sptps-test-c derivation about "rebuilding the C binary on
            # every Rust-only change" was wrong about THIS dependency
            # edge: both filesets are src/-only, so a Rust edit does NOT
            # invalidate them — entering the shell after a Rust change
            # is free. A src/ edit DOES rebuild on entry (~10s warm),
            # which is correct: any C change should re-run cross-impl.
            #
            # The crossimpl.rs tests are THE wire-compat proof; they
            # need to run with the rest of the suite, not be opt-in.
            TINC_C_TINCD = "${self'.packages.tincd-c}/sbin/tincd";
            TINC_C_SPTPS_TEST = "${self'.packages.sptps-test-c}/bin/sptps_test";
            TINC_C_SPTPS_KEYPAIR = "${self'.packages.sptps-test-c}/bin/sptps_keypair";

            packages = with pkgs; [
              cargo
              cargo-nextest
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
              # throughput gate (crates/tincd/benches/throughput.rs).
              # `cargo bench --bench throughput --profile profiling`.
              # iperf3 measures the tunnel; perf records the daemon
              # during the 5s window. perf is best-effort: if
              # `kernel.perf_event_paranoid >= 2` (Debian default)
              # the bench still measures throughput, just no profile.
              iperf3
              perf
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
                    ./tinc-c/src/chacha-poly1305
                    ./tinc-c/src/ed25519
                    ./tinc-c/src/nolegacy/prf.c
                    ./tinc-c/src/system.h
                    ./tinc-c/src/utils.h
                    ./tinc-c/src/xalloc.h
                    ./tinc-c/src/prf.h
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
          # `TINC_C_SPTPS_TEST` / `TINC_C_SPTPS_KEYPAIR` point here for
          # the cross-impl tests in tinc-tools/tests/self_roundtrip.rs.
          # The devshell sets both — see the comment there about why
          # the src/-only fileset makes that free for Rust-side edits.
          packages.sptps-test-c = pkgs.stdenv.mkDerivation {
            pname = "tinc-sptps-test-c";
            version = "1.1pre18";
            # Fileset: meson needs the whole src/ tree (the meson.build
            # files reference each other), plus the top-level meson
            # config. No point being clever about minimizing this —
            # it's ~500 small files, derivation rebuild is cheap, and
            # any src/ change SHOULD invalidate it (that's the point of
            # cross-impl: test against the C-that-is, not the C-that-was).
            # The whole upstream tree. We used to fileset-minimize this,
            # but now that it lives in tinc-c/ the boundary is the
            # directory itself — any change in there is by definition a
            # C-side change that should invalidate the cross-impl binaries.
            src = ./tinc-c;
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

          # The Rust daemon + CLI. The NixOS module points `package =`
          # here; its ExecStart hard-codes ${pkg}/bin/tincd, which is
          # where buildRustPackage puts it. doCheck=false: netns tests
          # need bwrap+userns the sandbox lacks. The dev shell runs the
          # full suite; this is the deployment artifact.
          packages.tincd = pkgs.rustPlatform.buildRustPackage {
            pname = "tincd";
            version = "0.1.0";
            src = lib.fileset.toSource {
              root = ./.;
              fileset = lib.fileset.unions [
                ./Cargo.toml
                ./Cargo.lock
                ./.cargo # x86-64-v3 + AVX2 flags; see config.toml
                ./crates
              ];
            };
            cargoLock.lockFile = ./Cargo.lock;
            # Just the bin crates; --workspace would pull tinc-ffi's cc.
            cargoBuildFlags = [
              "-p"
              "tincd"
              "-p"
              "tinc-tools"
            ];
            doCheck = false;
            meta.mainProgram = "tincd";
          };

          # VM tests. Linux-only (runNixOSTest boots qemu).
          checks = lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
            # Rust↔Rust: argv/config-layout compat with the module.
            nixos-tinc = pkgs.callPackage ./nix/nixos-test.nix {
              inherit (self'.packages) tincd;
            };

            # Rust↔C: deployment-level wire compat.
            nixos-tinc-crossimpl = pkgs.callPackage ./nix/nixos-test.nix {
              inherit (self'.packages) tincd tincd-c;
            };

            # tinc-auth: nginx auth_request → control socket lookup.
            # No C equivalent (nginx-auth is a Rust-side feature),
            # so no crossimpl variant. Proves socket activation +
            # the header reaches the proxied origin + off-mesh 401s.
            nixos-tinc-auth = pkgs.callPackage ./nix/nixos-test-auth.nix {
              inherit (self'.packages) tincd;
            };

            # Tier-0 NAT punch: two leaves behind iptables MASQUERADE,
            # one relay. Asserts the leaves go direct (not via relay)
            # within 30s. The two-node test above can't exercise this —
            # both nodes there have static `Address=`; the punch path
            # never fires.
            nixos-tinc-nat = pkgs.callPackage ./nix/nixos-test-nat.nix {
              inherit (self'.packages) tincd;
            };

            # Tier-2a/2b DHT discovery: 6 VMs (relay + 10-node DHT
            # swarm + 2 NAT'd leaves + 1 cold-start node). Asserts
            # the port-probe learns the NAT mapping for tincd's
            # socket through real iptables MASQUERADE, the BEP 44
            # publish carries it, and a node with `ConnectTo=relay`
            # but no `Address=relay` can connect via DHT resolve.
            # Slowest VM test (~65s); the unit-test Testnet covers
            # the same wire format much faster, this proves the
            # config plumbing + NAT path.
            nixos-tinc-dht = pkgs.callPackage ./nix/nixos-test-dht.nix {
              inherit (self'.packages) tincd;
            };
          };

          # The C tincd daemon. Target for crates/tincd/tests/
          # crossimpl.rs (TINC_C_TINCD=$out/bin/tincd) and the
          # nixos-tinc-crossimpl VM test. OpenSSL not nolegacy: the
          # NixOS module's preStart calls `tinc generate-rsa-keys`,
          # which nolegacy tincctl rejects at the dispatch table.
          # Legacy C still negotiates SPTPS-only against us (no RSA
          # pubkey in hosts/ → no legacy offered).
          packages.tincd-c = pkgs.stdenv.mkDerivation {
            pname = "tinc-tincd-c";
            version = "1.1pre18";
            src = ./tinc-c;
            nativeBuildInputs = with pkgs; [
              meson
              ninja
              pkg-config
            ];
            buildInputs = [ pkgs.openssl ];
            # Meson defaults sysconfdir to $out/etc; the NixOS module
            # calls `tinc -n NET ...` without -c and expects /etc.
            mesonFlags = [
              "--sysconfdir=/etc"
              "--localstatedir=/var"
              "-Dcrypto=openssl" # default; explicit vs. sptps-test-c
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
            # Default mesonInstallPhase. tincd lands in $out/sbin
            # (meson.build sets install_dir: dir_sbin); also installs
            # tinc(ctl) and the bash completion. We only care about
            # tincd but the extras are harmless and overriding is
            # more lines than not.
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
                    ./tinc-c/src/splay_tree.h
                    ./tinc-c/src/splay_tree.c
                    ./tinc-c/src/list.h
                    ./tinc-c/src/list.c
                    # splay_tree.c does `#include "system.h"`. Quoted include
                    # searches the .c's own directory first — i.e. src/. The
                    # -DTINC_SYSTEM_H from gen_graph.c guards it out, but the
                    # preprocessor still has to open the file to find the guard.
                    # Same for xalloc.h via list.c.
                    ./tinc-c/src/system.h
                    ./tinc-c/src/xalloc.h
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
                    ./tinc-c/src/ed25519/sha512.c
                    ./tinc-c/src/ed25519/sha512.h
                    ./tinc-c/src/ed25519/fixedint.h
                  ];
                };
                hardeningDisable = [ "fortify" ];
              }
              ''
                $CC -std=c11 -O1 -Wall -Werror \
                  $src/kat/gen_node_id.c $src/tinc-c/src/ed25519/sha512.c -o gen
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
