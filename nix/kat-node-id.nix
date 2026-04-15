# node.c:125-128: sha512(name, strlen(name), buf), keep first 6
# bytes. The 6-byte node ID prefixes every UDP packet (SRCID/
# DSTID, net.h:92-93). Links the actual src/ed25519/sha512.c
# (LibTomCrypt) so the vectors are ground truth, not a second
# SHA-512 implementation we hope agrees. Vectors inlined in
# crates/tincd/src/node_id.rs::tests::from_name_kat.
{ runCommandCC, lib }:
runCommandCC "tinc-kat-node-id"
  {
    src = lib.fileset.toSource {
      root = ../.;
      fileset = lib.fileset.unions [
        ../kat/gen_node_id.c
        ../tinc-c/src/ed25519/sha512.c
        ../tinc-c/src/ed25519/sha512.h
        ../tinc-c/src/ed25519/fixedint.h
      ];
    };
    hardeningDisable = [ "fortify" ];
  }
  ''
    $CC -std=c11 -O1 -Wall -Werror \
      $src/kat/gen_node_id.c $src/tinc-c/src/ed25519/sha512.c -o gen
    ./gen > $out
  ''
