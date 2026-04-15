# KAT JSON for inet_checksum (route.c:63-86). Standalone
# TU; the function is copy-pasted verbatim into the
# generator so the only fileset entry is the generator
# itself. Vectors are embedded as a literal table in
# crates/tincd/src/packet.rs; this derivation is the
# ground truth to diff against if the C ever changes.
{ runCommandCC }:
runCommandCC "tinc-kat-checksum"
  {
    src = ../kat/gen_checksum.c;
    hardeningDisable = [ "fortify" ];
  }
  ''
    $CC -std=c11 -O1 -Wall -Werror $src -o gen
    ./gen > $out
  ''
