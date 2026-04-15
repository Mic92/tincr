# KAT JSON for tinc-graph: real splay_tree.c + list.c, copies of
# mst_kruskal/sssp_bfs from graph.c. Separate derivation from
# kat-vectors because the file set is disjoint and we don't want
# crypto-side changes to dirty the graph KAT cache (or vice versa).
{ runCommandCC, lib }:
runCommandCC "tinc-kat-graph"
  {
    src = lib.fileset.toSource {
      root = ../.;
      fileset = lib.fileset.unions [
        ../kat_graph/gen_graph.c
        ../tinc-c/src/splay_tree.h
        ../tinc-c/src/splay_tree.c
        ../tinc-c/src/list.h
        ../tinc-c/src/list.c
        # splay_tree.c does `#include "system.h"`. Quoted include
        # searches the .c's own directory first — i.e. src/. The
        # -DTINC_SYSTEM_H from gen_graph.c guards it out, but the
        # preprocessor still has to open the file to find the guard.
        # Same for xalloc.h via list.c.
        ../tinc-c/src/system.h
        ../tinc-c/src/xalloc.h
      ];
    };
    hardeningDisable = [ "fortify" ];
  }
  ''
    $CC -std=c11 -O1 $src/kat_graph/gen_graph.c -o gen
    ./gen > $out
  ''
