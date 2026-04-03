// KAT generator for graph.c: sssp_bfs + mst_kruskal.
//
// Same shape as kat/gen_kat.c: standalone TU, #includes the real .c
// directly, stubs the world. The graph algorithms touch a lot of
// surface (node_t, edge_t, splay trees, list_t, connection_t) but only
// *read* most of it — the only writes outside the graph structs
// themselves are `update_node_udp` and `c->status.mst`.
//
// `update_node_udp` we suppress: it's gated on
//   !e->to->status.reachable || (addr family check)
// so if every node starts reachable=true with a non-UNSPEC address,
// the call never fires. That's fine for KATs — the address-learning
// side channel is daemon territory anyway. The Rust side will emit it
// as a typed event for the daemon to act on; we test the routing
// outputs (distance, nexthop, via, indirect, MST set) here.
//
// `c->status.mst` we capture: every edge that participates in the MST
// gets a fake connection_t whose mst bit we read back.
//
// One subtlety: `sssp_bfs` reads the *previous* run's `reachable` for
// the suppress-update_node_udp gate, and `mst_kruskal` uses it to pick
// a starting point. So `reachable` is an *input*. We seed it.
//
// The real `graph()` runs sssp first, then check_reachability (which
// flips reachable := visited and fires scripts), then kruskal. We skip
// check_reachability entirely (it's 90% execute_script) and instead
// dump `visited` directly — that's what reachable becomes.

// ────────────────────────────────────────────────────────────────────
// Stubs: just enough surface for graph.c to compile.

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>

// Logging is voluminous in graph.c (DEBUG_SCARY_THINGS). Silence it.
typedef enum { DEBUG_ALWAYS, DEBUG_SCARY_THINGS, DEBUG_TRAFFIC } debug_t;
static inline void logger(debug_t l, int p, const char *f, ...) {
	(void)l; (void)p; (void)f;
}
#define LOG_ERR 0
#define LOG_DEBUG 0

static inline void *xzalloc(size_t n) { return calloc(1, n); }
static inline void *xmalloc(size_t n) { return malloc(n); }

// ────────────────────────────────────────────────────────────────────
// Real splay tree + list — they're standalone, no deps. Including the
// .c is gross but we need the iteration macros to behave identically.
// (They read `node->next` *before* the body runs, which is what makes
// the BFS's mid-iteration `list_insert_tail` safe.)

#define TINC_SYSTEM_H
#define TINC_XALLOC_H
#define ATTR_MALLOC
#define ATTR_DEALLOCATOR(x)
#define ATTR_NONNULL
#include "../src/splay_tree.h"
#include "../src/list.h"
#include "../src/splay_tree.c"
#include "../src/list.c"

// ────────────────────────────────────────────────────────────────────
// Minimal sockaddr_t. The BFS only reads `.sa.sa_family`; everything
// else is opaque to us. Match AF_UNSPEC/AF_UNKNOWN handling exactly.

#define AF_UNKNOWN 255

typedef union {
	struct sockaddr sa;
	struct sockaddr_storage storage;
} sockaddr_t;

// ────────────────────────────────────────────────────────────────────
// Minimal node_t / edge_t / connection_t. Only the fields graph.c
// touches. Layout doesn't matter (we never share these with real C).

typedef struct connection_t {
	struct {
		bool mst: 1;
	} status;
} connection_t;

typedef struct node_t node_t;
typedef struct edge_t edge_t;

// status bitfield: graph.c reads/writes visited, indirect, reachable.
// check_reachability also touches a bunch more (validkey, sptps,
// waitingforkey, udp_confirmed) but we're not running that.
typedef struct {
	bool visited: 1;
	bool reachable: 1;
	bool indirect: 1;
} node_status_t;

struct node_t {
	char *name;
	node_status_t status;
	uint32_t options;

	// SSSP outputs
	int distance;
	int weighted_distance;
	node_t *nexthop;
	edge_t *prevedge;
	node_t *via;

	// gates the update_node_udp call we want to suppress
	sockaddr_t address;

	splay_tree_t edge_tree;

	// used by check_reachability — unused here, but easier to leave
	// the field than to #ifdef it out of the include
	struct connection_t *connection;
};

struct edge_t {
	node_t *from;
	node_t *to;
	uint32_t options;
	int weight;
	edge_t *reverse;
	connection_t *connection;
	sockaddr_t address;
};

// ────────────────────────────────────────────────────────────────────
// Globals graph.c expects.

static int node_compare(const node_t *a, const node_t *b) {
	return strcmp(a->name, b->name);
}
splay_tree_t node_tree = { .compare = (splay_compare_t)node_compare };

static int edge_weight_compare(const edge_t *a, const edge_t *b) {
	int r = a->weight - b->weight;
	if (r) return r;
	r = strcmp(a->from->name, b->from->name);
	if (r) return r;
	return strcmp(a->to->name, b->to->name);
}
splay_tree_t edge_weight_tree = { .compare = (splay_compare_t)edge_weight_compare };

static int edge_compare(const edge_t *a, const edge_t *b) {
	return strcmp(a->to->name, b->to->name);
}

list_t connection_list = {0};
node_t *myself;

// OPTION_INDIRECT, the one bit sssp_bfs cares about.
#define OPTION_INDIRECT 0x0001

// Suppressed (guarded by `!reachable`, which we keep true). Abort if
// it ever fires — means the gate broke.
static void update_node_udp(node_t *n, const sockaddr_t *sa) {
	(void)n; (void)sa;
	fprintf(stderr, "update_node_udp fired — gate broken\n");
	abort();
}

// ────────────────────────────────────────────────────────────────────
// Now pull in the real algorithms. mst_kruskal and sssp_bfs are the
// two we want; check_reachability and graph() we don't, but they're
// in the same TU. Pulling them in means stubbing their callees.
// Easier: copy the two functions verbatim. They're 40 + 80 LOC and
// the whole point of a KAT generator is one-shot fidelity, not
// maintenance. Any drift in graph.c shows up as KAT failures.
//
// (Alternative considered: #include "../src/graph.c" with stubs for
// subnet_cache_flush_tables, execute_script, environment_*, sptps_stop,
// timeout_del, device_enable/disable, sockaddr2str, OPTION_VERSION,
// experimental, MTU, now, device_standby. Twelve stubs vs two
// short copies — copies win.)

static void mst_kruskal(void) {
	for list_each(connection_t, c, &connection_list) {
		c->status.mst = false;
	}
	for splay_each(node_t, n, &node_tree) {
		n->status.visited = false;
	}
	for splay_each(edge_t, e, &edge_weight_tree) {
		if(e->from->status.reachable) {
			e->from->status.visited = true;
			break;
		}
	}
	bool skipped = false;
	for splay_each(edge_t, e, &edge_weight_tree) {
		if(!e->reverse || (e->from->status.visited == e->to->status.visited)) {
			skipped = true;
			continue;
		}
		e->from->status.visited = true;
		e->to->status.visited = true;
		if(e->connection) e->connection->status.mst = true;
		if(e->reverse->connection) e->reverse->connection->status.mst = true;
		if(skipped) {
			skipped = false;
			next = edge_weight_tree.head;
		}
	}
}

static void sssp_bfs(void) {
	list_t *todo = list_alloc(NULL);

	for splay_each(node_t, n, &node_tree) {
		n->status.visited = false;
		n->status.indirect = true;
		n->distance = -1;
	}

	myself->status.visited = true;
	myself->status.indirect = false;
	myself->nexthop = myself;
	myself->prevedge = NULL;
	myself->via = myself;
	myself->distance = 0;
	myself->weighted_distance = 0;
	list_insert_head(todo, myself);

	for list_each(node_t, n, todo) {
		assert(n->distance >= 0);
		for splay_each(edge_t, e, &n->edge_tree) {
			if(!e->reverse || e->to == myself) continue;

			bool indirect = n->status.indirect || e->options & OPTION_INDIRECT;

			if(e->to->status.visited
			   && (!e->to->status.indirect || indirect)
			   && (e->to->distance != n->distance + 1
			       || e->to->weighted_distance <= n->weighted_distance + e->weight))
				continue;

			if(!e->to->status.visited
			   || (e->to->distance == n->distance + 1
			       && e->to->weighted_distance > n->weighted_distance + e->weight)) {
				e->to->nexthop = (n->nexthop == myself) ? e->to : n->nexthop;
				e->to->weighted_distance = n->weighted_distance + e->weight;
			}

			e->to->status.visited = true;
			e->to->status.indirect = indirect;
			e->to->prevedge = e;
			e->to->via = indirect ? n->via : e->to;
			e->to->options = e->options;
			e->to->distance = n->distance + 1;

			if(!e->to->status.reachable
			   || (e->to->address.sa.sa_family == AF_UNSPEC
			       && e->address.sa.sa_family != AF_UNKNOWN))
				update_node_udp(e->to, &e->address);

			list_insert_tail(todo, e->to);
		}
		next = node->next;
		list_delete_node(todo, node);
	}
	list_free(todo);
}

// ────────────────────────────────────────────────────────────────────
// Test-case construction. Deterministic RNG (LCG — overkill, but
// having a *named* algorithm means the Rust side can replay exactly
// the same case if a KAT fails and we want to bisect).

static uint64_t rng_state;
static void rng_seed(uint64_t s) { rng_state = s; }
static uint32_t rng_u32(void) {
	rng_state = rng_state * 6364136223846793005ull + 1442695040888963407ull;
	return (uint32_t)(rng_state >> 32);
}

#define MAX_NODES 32
#define MAX_EDGES 128

static node_t nodes[MAX_NODES];
static edge_t edges[MAX_EDGES];
static connection_t conns[MAX_EDGES]; // one per edge for mst capture
static int n_nodes, n_edges;

static void reset(void) {
	splay_empty_tree(&node_tree);
	splay_empty_tree(&edge_weight_tree);
	connection_list.head = connection_list.tail = NULL;
	connection_list.count = 0;
	memset(nodes, 0, sizeof nodes);
	memset(edges, 0, sizeof edges);
	memset(conns, 0, sizeof conns);
	n_nodes = n_edges = 0;
}

static node_t *add_node(const char *name) {
	node_t *n = &nodes[n_nodes++];
	n->name = (char *)name;
	// Seed: reachable=true, AF_INET — suppresses update_node_udp.
	n->status.reachable = true;
	n->address.sa.sa_family = AF_INET;
	n->edge_tree.compare = (splay_compare_t)edge_compare;
	splay_insert(&node_tree, n);
	return n;
}

// Add a directed edge. The caller pairs them (a→b and b→a) and we
// link `reverse` after both exist. Real edge_add does the lookup; we
// hand-wire it because the KAT input format wants to be explicit
// about which pairs exist (one-directional edges are *legal* — sssp
// just skips them via the `!e->reverse` check).
static edge_t *add_edge(node_t *from, node_t *to, int weight, uint32_t opts) {
	edge_t *e = &edges[n_edges];
	e->from = from;
	e->to = to;
	e->weight = weight;
	e->options = opts;
	e->address.sa.sa_family = AF_INET;
	e->connection = &conns[n_edges];
	n_edges++;
	splay_insert(&from->edge_tree, e);
	splay_insert(&edge_weight_tree, e);
	list_insert_tail(&connection_list, e->connection);
	return e;
}

static int nodeidx(node_t *n) {
	return n ? (int)(n - nodes) : -1;
}

// edge.c:105-112 verbatim semantics: unlink reverse, remove from
// per-node tree + global weight tree. The slab slot stays (we keep
// addressing edges by index) but mark `from = NULL` so emission can
// skip it. The Rust side's free-list slot is similarly None.
static void del_edge(int idx) {
	edge_t *e = &edges[idx];
	assert(e->from && "double delete");
	if (e->reverse) e->reverse->reverse = NULL;
	splay_delete(&edge_weight_tree, e);
	splay_delete(&e->from->edge_tree, e);
	// Clear the connection's mst bit — emit_case reads conns[] linearly
	// and doesn't know this edge is dead. The real tinc removes from
	// connection_list; we just zero the bit we read.
	conns[idx].status.mst = false;
	e->from = NULL; // tombstone
}

// ────────────────────────────────────────────────────────────────────
// JSON emission. One object per case.

// Emit one sssp+mst snapshot under the given JSON keys. Runs
// mst_kruskal in-place (trashes `visited`); sssp must already have
// run. Factored out so delete-cases can emit "before" and "after".
static void emit_snapshot(FILE *out, const char *sssp_key, const char *mst_key) {
	bool sssp_visited[MAX_NODES];
	for (int i = 0; i < n_nodes; i++)
		sssp_visited[i] = nodes[i].status.visited;

	for (int i = 0; i < n_nodes; i++)
		nodes[i].status.reachable = sssp_visited[i];
	mst_kruskal();

	fprintf(out, "    \"%s\": [", sssp_key);
	for (int i = 0; i < n_nodes; i++) {
		node_t *n = &nodes[i];
		bool r = sssp_visited[i];
		fprintf(out, "%s{\"reachable\":%s,\"indirect\":%s,"
			"\"distance\":%d,\"weighted_distance\":%d,"
			"\"nexthop\":%d,\"via\":%d,\"prevedge\":%d,\"options\":%u}",
			i ? "," : "",
			r ? "true" : "false",
			r && n->status.indirect ? "true" : "false",
			r ? n->distance : -1,
			r ? n->weighted_distance : -1,
			r ? nodeidx(n->nexthop) : -1,
			r ? nodeidx(n->via) : -1,
			r && n->prevedge ? (int)(n->prevedge - edges) : -1,
			r ? n->options : 0);
	}
	fprintf(out, "],\n");

	fprintf(out, "    \"%s\": [", mst_key);
	int first = 1;
	for (int i = 0; i < n_edges; i++) {
		if (conns[i].status.mst) {
			fprintf(out, "%s%d", first ? "" : ",", i);
			first = 0;
		}
	}
	fprintf(out, "]");
}

static void emit_case(const char *name, FILE *out) {
	fprintf(out, "  {\n    \"name\": \"%s\",\n", name);

	// Input: nodes (just names — index = position), edges, myself.
	fprintf(out, "    \"nodes\": [");
	for (int i = 0; i < n_nodes; i++)
		fprintf(out, "%s\"%s\"", i ? "," : "", nodes[i].name);
	fprintf(out, "],\n");

	fprintf(out, "    \"edges\": [");
	for (int i = 0; i < n_edges; i++) {
		fprintf(out, "%s{\"from\":%d,\"to\":%d,\"weight\":%d,\"opts\":%u,\"reverse\":%d}",
			i ? "," : "",
			nodeidx(edges[i].from), nodeidx(edges[i].to),
			edges[i].weight, edges[i].options,
			edges[i].reverse ? (int)(edges[i].reverse - edges) : -1);
	}
	fprintf(out, "],\n");

	fprintf(out, "    \"myself\": %d,\n", nodeidx(myself));

	emit_snapshot(out, "sssp", "mst");
	fprintf(out, "\n  }");
}

// Delete-phase variant: emit the pre-delete snapshot, then delete the
// listed edges (real splay_delete via del_edge), re-run sssp, emit the
// post-delete snapshot. The Rust KAT test deletes the same indices and
// diffs the second snapshot.
static void emit_case_del(const char *name, const int *del, int n_del, FILE *out) {
	fprintf(out, "  {\n    \"name\": \"%s\",\n", name);

	fprintf(out, "    \"nodes\": [");
	for (int i = 0; i < n_nodes; i++)
		fprintf(out, "%s\"%s\"", i ? "," : "", nodes[i].name);
	fprintf(out, "],\n");

	fprintf(out, "    \"edges\": [");
	for (int i = 0; i < n_edges; i++) {
		fprintf(out, "%s{\"from\":%d,\"to\":%d,\"weight\":%d,\"opts\":%u,\"reverse\":%d}",
			i ? "," : "",
			nodeidx(edges[i].from), nodeidx(edges[i].to),
			edges[i].weight, edges[i].options,
			edges[i].reverse ? (int)(edges[i].reverse - edges) : -1);
	}
	fprintf(out, "],\n");

	fprintf(out, "    \"myself\": %d,\n", nodeidx(myself));

	emit_snapshot(out, "sssp", "mst");
	fprintf(out, ",\n");

	fprintf(out, "    \"del_edges\": [");
	for (int i = 0; i < n_del; i++)
		fprintf(out, "%s%d", i ? "," : "", del[i]);
	fprintf(out, "],\n");

	for (int i = 0; i < n_del; i++) del_edge(del[i]);

	// Re-seed reachable for the suppress-update_node_udp gate —
	// del_edge can disconnect nodes, the second sssp will visit
	// fewer, but the gate reads the *previous* reachable (now stale).
	// Set everyone reachable=true again (same seeding as add_node).
	for (int i = 0; i < n_nodes; i++) nodes[i].status.reachable = true;
	sssp_bfs();
	emit_snapshot(out, "sssp_after", "mst_after");
	fprintf(out, "\n  }");
}

// ────────────────────────────────────────────────────────────────────
// Hand-crafted cases. Each one targets a specific branch in sssp_bfs
// or mst_kruskal. Names from `n0`..`n31` so node indices are obvious.

static const char *NM[MAX_NODES] = {
	"n0","n1","n2","n3","n4","n5","n6","n7","n8","n9","n10","n11","n12","n13","n14","n15",
	"n16","n17","n18","n19","n20","n21","n22","n23","n24","n25","n26","n27","n28","n29","n30","n31"
};

// Helper: bidirectional edge pair, reverse-linked.
static void link_pair(node_t *a, node_t *b, int wa, int wb, uint32_t oa, uint32_t ob) {
	edge_t *ea = add_edge(a, b, wa, oa);
	edge_t *eb = add_edge(b, a, wb, ob);
	ea->reverse = eb;
	eb->reverse = ea;
}

// Isolated node (myself only).
static void case_singleton(FILE *out) {
	reset();
	add_node(NM[0]);
	myself = &nodes[0];
	sssp_bfs();
	emit_case("singleton", out);
}

// Linear chain. Tests distance counting and nexthop propagation.
static void case_chain(FILE *out) {
	reset();
	for (int i = 0; i < 5; i++) add_node(NM[i]);
	for (int i = 0; i < 4; i++) link_pair(&nodes[i], &nodes[i+1], 10, 10, 0, 0);
	myself = &nodes[0];
	sssp_bfs();
	emit_case("chain5", out);
}

// Diamond: two paths to n3. Same hop count, different weights.
// Tests the weighted_distance tiebreak (line 188:
// `e->to->weighted_distance > n->weighted_distance + e->weight`).
static void case_diamond_weight(FILE *out) {
	reset();
	for (int i = 0; i < 4; i++) add_node(NM[i]);
	// 0→1 cheap, 0→2 expensive, both → 3
	link_pair(&nodes[0], &nodes[1], 5, 5, 0, 0);
	link_pair(&nodes[0], &nodes[2], 50, 50, 0, 0);
	link_pair(&nodes[1], &nodes[3], 10, 10, 0, 0);
	link_pair(&nodes[2], &nodes[3], 10, 10, 0, 0);
	myself = &nodes[0];
	sssp_bfs();
	emit_case("diamond_weight", out);
}

// Diamond: one path indirect, one direct. Tests the indirect→direct
// upgrade (line 180: `!e->to->status.indirect || indirect` — if e->to
// was reached indirectly and we now have a direct path, take it even
// if `distance` worsens). This is *the* tricky branch.
static void case_diamond_indirect(FILE *out) {
	reset();
	for (int i = 0; i < 4; i++) add_node(NM[i]);
	// 0→1 indirect (cheap), 0→2 direct (expensive)
	// Both reach 3. The indirect path is 2 hops via 1 (cheap), the
	// direct path is 2 hops via 2 (expensive). BFS visits 1 before 2
	// (alphabetical edge_tree order), so 3 first gets via-1 indirect.
	// Then the via-2 direct path should *override* it.
	link_pair(&nodes[0], &nodes[1], 5, 5, OPTION_INDIRECT, OPTION_INDIRECT);
	link_pair(&nodes[0], &nodes[2], 50, 50, 0, 0);
	link_pair(&nodes[1], &nodes[3], 5, 5, 0, 0);
	link_pair(&nodes[2], &nodes[3], 50, 50, 0, 0);
	myself = &nodes[0];
	sssp_bfs();
	emit_case("diamond_indirect", out);
}

// One-directional edge: a→b exists, b→a doesn't. sssp skips it
// (`!e->reverse`). a is unreachable from myself=b. Tests the skip.
static void case_oneway(FILE *out) {
	reset();
	add_node(NM[0]); add_node(NM[1]); add_node(NM[2]);
	// 0↔1 bidi, 1→2 one-way (no reverse)
	link_pair(&nodes[0], &nodes[1], 10, 10, 0, 0);
	add_edge(&nodes[1], &nodes[2], 10, 0); // no reverse linked
	myself = &nodes[0];
	sssp_bfs();
	emit_case("oneway", out);
}

// MST restart-on-progress: edges sorted by weight, but the lightest
// edge connects two nodes that are *both* unvisited at first pass.
// `skipped=true; ... next = edge_weight_tree.head;` is the rewind.
//
// Setup: 4 nodes, edges (weight): 1-2(5), 0-1(10), 2-3(15).
// Weight order: (1-2), (0-1), (2-3).
// Starting reachable: only n0. So start visited={0}.
// Pass 1: (1-2) — both unvisited, skip. (0-1) — 0 visited 1 not, take.
//   Now visited={0,1}, skipped=true → REWIND.
// Pass 2: (1-2) — 1 visited 2 not, take. (0-1) — both visited, skip.
//   (2-3) — 2 visited 3 not, take. Done.
// Without the rewind, (1-2) would never be revisited.
static void case_mst_rewind(FILE *out) {
	reset();
	for (int i = 0; i < 4; i++) add_node(NM[i]);
	link_pair(&nodes[1], &nodes[2], 5, 5, 0, 0);   // edges 0,1
	link_pair(&nodes[0], &nodes[1], 10, 10, 0, 0); // edges 2,3
	link_pair(&nodes[2], &nodes[3], 15, 15, 0, 0); // edges 4,5
	myself = &nodes[0];
	sssp_bfs();  // sets visited for all (chain reachable from 0)
	emit_case("mst_rewind", out);
}

// Disconnected: two components. n0-n1 connected, n2-n3 connected,
// no path between. myself=n0. Tests reachable=false output and that
// MST only spans the reachable component.
static void case_disconnected(FILE *out) {
	reset();
	for (int i = 0; i < 4; i++) add_node(NM[i]);
	link_pair(&nodes[0], &nodes[1], 10, 10, 0, 0);
	link_pair(&nodes[2], &nodes[3], 10, 10, 0, 0);
	myself = &nodes[0];
	sssp_bfs();
	emit_case("disconnected", out);
}

// chain5, then cut the middle. Tests del_edge: n3/n4 become
// unreachable, MST shrinks to n0-n1-n2 only. Deletes both halves
// (the daemon's del_edge_h does too) so the post-state is clean.
static void case_chain_del(FILE *out) {
	reset();
	for (int i = 0; i < 5; i++) add_node(NM[i]);
	for (int i = 0; i < 4; i++) link_pair(&nodes[i], &nodes[i+1], 10, 10, 0, 0);
	myself = &nodes[0];
	sssp_bfs();
	// Edges 4,5 are the n2↔n3 pair (third link_pair call).
	int del[] = {4, 5};
	emit_case_del("chain5_del_mid", del, 2, out);
}

// Diamond: cut the cheap path. n3's nexthop must flip to n2.
// Tests that del_edge correctly removes from the per-node tree (so
// sssp doesn't see the dead edge) AND from edge_weight_tree (so MST
// doesn't pick it).
static void case_diamond_del(FILE *out) {
	reset();
	for (int i = 0; i < 4; i++) add_node(NM[i]);
	link_pair(&nodes[0], &nodes[1], 5, 5, 0, 0);   // 0,1: cheap
	link_pair(&nodes[0], &nodes[2], 50, 50, 0, 0); // 2,3: expensive
	link_pair(&nodes[1], &nodes[3], 10, 10, 0, 0); // 4,5
	link_pair(&nodes[2], &nodes[3], 10, 10, 0, 0); // 6,7
	myself = &nodes[0];
	sssp_bfs();
	// Kill 0↔1. n3 now reachable only via n2 (heavier).
	int del[] = {0, 1};
	emit_case_del("diamond_del_cheap", del, 2, out);
}

// Delete one half only. The twin is still in the trees but reverseless;
// sssp's `!e->reverse` check skips it. This is the transient state
// between the two DEL_EDGE messages arriving.
static void case_del_half(FILE *out) {
	reset();
	for (int i = 0; i < 3; i++) add_node(NM[i]);
	link_pair(&nodes[0], &nodes[1], 10, 10, 0, 0); // 0,1
	link_pair(&nodes[1], &nodes[2], 10, 10, 0, 0); // 2,3
	myself = &nodes[0];
	sssp_bfs();
	// Delete only 1→2 (edge 2). 2→1 (edge 3) survives reverseless.
	int del[] = {2};
	emit_case_del("del_half_reverseless", del, 1, out);
}

// Asymmetric weights. a→b weight 10, b→a weight 100. sssp_bfs uses the
// *outgoing* edge weight from each node; the reverse edge's weight is
// irrelevant to traversal (it's a separate edge). Tests that we
// don't accidentally average or pick the wrong direction.
static void case_asym_weight(FILE *out) {
	reset();
	for (int i = 0; i < 3; i++) add_node(NM[i]);
	link_pair(&nodes[0], &nodes[1], 10, 100, 0, 0);
	link_pair(&nodes[1], &nodes[2], 10, 100, 0, 0);
	myself = &nodes[0];
	sssp_bfs();
	emit_case("asym_weight", out);
}

// Random graphs. Seeded so the KAT JSON is reproducible.
static void case_random(int seed, FILE *out) {
	reset();
	rng_seed(seed);

	int nn = 4 + rng_u32() % (MAX_NODES - 4);
	for (int i = 0; i < nn; i++) add_node(NM[i]);

	// Ensure connectedness from n0 by chaining first, then add random.
	for (int i = 1; i < nn; i++) {
		int j = rng_u32() % i; // connect to some earlier node
		int w = 1 + rng_u32() % 100;
		uint32_t o = (rng_u32() % 8 == 0) ? OPTION_INDIRECT : 0;
		link_pair(&nodes[j], &nodes[i], w, w, o, o);
	}

	// Extra random edges. Avoid duplicates (splay_insert returns NULL
	// on dup, but we already incremented n_edges by then — messy).
	int extra = rng_u32() % (MAX_EDGES / 4);
	for (int k = 0; k < extra && n_edges + 2 <= MAX_EDGES; k++) {
		int a = rng_u32() % nn, b = rng_u32() % nn;
		if (a == b) continue;
		// Dup check: lookup in a's edge_tree.
		edge_t probe = { .to = &nodes[b] };
		if (splay_search(&nodes[a].edge_tree, &probe)) continue;
		int w = 1 + rng_u32() % 100;
		uint32_t o = (rng_u32() % 8 == 0) ? OPTION_INDIRECT : 0;
		link_pair(&nodes[a], &nodes[b], w, w, o, o);
	}

	myself = &nodes[0];
	sssp_bfs();

	char nm[32];
	snprintf(nm, sizeof nm, "random_%d", seed);
	emit_case(nm, out);
}

int main(void) {
	FILE *out = stdout;
	fprintf(out, "[\n");

	case_singleton(out);    fprintf(out, ",\n");
	case_chain(out);        fprintf(out, ",\n");
	case_diamond_weight(out);   fprintf(out, ",\n");
	case_diamond_indirect(out); fprintf(out, ",\n");
	case_oneway(out);       fprintf(out, ",\n");
	case_mst_rewind(out);   fprintf(out, ",\n");
	case_disconnected(out); fprintf(out, ",\n");
	case_asym_weight(out);  fprintf(out, ",\n");
	case_chain_del(out);    fprintf(out, ",\n");
	case_diamond_del(out);  fprintf(out, ",\n");
	case_del_half(out);     fprintf(out, ",\n");

	for (int s = 1; s <= 10; s++) {
		case_random(s, out);
		if (s < 10) fprintf(out, ",\n");
	}

	fprintf(out, "\n]\n");
	return 0;
}
