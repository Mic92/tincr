/*
 * KAT vector generator for NodeId6 (node.c:125-128).
 *
 * node_add() does: sha512(n->name, strlen(n->name), buf) then
 * memcpy(&n->id, buf, 6). The 6-byte node ID is the SHA-512 prefix
 * of the node name bytes (no NUL terminator). This is the lookup key
 * for the UDP fast path (net_packet.c:617-633): every UDP packet is
 * prefixed [dst_id:6][src_id:6], receiver does HashMap lookup, falls
 * back to trial-decrypt on miss.
 *
 * We link the actual src/ed25519/sha512.c (LibTomCrypt). Standalone
 * TU otherwise. The display format (node.c:204-208) is %02x lowercase
 * with no separators — same as our hex emission.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "../tinc-c/src/ed25519/sha512.h"

static void emit_case(const char *name, bool last) {
	unsigned char buf[64];
	sha512(name, strlen(name), buf);
	/* node.c:128: memcpy(&n->id, buf, sizeof(n->id)) — first 6. */
	printf("    {\"name\": \"%s\", \"id\": \"", name);
	for (int i = 0; i < 6; i++) printf("%02x", buf[i]);
	printf("\"}%s\n", last ? "" : ",");
}

int main(void) {
	printf("{\"node_id\": [\n");
	emit_case("alice", false);
	emit_case("bob", false);
	emit_case("", false);
	emit_case("long_name_with_underscores_and_digits123", true);
	printf("]}\n");
	return 0;
}
