/*
 * KAT vector generator for inet_checksum (route.c:63-86).
 *
 * Unlike the crypto KAT, this is trivial: one static function copy-
 * pasted verbatim, six fixed inputs, JSON out. No -include shim, no
 * source linking. Standalone TU.
 *
 * IMPORTANT: the C does `memcpy(&word, data, 2)` — a NATIVE-endian
 * u16 load. So the numeric checksum value depends on host endianness.
 * RFC 1071 §2(B) proves the sum is byte-order independent *as bytes
 * on the wire*, but the u16 we print here is the host-order number.
 * The Rust port must use from_ne_bytes (not from_be_bytes) to match.
 * Both sides of the KAT run on the same builder; that's what pins it.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

/* ─── verbatim from src/route.c:63-86 ─────────────────────────────── */

static uint16_t inet_checksum(void *vdata, size_t len, uint16_t prevsum) {
	uint8_t *data = vdata;
	uint16_t word;
	uint32_t checksum = prevsum ^ 0xFFFF;

	while(len >= 2) {
		memcpy(&word, data, sizeof(word));
		checksum += word;
		data += 2;
		len -= 2;
	}

	if(len) {
		checksum += *data;
	}

	while(checksum >> 16) {
		checksum = (checksum & 0xFFFF) + (checksum >> 16);
	}

	return (uint16_t) ~checksum;
}

/* ─── JSON emission ───────────────────────────────────────────────── */

static void emit_hex(const uint8_t *p, size_t n) {
	for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
}

static void emit_case(const char *name, const uint8_t *data, size_t len,
                      uint16_t prevsum, bool last) {
	uint16_t out = inet_checksum((void *)data, len, prevsum);
	printf("    {\"name\": \"%s\", \"data\": \"", name);
	emit_hex(data, len);
	printf("\", \"prevsum\": %u, \"checksum\": %u}%s\n",
	       (unsigned)prevsum, (unsigned)out, last ? "" : ",");
}

int main(void) {
	printf("{\n  \"inet_checksum\": [\n");

	/* 1. zero-length, init prevsum=0xFFFF: ~0 = 0xFFFF, ^0xFFFF = 0,
	   no folding, ~0 = 0xFFFF. */
	emit_case("empty", (const uint8_t *)"", 0, 0xFFFF, false);

	/* 2. RFC 1071 §3 worked example. On LE host: 0x0d22. */
	static const uint8_t rfc1071[] = {
		0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7
	};
	emit_case("rfc1071_example", rfc1071, sizeof(rfc1071), 0xFFFF, false);

	/* 3. Single odd byte. Tail path: checksum += *data (low half). */
	static const uint8_t one[] = {0xab};
	emit_case("single_byte", one, sizeof(one), 0xFFFF, false);

	/* 4. Odd length (3 bytes): one word + one tail. */
	static const uint8_t three[] = {0x12, 0x34, 0x56};
	emit_case("odd_length_3", three, sizeof(three), 0xFFFF, false);

	/* 5. Real IPv4 header, 20 bytes, ip_sum field zeroed. This is
	   what route.c:202 does: ip.ip_sum = inet_checksum(&ip, 20, ~0).
	   45 00 00 73 00 00 40 00 40 11 [00 00] c0 a8 00 01 c0 a8 00 c7
	   = v4 ihl5, len 115, DF, ttl 64, UDP, 192.168.0.1→192.168.0.199 */
	static const uint8_t iphdr[] = {
		0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01,
		0xc0, 0xa8, 0x00, 0xc7
	};
	emit_case("ipv4_header_zeroed_sum", iphdr, sizeof(iphdr), 0xFFFF, false);

	/* 6. Chained call. route.c:207-208 does this for ICMP: checksum
	   the icmp header, then chain in the payload by passing the
	   previous result as prevsum. We split the RFC 1071 input. */
	uint16_t mid = inet_checksum((void *)rfc1071, 4, 0xFFFF);
	emit_case("chain_first_half", rfc1071, 4, 0xFFFF, false);
	emit_case("chain_second_half", rfc1071 + 4, 4, mid, false);

	/* 7. All ones — exercises the carry fold loop multiply. */
	static const uint8_t ones[8] = {0xff, 0xff, 0xff, 0xff,
	                                0xff, 0xff, 0xff, 0xff};
	emit_case("all_ones_8", ones, sizeof(ones), 0xFFFF, true);

	printf("  ]\n}\n");
	return 0;
}
