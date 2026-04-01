/*
 * Verbatim copy of b64encode_tinc / b64decode_tinc from src/utils.c.
 *
 * Why a copy: utils.c drags in logger.h, xalloc.h, and a bunch of unrelated
 * helpers. The b64 functions themselves are pure and self-contained, so we
 * extract just those ~100 lines rather than stub half the codebase.
 *
 * IMPORTANT: This is tinc's *non-standard* base64. Differences from RFC 4648:
 *
 *   1. Bit order is LSB-first within each 3-byte group:
 *        RFC 4648:  triplet = b[0]<<16 | b[1]<<8 | b[2], emit top 6 bits first
 *        tinc:      triplet = b[0] | b[1]<<8 | b[2]<<16, emit low 6 bits first
 *      Consequence: tinc-b64("foo") != RFC-b64("foo"). Different *string*.
 *
 *   2. Decoder accepts both standard ('+','/') and URL-safe ('-','_')
 *      simultaneously, and even mixed within the same string. The encode
 *      side picks one alphabet, but decode is permissive.
 *
 *   3. No '=' padding, ever. Encoder doesn't emit it; decoder treats '='
 *      as -1 (invalid) which makes the high-bit check fire and return 0.
 *
 * Keep this file in sync with src/utils.c if upstream changes (unlikely;
 * this format is wire-protocol-locked).
 */

#include <stdint.h>
#include <stddef.h>

static const char base64_original[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char base64_urlsafe[]  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/* Decode table: '+' and '-' both map to 62; '/' and '_' both to 63. */
static const signed char base64_decode[256] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, 62, -1, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
	-1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, 63,
	-1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

size_t b64decode_tinc(const char *src, void *dst, size_t length) {
	size_t i;
	uint32_t triplet = 0;
	unsigned char *udst = (unsigned char *)dst;

	for(i = 0; i < length && src[i]; i++) {
		triplet |= (uint32_t)(base64_decode[src[i] & 0xff] << (6 * (i & 3)));

		if((i & 3) == 3) {
			if(triplet & 0xff000000U) {
				return 0;
			}

			udst[0] = triplet & 0xff;
			triplet >>= 8;
			udst[1] = triplet & 0xff;
			triplet >>= 8;
			udst[2] = triplet;
			triplet = 0;
			udst += 3;
		}
	}

	if(triplet & 0xff000000U) {
		return 0;
	}

	if((i & 3) == 3) {
		udst[0] = triplet & 0xff;
		triplet >>= 8;
		udst[1] = triplet & 0xff;
		return i / 4 * 3 + 2;
	} else if((i & 3) == 2) {
		udst[0] = triplet & 0xff;
		return i / 4 * 3 + 1;
	} else {
		return i / 4 * 3;
	}
}

static size_t b64encode_internal(const void *src, char *dst, size_t length, const char *alphabet) {
	uint32_t triplet;
	const unsigned char *usrc = (unsigned char *)src;
	size_t si = length / 3 * 3;
	size_t di = length / 3 * 4;

	switch(length % 3) {
	case 2:
		triplet = usrc[si] | usrc[si + 1] << 8;
		dst[di] = alphabet[triplet & 63];
		triplet >>= 6;
		dst[di + 1] = alphabet[triplet & 63];
		triplet >>= 6;
		dst[di + 2] = alphabet[triplet];
		dst[di + 3] = 0;
		length = di + 3;
		break;

	case 1:
		triplet = usrc[si];
		dst[di] = alphabet[triplet & 63];
		triplet >>= 6;
		dst[di + 1] = alphabet[triplet];
		dst[di + 2] = 0;
		length = di + 2;
		break;

	default:
		dst[di] = 0;
		length = di;
		break;
	}

	while(si > 0) {
		di -= 4;
		si -= 3;
		triplet = usrc[si] | usrc[si + 1] << 8 | usrc[si + 2] << 16;
		dst[di] = alphabet[triplet & 63];
		triplet >>= 6;
		dst[di + 1] = alphabet[triplet & 63];
		triplet >>= 6;
		dst[di + 2] = alphabet[triplet & 63];
		triplet >>= 6;
		dst[di + 3] = alphabet[triplet];
	}

	return length;
}

size_t b64encode_tinc(const void *src, char *dst, size_t length) {
	return b64encode_internal(src, dst, length, base64_original);
}

size_t b64encode_tinc_urlsafe(const void *src, char *dst, size_t length) {
	return b64encode_internal(src, dst, length, base64_urlsafe);
}
