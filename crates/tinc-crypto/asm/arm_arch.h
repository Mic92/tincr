/* Minimal stand-in for OpenSSL's crypto/arm_arch.h, just enough to
 * assemble poly1305-armv8.S in isolation. The full header carries CPU
 * model IDs and a dozen capability bits; the Poly1305 kernel only
 * touches ARMV7_NEON and the BTI/PAC hint macros. */
#ifndef TINC_ARM_ARCH_H
#define TINC_ARM_ARCH_H

#define ARMV7_NEON (1 << 0)

#ifndef __ASSEMBLER__
/* Runtime capability word read by poly1305_init to choose between the
 * scalar and NEON code paths. Defined in poly1305_glue.c. */
extern unsigned int OPENSSL_armcap_P;
#endif

/* BTI / pointer-auth hints. Real OpenSSL gates these on
 * __ARM_FEATURE_BTI_DEFAULT / __ARM_FEATURE_PAC_DEFAULT; we don't build
 * with -mbranch-protection so the no-op forms are correct (and `hint`
 * encodings are NOPs on cores without the extension anyway). */
#define AARCH64_VALID_CALL_TARGET
#define AARCH64_SIGN_LINK_REGISTER
#define AARCH64_VALIDATE_LINK_REGISTER

#endif /* TINC_ARM_ARCH_H */
