# Test fixtures, not secrets. Generated with `sptps_keypair` — the PEM
# body is tinc's non-standard b64 (LSB-first, see tinc-crypto/b64.rs);
# `openssl genpkey` output would not parse. No RSA; we're SPTPS-only.
{
  alpha = {
    ed25519Private = ''
      -----BEGIN ED25519 PRIVATE KEY-----
      Q7SwvJjSNPky+xztEfL3OsEqTcG60bBLkAkSJpwPrD0c7n4RhKTdxmJvj8QyCyVs
      woZc0tJ91FQdxanDkPOm7/aPJcHhlTil4FOeI5Dtn0MWeVsvCGr647NYSG46pSru
      -----END ED25519 PRIVATE KEY-----
    '';
    ed25519Public = "v2TC3RY5kYJehjHS+Q7JNjlXF7rgxqO+eDmkBueq0qL";
  };
  beta = {
    ed25519Private = ''
      -----BEGIN ED25519 PRIVATE KEY-----
      IOUjqk2w412nqhC5JgJGwvm66jxzLohdLdWrH/1jPrWxEyl/HXmVdfnR7YREhtWx
      g80y4bJBRu5oUE9GPpm/ujBinF0y8/QrQlWJdB8FXvESxwxzLof5BYwrIGhvfb8v
      -----END ED25519 PRIVATE KEY-----
    '';
    ed25519Public = "Yg4ZBtM/P0KUpVSXAfx1LhUMc88C6XeAG8KiR473G/L";
  };
}
