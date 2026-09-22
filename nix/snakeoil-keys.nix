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
  # Third node for the NAT-punch test (nix/nixos-test-nat.nix). Generated
  # the same way: `target/debug/sptps_keypair gamma.priv gamma.pub`.
  gamma = {
    ed25519Private = ''
      -----BEGIN ED25519 PRIVATE KEY-----
      Y8246pHi8M3xbxs+74VGSFbxgVeI837vYXbYaT9bNNk+G7pizKbn9FYiXSmceHfz
      dYdOLtXZzZcxDuhCndzcVgHRKq/NWHEnKPsAp4Q+6H40DWAYvm22kIrQgQlpprOx
      -----END ED25519 PRIVATE KEY-----
    '';
    ed25519Public = "4Rki6fj1BxpyDLQKOkv+BO9gFA2rptNJyKEIUZa6qTM";
  };
  # Fourth node: the tinc-pre peer in the SPTPS-fallback test
  # (nix/nixos-test-sptps-fallback.nix). Its host file is written by
  # hand there, so tinc-pre never has to generate this keypair itself.
  pre = {
    ed25519Private = ''
      -----BEGIN ED25519 PRIVATE KEY-----
      Yb8KT89r8bztR1IYKvznj2T0MKwUTlXNc38erxE8manpVhcIi0JIIXwtCSkvA/v9
      izqTVatlpQy2WE/wG71YyvRSGWcY6KTEJ+iGriczOZLd85Mr6KSpI/kw/J0M9Lyo
      -----END ED25519 PRIVATE KEY-----
    '';
    ed25519Public = "bkkhFHmuyERivoxqI3sT2SHfOzquiUKyPJ8fCNT/iMK";
  };
  # Fifth node: the tinc 1.0.37 peer in the SPTPS-fallback test. 1.0
  # never reads Ed25519, but the upstream module writes the key line
  # unconditionally, so give it a real key instead of an empty file.
  stable = {
    ed25519Private = ''
      -----BEGIN ED25519 PRIVATE KEY-----
      gEzOlcd/ed82KQfsbX6q3rPrU0ICgIRHuJtKWzGu7dVHQFk4gQncutezFt8Zo9Yd
      60GPcMJD+9yISIXnAn35MaAuSRnk8qf+K6YdWwvLDApWqKdeoms95DHb/weNCJiA
      -----END ED25519 PRIVATE KEY-----
    '';
    ed25519Public = "GgrU0JJv6nviOWnF87yAQqlqSnHqJbf+wx2PsXjQiIA";
  };
}
