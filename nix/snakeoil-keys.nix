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
  # Tier-2b cold-start node (nix/nixos-test-dht.nix). carol's hosts/relay
  # has the pubkey but NO Address= — she can only reach relay if the
  # DHT tells her where it is.
  delta = {
    ed25519Private = ''
      -----BEGIN ED25519 PRIVATE KEY-----
      wVO2JOA/dKa8iqZ/3ySLQUlGnilMeDT+fHU2gfITzc2ATRXOf2Tak2ov7CeOML4G
      bI7DWHnvEXRy49JpMgRftp7Bfmoz6U/a+M37azWDiEc5HXL1huyQj90qbafyaOOb
      -----END ED25519 PRIVATE KEY-----
    '';
    ed25519Public = "6ewnJ6sO1vmPz9u2s1gIBX+x1SdorM0YPt6m2nsmjzG";
  };
  # DHT-only bootstrap node (nix/nixos-test-dht.nix). dave has NO
  # ConnectTo and his hosts/* carry pubkeys only — AutoConnect must
  # pick a candidate on `has_dht_key` alone, then DHT-resolve it.
  epsilon = {
    ed25519Private = ''
      -----BEGIN ED25519 PRIVATE KEY-----
      4o7YUNSl6riz+9f4B7/pEK5LiSk0Udj7jDxTyJQlycnM7XG4DUsGP3XFZrwd1TsB
      XtGXHqVfWHZWUUpXKbwegsNROaJhaUEi7uyTxs/iWAcjmHHbJDNheI+vcgrXR8qZ
      -----END ED25519 PRIVATE KEY-----
    '';
    ed25519Public = "bTkjWSoGFh4ur8UM7voFA3o5xxWyQToHi/LH46VEvaG";
  };
}
