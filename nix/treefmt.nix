{ pkgs, ... }:
{
  projectRootFile = "flake.nix";
  programs = {
    rustfmt.enable = true;
    # Rust port: unlike the GHC-based nixfmt it also evaluates on
    # platforms without a Haskell toolchain (riscv64).
    nixfmt.enable = true;
    nixfmt.package = pkgs.nixfmt-rs;
    # The C side stays under astyle (upstream's choice); don't
    # fight it from here.
  };
  settings.global.excludes = [
    "src/**" # upstream C, not ours to reformat
    "Cargo.lock"
    "*.json"
  ];
}
