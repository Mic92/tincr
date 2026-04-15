{
  projectRootFile = "flake.nix";
  programs = {
    rustfmt.enable = true;
    nixfmt.enable = true;
    # The C side stays under astyle (upstream's choice); don't
    # fight it from here.
  };
  settings.global.excludes = [
    "src/**" # upstream C, not ours to reformat
    "Cargo.lock"
    "*.json"
  ];
}
