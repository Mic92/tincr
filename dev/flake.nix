# Development-only inputs. The root flake loads this through flake-compat
# so that consumers of tincr lock nothing but nixpkgs and crane.
# Update with `nix flake update --flake ./dev`.
{
  inputs = {
    treefmt-nix.url = "github:numtide/treefmt-nix";
    treefmt-nix.inputs.nixpkgs.follows = "";
    fenix.url = "github:nix-community/fenix";
    fenix.inputs.nixpkgs.follows = "";
    nixbot.url = "github:Mic92/nixbot";
    nixbot.inputs.nixpkgs.follows = "";
    nixbot.inputs.treefmt-nix.follows = "treefmt-nix";
  };

  outputs = inputs: inputs;
}
