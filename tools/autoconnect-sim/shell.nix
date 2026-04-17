{
  pkgs ? import <nixpkgs> { },
}:
pkgs.mkShell {
  packages = [
    (pkgs.python3.withPackages (
      p: with p; [
        networkx
        numpy
      ]
    ))
    pkgs.ruff
    pkgs.mypy
  ];
}
