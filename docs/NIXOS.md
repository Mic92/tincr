# NixOS module: `services.tincr`

The flake exports `nixosModules.tincr`. Wires tincd as a Type=notify
service with socket activation, hands the interface to systemd-networkd
(TUN pre-created with `TUNSETOWNER=tincr`, no `CAP_NET_ADMIN` needed),
and optionally hooks the in-mesh DNS stub into systemd-resolved.

## Minimal config

```nix
{
  inputs.tincr.url = "github:Mic92/tincr";

  outputs = { self, nixpkgs, tincr, ... }: {
    nixosConfigurations.alpha = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        tincr.nixosModules.tincr
        {
          services.tincr.networks.mesh = {
            ed25519PrivateKeyFile = "/var/lib/tincr/mesh/ed25519_key.priv";
            addresses = [ "10.21.0.1/16" ];
            connectTo = [ "beta" ];
            openFirewall = true;
            hosts = {
              alpha = ''
                Subnet = 10.21.0.1/32
                Ed25519PublicKey = ...
              '';
              beta = ''
                Address = beta.example.com
                Subnet = 10.21.0.2/32
                Ed25519PublicKey = ...
              '';
            };
          };
        }
      ];
    };
  };
}
```

The Ed25519 key is **stateful**: the module never generates it. Drop
the bytes at `ed25519PrivateKeyFile` (mode `0400`, owner `tincr`)
before the unit starts. Bootstrap on a fresh host:

```sh
install -d -m 0700 -o tincr -g tincr /var/lib/tincr/mesh
sudo -u tincr tincd -n mesh -K ed25519
```

## In-mesh DNS

Set `dns.enable` and pick an address inside the network's prefix:

```nix
services.tincr.networks.mesh = {
  addresses = [ "10.21.0.1/16" ];
  dns = {
    enable = true;
    suffix = "mesh";
    address4 = "10.21.0.53";
  };
};
```

The module turns on `services.resolved` and routes `*.mesh` queries
to the daemon over the tunnel. `dig beta.mesh` from any mesh member
returns beta's tinc IP without `/etc/hosts` plumbing. Background +
other resolver integrations: [DNS.md](DNS.md).

## Multiple networks

`services.tincr.networks` is `attrsOf`. Each name becomes the
confbase under `/etc/tinc/`. `listenPort` defaults to 655; override
when running more than one network:

```nix
services.tincr.networks = {
  mesh    = { listenPort = 655; ed25519PrivateKeyFile = ...; };
  staging = { listenPort = 656; ed25519PrivateKeyFile = ...; };
};
```

## What the module doesn't do

Operator-driven, not declared: private keys, peer invitations
(`tinc -n <net> invite`), and joining (`tinc -n <net> join <url>`).
Set `socketActivation = false` to pin the daemon to
`multi-user.target` instead of starting on the first inbound SYN.
