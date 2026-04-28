# Quickstart

Two machines on a mesh in five minutes, then a third one behind NAT
that finds them via the DHT alone.

All commands assume the `tincd` package from this repo is on `PATH`
(it ships `tincd`, `tinc`, `tinc-dht-seed`, `tinc-auth`,
`sptps_keypair`). Everything that touches `/etc/tinc` or `/dev/net/tun`
needs root; prefix with `sudo` or run from a root shell.

## Pick a netname and address range

- netname: `myvpn` (config lives in `/etc/tinc/myvpn`)
- VPN range: `10.20.0.0/24`
- node `alpha` → `10.20.0.1`, public address `203.0.113.10`
- node `beta` → `10.20.0.2`

## Node alpha

```sh
tinc -n myvpn init alpha
tinc -n myvpn add DeviceType tun
tinc -n myvpn add Interface myvpn
tinc -n myvpn add Subnet 10.20.0.1
tinc -n myvpn add Address 203.0.113.10     # alpha's reachable address
```

> `DeviceType` is required: tincr defaults to a **dummy** device (so
> tests can run unprivileged). Without it the daemon starts, peers
> connect, and no packets flow. `Interface = myvpn` pins the kernel
> ifname; otherwise you get `tun0`/`tun1`/….

`init` wrote a stub `tinc-up`; make it bring the interface up:

```sh
tinc -n myvpn edit tinc-up
```

```sh
#!/bin/sh
ip link set dev $INTERFACE up
ip addr add 10.20.0.1/24 dev $INTERFACE
```

The address is alpha's own VPN IP; the `/24` is the *whole* VPN range
so the kernel routes every `10.20.0.0/24` packet into the TUN.

## Node beta

```sh
tinc -n myvpn init beta
tinc -n myvpn add DeviceType tun
tinc -n myvpn add Interface myvpn
tinc -n myvpn add Subnet 10.20.0.2
tinc -n myvpn add ConnectTo alpha
tinc -n myvpn edit tinc-up               # ip addr add 10.20.0.2/24 dev $INTERFACE
```

## Exchange host files

Each node needs the other's `hosts/NAME` (public key + Subnet +
Address). `export` prints it, `import` reads it from stdin:

```sh
# on alpha
tinc -n myvpn export | ssh root@beta tinc -n myvpn import

# on beta
tinc -n myvpn export | ssh root@alpha tinc -n myvpn import
```

(or `tinc -n myvpn exchange` over a single bidirectional pipe, or
`tinc -n myvpn invite beta` / `tinc -n myvpn join URL` if you'd rather
not copy files at all.)

## Start and verify

Open TCP+UDP **655** on alpha (the side with `Address`) — see
[FIREWALL.md](FIREWALL.md) for nftables/iptables/firewalld/ufw/NixOS
recipes. Then:

```sh
# both nodes, foreground with logs
tincd -n myvpn -D

# from beta
ping -c3 10.20.0.1

# inspect
tinc -n myvpn dump nodes
tinc -n myvpn dump edges
tinc -n myvpn info alpha
```

Under systemd use the instanced unit instead of running `tincd`
directly; see [OPERATING.md](OPERATING.md).

## Third node via DHT discovery (no `Address=`)

`carol` sits behind NAT, has never heard alpha's IP, and joins
anyway. This is the path `nix/nixos-test-dht.nix` exercises end to
end.

1. Generate a 32-byte mesh secret once and distribute it out-of-band to every node:

   ```sh
   head -c32 /dev/urandom > /etc/tinc/myvpn/dht.secret
   chmod 600 /etc/tinc/myvpn/dht.secret
   ```

1. On **every** node (alpha, beta, carol), enable discovery:

   ```sh
   tinc -n myvpn add DhtDiscovery yes
   tinc -n myvpn add DhtSecretFile dht.secret
   tinc -n myvpn add UPnP yes        # optional: ask the router for a port map
   ```

   Then **restart** `tincd` (DHT and `DhtSecretFile` are read once at
   startup; `tinc reload` does not enable them).

   With no `DhtBootstrap` lines the daemon dials the public mainline
   bootstrap list and persists its routing table to
   `$STATE_DIRECTORY/dht_nodes` for warm restart. Records are
   published under a daily key-blinded Ed25519 key and
   XChaCha20-Poly1305-sealed with a key derived from
   `(node-pubkey, day, dht.secret)`, so a DHT crawler sees only
   opaque blobs.

1. On **carol**:

   ```sh
   tinc -n myvpn init carol
   tinc -n myvpn add DeviceType tun
   tinc -n myvpn add Interface myvpn
   tinc -n myvpn add Subnet 10.20.0.3
   tinc -n myvpn add ConnectTo alpha          # name only — no Address for alpha
   tinc -n myvpn add DhtDiscovery yes
   tinc -n myvpn add DhtSecretFile dht.secret
   tinc -n myvpn edit tinc-up                 # ip addr add 10.20.0.3/24 …
   ```

   Import alpha's host file (carol needs alpha's *pubkey*, nothing
   else), then start:

   ```sh
   ssh root@alpha tinc -n myvpn export | tinc -n myvpn import
   tincd -n myvpn -D
   ```

   The first outgoing attempt logs
   `Could not set up a meta connection to alpha` (the address cache
   is empty), the retry queues a DHT resolve, and within ~30 s:

   ```
   DHT resolved alpha: tcp=203.0.113.10:655 …
   Connection with alpha activated
   ```

   You can also drop `ConnectTo` entirely and set `AutoConnect = yes`
   instead — with `DhtDiscovery` on, AutoConnect will pick any node
   whose `hosts/NAME` has an `Ed25519PublicKey`, resolve it, and
   dial. That is the `dave` scenario in the NixOS test: a node whose
   `hosts/` directory contains *only pubkeys* still joins the mesh.

1. Debugging a record by hand:

   ```sh
   tinc-dht-seed --resolve --secret-file /etc/tinc/myvpn/dht.secret \
       "$(tinc -n myvpn get alpha.Ed25519PublicKey)"
   # → tinc1 v4=203.0.113.10:655 tcp=203.0.113.10:655 v6=[…]:655
   ```

## NixOS

Use the flake's own `services.tincr` module — socket activation,
networkd-owned TUN, and optional resolved hookup are wired for
you. See [NIXOS.md](NIXOS.md).
