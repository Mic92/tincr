# Quickstart

This guide connects two machines into a mesh.

All commands assume the `tincd` package from this repo is on `PATH`
(it ships `tincd`, `tinc`, `tinc-auth`,
`sptps_keypair`). Everything that touches `/etc/tinc` or
`/dev/net/tun` needs root. Prefix the commands with `sudo` or run
them from a root shell.

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
> tests can run unprivileged). Without it the daemon starts and peers
> connect, but no packets flow. `Interface = myvpn` pins the kernel
> interface name. Without it you get `tun0`/`tun1`/….

`init` wrote a stub `tinc-up` script. Edit it so it brings the
interface up:

```sh
tinc -n myvpn edit tinc-up
```

```sh
#!/bin/sh
ip link set dev $INTERFACE up
ip addr add 10.20.0.1/24 dev $INTERFACE
```

The address is alpha's own VPN IP. The `/24` is the *whole* VPN
range, so the kernel routes every `10.20.0.0/24` packet into the
TUN device.

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

Each node needs the other's `hosts/NAME` file, which carries the
public key, `Subnet`, and `Address`. `export` prints the local one,
`import` reads one from stdin:

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

Open TCP+UDP port **655** in alpha's firewall (the side with
`Address`). [FIREWALL.md](FIREWALL.md) has recipes for
nftables/iptables/firewalld/ufw/NixOS. Then:

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
directly. See [OPERATING.md](OPERATING.md).

## NixOS

Use the flake's own `services.tincr` module. It wires up socket
activation, a networkd-owned TUN device, and (optionally)
systemd-resolved for you. See [NIXOS.md](NIXOS.md).
