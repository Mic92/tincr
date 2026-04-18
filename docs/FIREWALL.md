# Firewall

tincd listens on one port (default **655**) for both the TCP meta
protocol and the UDP data channel. Open both on every node that
should accept inbound connections; nodes that only dial out
(`ConnectTo` behind NAT) can stay closed and rely on conntrack.

If you changed `Port` in `tinc.conf` / `hosts/NAME`, substitute that
number everywhere below.

The DHT client and the UPnP/PCP port-mapper use outbound UDP only;
their replies are accepted by the `ct state established` rule every
stateful firewall already has — no extra inbound rule needed.

## nftables

```sh
nft add rule inet filter input tcp dport 655 accept
nft add rule inet filter input udp dport 655 accept
```

Persisted (`/etc/nftables.conf` or a drop-in):

```nft
table inet filter {
  chain input {
    tcp dport 655 accept
    udp dport 655 accept
  }
}
```

## iptables / ip6tables

```sh
iptables  -A INPUT -p tcp --dport 655 -j ACCEPT
iptables  -A INPUT -p udp --dport 655 -j ACCEPT
ip6tables -A INPUT -p tcp --dport 655 -j ACCEPT
ip6tables -A INPUT -p udp --dport 655 -j ACCEPT
```

## firewalld

```sh
firewall-cmd --permanent --add-port=655/tcp
firewall-cmd --permanent --add-port=655/udp
firewall-cmd --reload
```

## ufw

```sh
ufw allow 655/tcp
ufw allow 655/udp
```

## NixOS

```nix
networking.firewall.allowedTCPPorts = [ 655 ];
networking.firewall.allowedUDPPorts = [ 655 ];
```

## Behind a NAT router

Either forward TCP+UDP 655 to the node manually, or set `UPnP = yes`
in `tinc.conf` and let the daemon ask the router via PCP / NAT-PMP /
UPnP-IGD. The mapped external address is logged as
`Portmapped Tcp 655 → EXT_IP:EXT_PORT` and, with `DhtDiscovery`
enabled, published in the node's DHT record so peers dial it
directly.

## Traffic *inside* the tunnel

The rules above admit the encrypted transport. Packets that come
*out* of the TUN interface are a separate policy decision — on a
default-drop `FORWARD`/`INPUT` host you also need, e.g.:

```sh
nft add rule inet filter input iifname "myvpn" accept
```

(or the equivalent `networking.firewall.trustedInterfaces` on NixOS).
