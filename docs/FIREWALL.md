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

### Enabling UPnP/PCP on the router

tincd tries PCP first (most modern firmware answers it on the same
NAT-PMP socket), then falls back to SSDP/UPnP-IGD. The router-side
switch is usually one checkbox; vendor names vary:

| Router | Where | Notes |
|---|---|---|
| AVM Fritz!Box | Internet → Permit Access → Port Sharing → per-device **Permit independent port sharing** | Speaks PCP (v4+v6), not NAT-PMP — the reason tincr is PCP-first. |
| OpenWrt | `opkg install luci-app-upnp` → Services → UPnP IGD & PCP → enable | miniupnpd; serves IGD, NAT-PMP and PCP off one socket. `secure_mode` is fine (tincd maps to its own LAN IP). |
| pfSense / OPNsense | Services → UPnP & NAT-PMP → Enable; set External=WAN, Internal=LAN | miniupnpd. Behind CGNAT enable STUN or set the override WAN address. |
| UniFi (UDM/UXG) | Network app → Settings → Internet (or Gateway) → UPnP → enable, select LAN networks | Off by default. |
| MikroTik RouterOS | IP → UPnP → Enabled; add Interfaces: WAN=external, LAN=internal | CLI: `/ip upnp set enabled=yes`; `/ip upnp interfaces add interface=ether1 type=external` etc. |
| ASUS (stock/Merlin) | Advanced Settings → WAN → Internet Connection → **Enable UPnP** | AiProtection's "router security" scan flags UPnP as a risk; that toggle is advisory, the WAN page is the actual switch. |
| TP-Link Archer/Deco | Advanced → NAT Forwarding → UPnP (Deco: app → More → Advanced → NAT Forwarding) | Usually on by default. |

If the router is itself behind CGNAT, the mapped address is still
RFC1918 and unhelpful to peers on the public internet; tincd publishes
it anyway (lab/LAN meshes use it), and the receiving side filters
unroutable hints.

## Traffic *inside* the tunnel

The rules above admit the encrypted transport. Packets that come
*out* of the TUN interface are a separate policy decision — on a
default-drop `FORWARD`/`INPUT` host you also need, e.g.:

```sh
nft add rule inet filter input iifname "myvpn" accept
```

(or the equivalent `networking.firewall.trustedInterfaces` on NixOS).
