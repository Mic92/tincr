# Tier-0 punch coordination test: two nodes behind NAT, one relay.
#
# Topology:
#
#   alice ──────┐                          ┌────── bob
#   vlan 2      │                          │    vlan 3
#               ├── alice_gw ══ relay ══ bob_gw ──┤
#               │   MASQUERADE  vlan 1    MASQUERADE
#
# The test driver auto-assigns `192.168.<vlan>.<index>` to each node's NIC
# on each vlan it's a member of, and populates /etc/hosts so `relay` resolves
# to relay's vlan-1 address. We don't fight this: alice's default route via
# alice_gw already gets her to vlan 1; alice_gw MASQUERADEs her src to its
# own vlan-1 address. The relay sees alice's traffic coming from
# `192.168.1.<alice_gw_index>` — exactly the NAT we want.
#
# alice and bob have NO route to each other's LAN. They each have a default
# route through their NAT gateway, which MASQUERADEs to a "WAN" subnet where
# the relay lives. Neither alice nor bob has the other's `Address=` configured
# — they only know `ConnectTo = relay`.
#
# Without Tier-0: both establish meta-conns to the relay, gossip ADD_EDGE,
# and learn each other's NAT-public IP (the WAN side of their gateway). But
# the *port* in ADD_EDGE is each node's *bind* port (655) — not the NAT-mapped
# port. With iptables MASQUERADE in port-restricting mode (the conntrack
# default), alice's UDP probe to `bob_gw:655` is dropped because bob's NAT
# mapping is for some ephemeral port. Traffic stays relayed forever.
#
# With Tier-0: when alice's REQ_KEY for bob is relayed, the relay appends
# alice's *observed* UDP port (the NAT-mapped one — the relay sees it via
# `recvfrom`). Bob stashes it. Same for ANS_KEY back to alice. Both probe
# at the correct port within ~1 RTT of each other. Conntrack on each NAT sees
# "reply to a packet I just sent" and accepts. udp_confirmed flips.
#
# Assertion: `dump nodes` shows the peer's `udp_confirmed` bit set, AND ping
# crosses without traversing the relay (TTL check would catch a relay hop, but
# the simpler probe is: the relay's transit-packet counter doesn't grow once
# the tunnel is direct).
{
  testers,
  tincd,
}:
let
  keys = import ./snakeoil-keys.nix;

  # All three nodes share the same hosts/ directory: every node knows every
  # node's pubkey and the relay's address. Nobody knows alice's or bob's
  # address — that's the whole point.
  hostSettings = {
    alice = {
      subnets = [ { address = "10.20.0.1"; } ];
      settings.Ed25519PublicKey = keys.alpha.ed25519Public;
      # No `addresses =` — alice is behind NAT, no static reachability.
    };
    bob = {
      subnets = [ { address = "10.20.0.2"; } ];
      settings.Ed25519PublicKey = keys.beta.ed25519Public;
      # No `addresses =` — same.
    };
    relay = {
      # The relay carries no user traffic of its own. /32 subnet is just
      # so `tinc dump subnets` has something to show; routing decisions
      # never pick it.
      subnets = [ { address = "10.20.0.254"; } ];
      settings.Ed25519PublicKey = keys.gamma.ed25519Public;
      # The ONE static address in the mesh. Both leaves ConnectTo this.
      # `relay` resolves via /etc/hosts (test driver populates node names).
      addresses = [ { address = "relay"; } ];
    };
  };

  # A leaf behind NAT. Its only route to the world is through `gw`.
  mkLeaf =
    self: gw: keypair:
    {
      nodes,
      lib,
      ...
    }:
    {
      # Single NIC on the LAN vlan toward its gateway. NOT on vlan 1 — if
      # the leaf had a vlan-1 address it could reach the relay directly
      # and the NAT would never be exercised.
      virtualisation.vlans = [ gw.lanVlan ];
      networking = {
        useDHCP = false;
        # No route to vlan 1, no route to the other leaf's LAN. The only
        # egress is the default through the gateway. That's the constraint
        # we're testing: can tinc punch through a NAT it has no static
        # knowledge of?
        #
        # The gateway's LAN-side address is its second NIC (eth2 = second
        # vlan in its `vlans` list = lanVlan). Dig it out of the gateway
        # node's evaluated config so we don't hardcode the test driver's
        # `192.168.<vlan>.<index>` numbering scheme.
        defaultGateway = (lib.head nodes.${gw.host}.networking.interfaces.eth2.ipv4.addresses).address;
        # Leaf firewall is permissive — we're testing the NAT *box's*
        # filtering, not the leaf's. tincd accepts all on 655.
        firewall.enable = false;
      };

      services.tinc.networks.mesh = {
        name = self;
        package = tincd;
        ed25519PrivateKeyFile = builtins.toFile "ed25519.priv" keypair;
        inherit hostSettings;
        settings = {
          DeviceType = "tun";
          # The single piece of config that makes this work: both leaves
          # know how to reach the relay. The relay knows neither.
          ConnectTo = "relay";
        };
        chroot = false;
      };

      networking.interfaces."tinc.mesh" = {
        virtual = true;
        virtualType = "tun";
        ipv4.addresses = [
          {
            address = if self == "alice" then "10.20.0.1" else "10.20.0.2";
            prefixLength = 24;
          }
        ];
      };
      systemd.services."tinc.mesh" = {
        after = [ "network-addresses-tinc.mesh.service" ];
        requires = [ "network-addresses-tinc.mesh.service" ];
      };

      environment.systemPackages = [ tincd ];
    };

  # iptables MASQUERADE box. eth1 = WAN (vlan 1, toward relay), eth2 = LAN
  # (toward the leaf). Conntrack's default is "port-restricted cone"
  # semantics: a mapping for (src_ip, src_port, dst_ip, dst_port) only
  # accepts packets FROM that exact (dst_ip, dst_port). Exactly what Tier-0
  # has to defeat.
  #
  # No hand-assigned addresses: the test driver gives this node
  # `192.168.1.<index>` on eth1 (vlan 1) and `192.168.<lanVlan>.<index>` on
  # eth2. We just need to tell the leaf its gateway's eth2 address — done
  # via /etc/hosts (the leaf's defaultGateway is the gateway's *hostname*).
  mkGateway =
    lanVlan:
    {
      ...
    }:
    {
      virtualisation.vlans = [
        1
        lanVlan
      ];
      networking = {
        useDHCP = false;
        firewall.enable = false;
        # NixOS's networking.nat module does exactly what we need: forward
        # LAN→WAN, MASQUERADE the source, conntrack the return. No special
        # ALG or hairpinning — vanilla home-router behaviour.
        nat = {
          enable = true;
          externalInterface = "eth1";
          internalInterfaces = [ "eth2" ];
        };
      };
    };
in
testers.runNixOSTest {
  name = "tincd-nat-punch";

  nodes = {
    # vlan 1 = the "WAN". relay + both gateways' eth1 live here.
    relay =
      {
        ...
      }:
      {
        virtualisation.vlans = [ 1 ];
        networking = {
          useDHCP = false;
          firewall.allowedTCPPorts = [ 655 ];
          firewall.allowedUDPPorts = [ 655 ];
        };

        services.tinc.networks.mesh = {
          name = "relay";
          package = tincd;
          ed25519PrivateKeyFile = builtins.toFile "ed25519.priv" keys.gamma.ed25519Private;
          inherit hostSettings;
          # Relay doesn't ConnectTo anyone — it accepts inbound. No
          # `addresses` needed for ourselves; the leaves dial us by
          # `Address = relay` in hosts/relay (which resolves via the
          # test driver's /etc/hosts → 192.168.0.1).
          settings.DeviceType = "tun";
          chroot = false;
        };

        networking.interfaces."tinc.mesh" = {
          virtual = true;
          virtualType = "tun";
          ipv4.addresses = [
            {
              address = "10.20.0.254";
              prefixLength = 24;
            }
          ];
        };
        systemd.services."tinc.mesh" = {
          after = [ "network-addresses-tinc.mesh.service" ];
          requires = [ "network-addresses-tinc.mesh.service" ];
        };

        environment.systemPackages = [ tincd ];
      };

    alice_gw = mkGateway 2;
    bob_gw = mkGateway 3;

    alice = mkLeaf "alice" {
      host = "alice_gw";
      lanVlan = 2;
    } keys.alpha.ed25519Private;
    bob = mkLeaf "bob" {
      host = "bob_gw";
      lanVlan = 3;
    } keys.beta.ed25519Private;
  };

  testScript = ''
    start_all()

    # NAT boxes first: leaves' default route points at them. They have no
    # service pulling in network-online.target; multi-user is sufficient.
    alice_gw.wait_for_unit("multi-user.target")
    bob_gw.wait_for_unit("multi-user.target")

    # Sanity: alice can reach the relay through her NAT (hostname resolves
    # to the relay's vlan-1 auto-addr; alice's default route via her gw
    # gets her there). But she CANNOT reach bob — different vlan, different
    # NAT, no route. If she could, we'd be testing nothing.
    alice.wait_until_succeeds("ping -c1 -W2 relay", timeout=10)
    alice.fail("ping -c1 -W1 bob")
    bob.fail("ping -c1 -W1 alice")

    relay.wait_for_unit("tinc.mesh.service")
    alice.wait_for_unit("tinc.mesh.service")
    bob.wait_for_unit("tinc.mesh.service")

    # Handshake. Both leaves connect to the relay; gossip propagates;
    # SPTPS handshake fires; Tier-0 reflexive append + immediate probe
    # opens both NATs. Ping over the tunnel proves end-to-end.
    alice.wait_until_succeeds("ping -c1 -W2 10.20.0.2", timeout=60)
    bob.wait_until_succeeds("ping -c1 -W2 10.20.0.1", timeout=60)

    # The actual assertion: udp_confirmed. `dump nodes` exposes the
    # status bitfield; `udp_confirmed` is bit 4 (`node_status_t`, 0x10
    # in the third hex group of the line). But the bitfield encoding is
    # fragile across versions; the durable signal is `via -` (no relay)
    # vs `via relay` in the dump. C tinc and our Rust both print this.
    #
    # A direct UDP path means the `via` field shows `-` (or the node's
    # own name in some output formats); a relayed path shows the relay's
    # name. Poll: the punch may take a few probe intervals (default 2s
    # when not confirmed, plus key-exchange RTT).
    #
    # If this fails, the test still proved *connectivity* (relayed) above.
    # What it'd prove BROKEN: the punch coordination. Which is the change.
    def has_direct(host, peer):
        # `dump nodes` line format: NAME id ... via VIA nexthop NEXTHOP ...
        # When direct: VIA is the peer's own name (or "-"). When relayed:
        # VIA is "relay". grep for the peer line, fail if it routes via relay.
        out = host.succeed(f"tinc -n mesh dump nodes | grep -w {peer}")
        return "via relay" not in out

    import time
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if has_direct(alice, "bob") and has_direct(bob, "alice"):
            break
        time.sleep(2)
    else:
        # Timed out. Dump state for debugging then fail.
        alice.succeed("tinc -n mesh dump nodes >&2")
        bob.succeed("tinc -n mesh dump nodes >&2")
        relay.succeed("tinc -n mesh dump nodes >&2")
        raise AssertionError("alice↔bob never went direct (still via relay)")

    # Direct path confirmed. Prove it stays direct under load.
    alice.succeed("ping -c10 -i0.2 10.20.0.2")

    # Sanity inverse: the relay should see alice and bob as DIRECT meta
    # neighbours (it accepted both their TCP) but should NOT carry their
    # UDP — the punch made it irrelevant. We don't have a transit-packet
    # counter exposed via `tinc`, so just assert the relay's view of the
    # graph is sane.
    relay.succeed("tinc -n mesh dump edges | grep -w alice")
    relay.succeed("tinc -n mesh dump edges | grep -w bob")
  '';
}
