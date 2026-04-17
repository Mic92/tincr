# DHT discovery: port-probe through NAT + BEP 44 publish + cold-start
# resolve, against a 10-node seed swarm. Same NAT topology as
# nixos-test-nat.nix; separate test so a DHT regression doesn't mask
# a Tier-0 regression.
#
# alice/bob: NAT'd leaves, `DhtDiscovery=yes`. The port-probe goes
# from tincd's own socket through MASQUERADE; the published `v4=`
# carries the NAT-mapped (ip,port) for the *correct* fd.
#
# carol: `ConnectTo=relay` but her `hosts/relay` has only the pubkey
# (no `Address=`). Addr cache exhausts immediately → retry_outgoing
# fires a DHT resolve → connects. The cold-start path the unit test
# can't reach (config plumbing, not Discovery API).
#
# Seeds bootstrap to each other via `relay:PORT` (NOT 127.0.0.1):
# loopback inter-seed bootstrap puts loopback addrs in routing
# tables, so referrals to alice say `127.0.0.1:port` and alice's
# iterative query never drains. See tinc-dht-seed.rs.
{
  testers,
  tincd,
}:
let
  keys = import ./snakeoil-keys.nix;

  # 16881 ≠ mainline's DEFAULT_PORT (6881): relay's own tincd-
  # mainline-actor binds 6881-first-then-ephemeral, the seed binary
  # has no fallback. They race at boot; if tincd wins 6881 the swarm
  # dies. 10 = mainline's own convergence floor.
  dhtBase = 16881;
  dhtCount = 10;
  dhtPorts = builtins.genList (i: dhtBase + i) dhtCount;

  dhtBootstrapLines = builtins.concatStringsSep "\n" (
    map (p: "DhtBootstrap = relay:${toString p}") dhtPorts
  );

  hostSettings = {
    alice = {
      subnets = [ { address = "10.20.0.1"; } ];
      settings.Ed25519PublicKey = keys.alpha.ed25519Public;
    };
    bob = {
      subnets = [ { address = "10.20.0.2"; } ];
      settings.Ed25519PublicKey = keys.beta.ed25519Public;
    };
    relay = {
      subnets = [ { address = "10.20.0.254"; } ];
      settings.Ed25519PublicKey = keys.gamma.ed25519Public;
      addresses = [ { address = "relay"; } ];
    };
    carol = {
      subnets = [ { address = "10.20.0.3"; } ];
      settings.Ed25519PublicKey = keys.delta.ed25519Public;
    };
  };

  # carol's view: relay's pubkey but no `addresses`. All three addr-
  # cache tiers empty → next_addr()=None → retry_outgoing → DHT.
  hostSettingsCarol = hostSettings // {
    relay = builtins.removeAttrs hostSettings.relay [ "addresses" ];
  };

  mkLeaf =
    self: gw: keypair:
    {
      nodes,
      lib,
      ...
    }:
    {
      virtualisation.vlans = [ gw.lanVlan ];
      networking = {
        useDHCP = false;
        defaultGateway = (lib.head nodes.${gw.host}.networking.interfaces.eth2.ipv4.addresses).address;
        firewall.enable = false;
      };

      services.tinc.networks.mesh = {
        name = self;
        package = tincd;
        ed25519PrivateKeyFile = builtins.toFile "ed25519.priv" keypair;
        inherit hostSettings;
        settings = {
          DeviceType = "tun";
          ConnectTo = "relay";
        };
        # extraConfig: DhtDiscovery isn't in the nixpkgs module's
        # toTincConf whitelist. `relay` resolves via test-driver
        # /etc/hosts on mainline's actor thread.
        extraConfig = ''
          DhtDiscovery = yes
          UPnP = yes
          UPnPRefreshPeriod = 10
          ${dhtBootstrapLines}
        '';
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
        # nftables backend: the test VM kernel doesn't autoload
        # ip_tables (firewall is off), so the libiptc miniupnpd
        # build dies at iptc_init. The nixpkgs miniupnpd module
        # switches to the nft build when this is on; nat.enable
        # below also uses the nft path.
        nftables.enable = true;
        nat = {
          enable = true;
          externalInterface = "eth1";
          internalInterfaces = [ "eth2" ];
        };
      };
      # IGD + NAT-PMP/PCP on the LAN side. The leaf's portmapper
      # thread asks this for a DNAT to its :655; the resulting WAN
      # (ip,port) lands in the DHT record's `tcp=` field. The
      # nixpkgs module hooks the MINIUPNPD chains into the firewall
      # for us.
      services.miniupnpd = {
        enable = true;
        natpmp = true;
        externalInterface = "eth1";
        internalIPs = [ "eth2" ];
        # 192.168.1.x WAN is RFC1918; miniupnpd refuses to
        # forward by default in that case. secure_mode=no isn't
        # strictly needed (the leaf maps to its own LAN IP) but
        # avoids a class of test-only mismatches.
        appendConfig = ''
          ext_allow_private_ipv4=yes
          secure_mode=no
        '';
      };
    };
in
testers.runNixOSTest {
  name = "tincd-dht-discovery";

  nodes = {
    relay =
      {
        pkgs,
        ...
      }:
      {
        virtualisation.vlans = [ 1 ];
        networking = {
          useDHCP = false;
          firewall.allowedTCPPorts = [ 655 ];
          firewall.allowedUDPPorts = [ 655 ] ++ dhtPorts;
        };

        services.tinc.networks.mesh = {
          name = "relay";
          package = tincd;
          ed25519PrivateKeyFile = builtins.toFile "ed25519.priv" keys.gamma.ed25519Private;
          inherit hostSettings;
          settings.DeviceType = "tun";
          # relay publishes too (carol resolves THIS record). v6 from
          # enumerate_v6 (2001:db8:1::, in 2000::/3); carol same /64.
          extraConfig = ''
            DhtDiscovery = yes
            ${dhtBootstrapLines}
          '';
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

        # Type=simple: prints one line per bound node and parks.
        # Bind failure exits nonzero → unit `failed` → wait_for_unit
        # propagates. Cross-VM ordering is in the test script.
        systemd.services.dht-seed = {
          description = "Mainline DHT seed swarm (test fixture)";
          wantedBy = [ "multi-user.target" ];
          after = [ "network.target" ];
          serviceConfig = {
            Type = "simple";
            # `relay` = SELF_HOST: routing tables hold alice-reachable
            # referral addrs (hairpin via eth1). See header comment.
            ExecStart = "${tincd}/bin/tinc-dht-seed ${toString dhtBase} ${toString dhtCount} relay";
          };
        };

        environment.systemPackages = [
          tincd
          pkgs.netcat
        ];
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

    # Cold-start node. vlan-1 (no NAT, same wire as relay). Tests
    # the resolve path, not the punch path; alice/bob cover NAT.
    carol =
      { ... }:
      {
        virtualisation.vlans = [ 1 ];
        networking = {
          useDHCP = false;
          firewall.enable = false;
        };

        services.tinc.networks.mesh = {
          name = "carol";
          package = tincd;
          ed25519PrivateKeyFile = builtins.toFile "ed25519.priv" keys.delta.ed25519Private;
          hostSettings = hostSettingsCarol;
          settings = {
            DeviceType = "tun";
            ConnectTo = "relay";
          };
          extraConfig = ''
            DhtDiscovery = yes
            ${dhtBootstrapLines}
          '';
          chroot = false;
        };

        networking.interfaces."tinc.mesh" = {
          virtual = true;
          virtualType = "tun";
          ipv4.addresses = [
            {
              address = "10.20.0.3";
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
  };

  testScript = ''
    start_all()

    alice_gw.wait_for_unit("multi-user.target")
    bob_gw.wait_for_unit("multi-user.target")

    # systemd dependency edges don't span VMs; wait explicitly.
    relay.wait_for_unit("dht-seed.service")
    # Type=simple's Active doesn't prove the binds finished. Last
    # port's line ⇒ all bound (binary fails-fast before printing).
    # wait_for_open_port is TCP-only, useless here.
    relay.wait_until_succeeds(
        "journalctl -u dht-seed --no-pager | "
        "grep 'listening on 0.0.0.0:${toString (dhtBase + dhtCount - 1)}'",
        timeout=10,
    )

    relay.wait_for_unit("tinc.mesh.service")
    alice.wait_for_unit("tinc.mesh.service")
    bob.wait_for_unit("tinc.mesh.service")
    carol.wait_for_unit("tinc.mesh.service")

    # ─── Precondition: carol has nowhere to dial. If hosts/relay
    # accidentally has Address= (module merge surprise), she connects
    # first try and the gates below pass for the wrong reason.
    carol.succeed(
        "journalctl -u tinc.mesh --no-pager | "
        "grep 'Could not set up a meta connection to relay'"
    )

    # ─── Gate: config plumbing. Synchronous in setup(); not
    # waiting. Catches "field exists but config.lookup() doesn't".
    alice.succeed(
        "journalctl -u tinc.mesh --no-pager | "
        "grep 'DHT discovery enabled.*bootstrap: relay:${toString dhtBase}'"
    )

    # ─── Gate: BEP 42 vote through NAT. Appears at first periodic
    # tick (~5-10s). 192.168.1.* proves WAN-side (MASQUERADE'd), not
    # alice's LAN (192.168.2.*). The exact <index> is the test
    # driver's nodes-attrset iteration order (not contractual).
    alice.wait_until_succeeds(
        "journalctl -u tinc.mesh --no-pager | "
        "grep 'DHT voted public v4: 192.168.1.'",
        timeout=60,
    )
    bob.wait_until_succeeds(
        "journalctl -u tinc.mesh --no-pager | "
        "grep 'DHT voted public v4: 192.168.1.'",
        timeout=60,
    )

    # ─── Gate: voted IP is exactly the gateway's WAN. Prefix grep
    # above could pass on a 192.168.1.* leak; this can't.
    alice_gw_wan = alice_gw.succeed(
        "ip -4 addr show eth1 | awk '/inet / {print $2}' | cut -d/ -f1"
    ).strip()
    print(f"alice_gw WAN address: {alice_gw_wan}")
    alice.succeed(
        f"journalctl -u tinc.mesh --no-pager | "
        f"grep -F 'DHT voted public v4: {alice_gw_wan}'"
    )

    # ─── Gate: port-probe through NAT. Probe goes from tincd's
    # listener through MASQUERADE; rxpath demux logs the echo.
    # MASQUERADE without --random is port-preserving under low
    # contention, so port=655 here — not asserted (normal NAT, not
    # a bug). The IP is the proof.
    alice.wait_until_succeeds(
        f"journalctl -u tinc.mesh --no-pager | "
        f"grep -F 'port probe: tincd reflexive v4 = {alice_gw_wan}:'",
        timeout=60,
    )

    # ─── Gate: BEP 44 publish carries the port-probe result. NAT'd
    # alice publishes a working v4= — the design's payload. Bad
    # signature ⇒ seeds drop the put (BEP 44 checks at store time)
    # ⇒ resolve sees nothing. Unit test covers this on loopback;
    # here the token is bound to the NAT-mapped source IP.
    relay.wait_until_succeeds(
        "${tincd}/bin/tinc-dht-seed --resolve "
        "'${keys.alpha.ed25519Public}' 127.0.0.1:${toString dhtBase} "
        f"| grep -F 'v4={alice_gw_wan}:'",
        timeout=60,
    )
    bob_gw_wan = bob_gw.succeed(
        "ip -4 addr show eth1 | awk '/inet / {print $2}' | cut -d/ -f1"
    ).strip()
    print(f"bob_gw WAN address: {bob_gw_wan}")
    relay.wait_until_succeeds(
        "${tincd}/bin/tinc-dht-seed --resolve "
        "'${keys.beta.ed25519Public}' 127.0.0.1:${toString dhtBase} "
        f"| grep -F 'v4={bob_gw_wan}:'",
        timeout=60,
    )

    # Full record → test log.
    relay.succeed(
        "echo 'alice published:' >&2 && "
        "${tincd}/bin/tinc-dht-seed --resolve "
        "'${keys.alpha.ed25519Public}' 127.0.0.1:${toString dhtBase} >&2"
    )

    # ─── Gate: portmapped TCP. The portmapper thread does NAT-PMP
    # to alice_gw, learns (alice_gw_wan, port). on_periodic_tick
    # logs the Mapped event and feeds discovery; the next publish
    # carries `tcp=`. miniupnpd installs a real DNAT rule — prove
    # it delivers by connecting from `relay` (vlan-1, the "WAN").
    alice.wait_until_succeeds(
        f"journalctl -u tinc.mesh --no-pager | "
        f"grep -F 'Portmapped Tcp 655 → {alice_gw_wan}:'",
        timeout=60,
    )
    relay.wait_until_succeeds(
        "${tincd}/bin/tinc-dht-seed --resolve "
        "'${keys.alpha.ed25519Public}' 127.0.0.1:${toString dhtBase} "
        f"| grep -F 'tcp={alice_gw_wan}:'",
        timeout=60,
    )
    alice_tcp = relay.succeed(
        "${tincd}/bin/tinc-dht-seed --resolve "
        "'${keys.alpha.ed25519Public}' 127.0.0.1:${toString dhtBase} "
        "| tr ' ' '\\n' | sed -n 's/^tcp=//p'"
    ).strip()
    print(f"alice published tcp={alice_tcp}")
    # nc -zv: 3-way handshake completing proves miniupnpd's DNAT
    # delivered to alice's :655 (alice_gw has nothing listening
    # there itself).
    relay.succeed(f"nc -zv -w3 {alice_tcp.replace(':', ' ')}")

    # ─── Tier-0 still works with DHT on (no-regression).
    alice.wait_until_succeeds("ping -c1 -W2 10.20.0.2", timeout=60)

    # ─── Gate: carol cold-start. Chain: addr cache empty → retry_
    # outgoing → resolve queued → (relay publishes ~5s in) →
    # drain_resolved → dht_hints → next retry connects. ~15-30s
    # depending on periodic-vs-retry timer interleaving; 60s budget.
    carol.wait_until_succeeds(
        "journalctl -u tinc.mesh --no-pager | "
        "grep 'DHT resolved relay:.*2001:db8:1::'",
        timeout=60,
    )
    carol.wait_until_succeeds(
        "journalctl -u tinc.mesh --no-pager | "
        "grep 'Connection with relay.*activated'",
        timeout=60,
    )
    carol.wait_until_succeeds("ping -c1 -W2 10.20.0.254", timeout=30)

    # Timeline → test log.
    carol.succeed(
        "echo '=== carol cold-start timeline ===' >&2 && "
        "journalctl -u tinc.mesh --no-pager | "
        "grep -E 'Could not set up|DHT resolved|Trying to connect|activated' >&2"
    )

    relay.succeed("journalctl -u dht-seed.service --no-pager >&2")
  '';
}
