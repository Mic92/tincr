{
  config,
  lib,
  pkgs,
  ...
}:

let
  inherit (lib)
    any
    attrValues
    concatStringsSep
    filter
    filterAttrs
    flatten
    literalExpression
    mapAttrs'
    mapAttrsToList
    mkDefault
    mkEnableOption
    mkIf
    mkMerge
    mkOption
    nameValuePair
    optional
    optionalAttrs
    types
    ;

  cfg = config.services.tincr;

  netOpts =
    { name, config, ... }:
    {
      options = {
        enable = mkEnableOption "the tincr daemon for this network" // {
          default = true;
        };

        package = mkOption {
          type = types.package;
          default = cfg.package;
          defaultText = literalExpression "config.services.tincr.package";
          description = "tincd package providing /bin/tincd and /bin/tinc.";
        };

        nodeName = mkOption {
          type = types.strMatching "[a-zA-Z0-9_]+";
          default = config._module.args.name or name;
          defaultText = literalExpression "<network attr name>";
          description = ''
            Tinc node name (the local node's identity inside the
            mesh). Must match a host file in `hosts` and is written
            to tinc.conf as `Name =`.
          '';
        };

        listenPort = mkOption {
          type = types.port;
          default = 655;
          description = ''
            TCP/UDP port the daemon listens on. The matching socket
            unit's `ListenStream=` is set from this; tincd opens UDP
            on the same address itself.
          '';
        };

        socketActivation = mkOption {
          type = types.bool;
          default = true;
          description = ''
            Whether to wire `tincr-<net>.socket` so systemd owns the
            TCP listener. tincd adopts the fd via LISTEN_FDS and
            opens UDP itself; restarts then keep the bound port.
          '';
        };

        openFirewall = mkOption {
          type = types.bool;
          default = false;
          description = ''
            Open `listenPort` for both TCP (meta) and UDP (SPTPS) in
            networking.firewall.
          '';
        };

        ed25519PrivateKeyFile = mkOption {
          type = types.path;
          example = "/var/lib/tincr/mesh/ed25519_key.priv";
          description = ''
            Path to the node's Ed25519 private key. Stateful; the
            module does not generate it. tinc.conf gets
            `Ed25519PrivateKeyFile =` pointing here.
          '';
        };

        hosts = mkOption {
          type = types.attrsOf types.lines;
          default = { };
          example = literalExpression ''
            {
              alice = '''
                Address = alice.example.com
                Subnet = 10.0.0.1/32
                Ed25519PublicKey = ...
              ''';
            }
          '';
          description = ''
            Host configuration files keyed by node name. Written to
            `/etc/tinc/<network>/hosts/<node>` verbatim.
          '';
        };

        connectTo = mkOption {
          type = types.listOf types.str;
          default = [ ];
          description = "Nodes to add as `ConnectTo =` lines in tinc.conf.";
        };

        autoConnect = mkOption {
          type = types.bool;
          default = true;
          description = "Set `AutoConnect = yes` in tinc.conf.";
        };

        deviceType = mkOption {
          type = types.enum [
            "tun"
            "tap"
          ];
          default = "tun";
          description = "DeviceType= in tinc.conf (Layer-3 vs Layer-2).";
        };

        interfaceName = mkOption {
          type = types.str;
          default = "tinc-${name}";
          defaultText = literalExpression ''"tinc-<network>"'';
          description = ''
            Name of the kernel interface tincd creates. `Interface=`
            in tinc.conf and the target of resolved/route hooks.
          '';
        };

        addresses = mkOption {
          type = types.listOf types.str;
          default = [ ];
          example = [
            "10.21.0.1/16"
            "fd21::1/64"
          ];
          description = ''
            Addresses assigned to the tinc interface via systemd-
            networkd `Address=`. CIDR-notation strings.
          '';
        };

        extraConfig = mkOption {
          type = types.lines;
          default = "";
          description = "Extra lines appended to tinc.conf.";
        };

        dns = {
          enable = mkEnableOption ''
            tincd's TUN-intercept DNS stub. When on, the daemon
            answers `<node>.<suffix>` queries with the node's
            `Subnet=` host-prefix routes; resolved is configured to
            route that suffix to the tinc interface.
          '';

          suffix = mkOption {
            type = types.str;
            default = "";
            example = "mesh";
            description = ''
              DNS zone the stub is authoritative for. resolved is
              configured with `Domains=~<suffix>` on the tinc
              interface, so only matching queries reach the stub.
            '';
          };

          address4 = mkOption {
            type = types.nullOr types.str;
            default = null;
            example = "10.21.0.53";
            description = ''
              IPv4 address the stub answers on. Must route to the
              tinc TUN — pick one inside the network's prefix.
              Either `address4` or `address6` must be set.
            '';
          };

          address6 = mkOption {
            type = types.nullOr types.str;
            default = null;
            example = "fd21::53";
            description = "IPv6 counterpart of `address4`.";
          };
        };

      };
    };

  enabledNets = filterAttrs (_: n: n.enable) cfg.networks;

  # /etc/tinc/<net>/ is tincd's default confbase; rendering inline
  # there avoids passing `-c` to the unit.
  mkTincConf =
    netName: net:
    let
      lines = filter (s: s != "") (
        [
          "Name = ${net.nodeName}"
          "DeviceType = ${net.deviceType}"
          "Interface = ${net.interfaceName}"
          "Port = ${toString net.listenPort}"
          "AutoConnect = ${if net.autoConnect then "yes" else "no"}"
          "Ed25519PrivateKeyFile = ${toString net.ed25519PrivateKeyFile}"
        ]
        ++ map (n: "ConnectTo = ${n}") net.connectTo
        ++ optional net.dns.enable "DNSSuffix = ${net.dns.suffix}"
        ++ optional (net.dns.enable && net.dns.address4 != null) "DNSAddress = ${net.dns.address4}"
        ++ optional (net.dns.enable && net.dns.address6 != null) "DNSAddress = ${net.dns.address6}"
        ++ optional (net.extraConfig != "") net.extraConfig
      );
    in
    concatStringsSep "\n" lines + "\n";

  # Static system user. Owns the persistent TUN (TUNSETOWNER) so
  # tincd's TUNSETIFF can re-attach without CAP_NET_ADMIN, and the
  # ed25519 key file can be group-readable.
  serviceUser = "tincr";

  # systemd-networkd .netdev unit. Pre-creates a persistent TUN with
  # IFF_VNET_HDR + IFF_NO_PI matching what tincd asks for and pins
  # the owner to `serviceUser`. Closing the fd after TUNSETPERSIST
  # leaves the netdev around for tincd to adopt by name.
  mkNetdev = netName: net: {
    netdevConfig = {
      Name = net.interfaceName;
      Kind = "tun";
    };
    tunConfig = {
      User = serviceUser;
      VNetHeader = "yes";
      PacketInfo = "no";
    };
  };

  # systemd-networkd .network unit per tinc interface. Address
  # assignment + split-DNS handed off to networkd/resolved.
  mkNetwork = netName: net: {
    matchConfig.Name = net.interfaceName;
    address = net.addresses;
    # tinc-mesh has no carrier until tincd opens the TUN; without
    # these flags networkd-wait-online blocks network-online.target
    # forever and tincd's `After=` order deadlocks.
    linkConfig.RequiredForOnline = "no";
    networkConfig = {
      ConfigureWithoutCarrier = true;
      LinkLocalAddressing = "no";
      IPv6AcceptRA = false;
    } // optionalAttrs net.dns.enable {
      DNS =
        optional (net.dns.address4 != null) net.dns.address4
        ++ optional (net.dns.address6 != null) net.dns.address6;
      Domains = "~${net.dns.suffix} ${net.dns.suffix}";
    };
  };

  etcForNet =
    netName: net:
    {
      "tinc/${netName}/tinc.conf".text = mkTincConf netName net;
    }
    // mapAttrs' (
      hostName: text: nameValuePair "tinc/${netName}/hosts/${hostName}" { text = text; }
    ) net.hosts;

  unitName = netName: "tincr-${netName}";

  # tincd runs as `serviceUser`. The TUN is pre-created by networkd
  # with TUNSETOWNER == serviceUser, so re-opening it needs no
  # capabilities. Only CAP_NET_BIND_SERVICE remains, for UDP 655.
  mkService =
    netName: net:
    let
      pkg = net.package;
      pidfile = "/run/tincr/${netName}.pid";
    in
    {
      description = "tinc VPN (network ${netName})";
      documentation = [
        "man:tincd(8)"
        "man:tinc(8)"
      ];
      after = [
        "network-online.target"
        "systemd-networkd.service"
      ];
      wants = [ "network-online.target" ];
      wantedBy = mkIf (!net.socketActivation) [ "multi-user.target" ];

      restartTriggers = [ (mkTincConf netName net) ];

      serviceConfig = {
        Type = "notify";
        NotifyAccess = "main";
        ExecStart = "${pkg}/bin/tincd -D -n ${netName} --pidfile=${pidfile}";
        ExecReload = "${pkg}/bin/tinc -n ${netName} reload";
        PIDFile = pidfile;
        WatchdogSec = 30;
        Restart = "on-failure";
        RestartSec = 5;
        KillMode = "mixed";

        User = serviceUser;
        Group = serviceUser;

        RuntimeDirectory = "tincr";
        RuntimeDirectoryMode = "0755";
        StateDirectory = "tincr/${netName}";
        StateDirectoryMode = "0700";

        CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];
        AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
        NoNewPrivileges = true;

        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        ProtectProc = "invisible";
        PrivateTmp = true;
        # PrivateDevices=true hides /dev/net/tun; allow-list it via
        # DevicePolicy=closed instead.
        PrivateDevices = false;
        DeviceAllow = [ "/dev/net/tun rw" ];
        DevicePolicy = "closed";

        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
          "AF_NETLINK"
          "AF_UNIX"
        ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [
          "@system-service"
          "~@privileged @resources"
        ];

        # ProtectSystem=strict makes /etc RO; tincd writes back to
        # hosts/ when it learns `Address=` from peers/invitations.
        ReadWritePaths = [ "/etc/tinc/${netName}" ];
      };
    };

  mkSocket = netName: net: {
    description = "tinc VPN listen socket (network ${netName})";
    wantedBy = [ "sockets.target" ];
    socketConfig = {
      ListenStream = toString net.listenPort;
      BindIPv6Only = "both";
      FreeBind = true;
    };
  };
in
{
  options.services.tincr = {
    networks = mkOption {
      type = types.attrsOf (types.submodule netOpts);
      default = { };
      description = ''
        Tincr networks. Each attribute name is the network's confbase
        directory under /etc/tinc/.
      '';
    };

    package = mkOption {
      type = types.package;
      description = "Default package used for any network without an explicit `package`.";
    };
  };

  config = mkIf (enabledNets != { }) (mkMerge [
    {
      users.users.${serviceUser} = {
        isSystemUser = true;
        group = serviceUser;
        description = "tincr VPN daemon";
      };
      users.groups.${serviceUser} = { };

      assertions = flatten (
        mapAttrsToList (n: net: [
          {
            assertion = !net.dns.enable || net.dns.address4 != null || net.dns.address6 != null;
            message = "services.tincr.networks.${n}.dns: address4 or address6 must be set.";
          }
          {
            assertion = !net.dns.enable || net.dns.suffix != "";
            message = "services.tincr.networks.${n}.dns: suffix must be set.";
          }
        ]) enabledNets
      );

      environment.etc = mkMerge (mapAttrsToList etcForNet enabledNets);

      networking.useNetworkd = mkDefault true;
      systemd.network = {
        netdevs = mapAttrs' (n: net: nameValuePair "40-tincr-${n}" (mkNetdev n net)) enabledNets;
        networks = mapAttrs' (n: net: nameValuePair "40-tincr-${n}" (mkNetwork n net)) enabledNets;
      };

      systemd.services = mapAttrs' (n: net: nameValuePair (unitName n) (mkService n net)) enabledNets;

      systemd.sockets = mapAttrs' (n: net: nameValuePair (unitName n) (mkSocket n net)) (
        filterAttrs (_: n: n.socketActivation) enabledNets
      );

      networking.firewall =
        let
          ports = flatten (mapAttrsToList (_: n: optional n.openFirewall n.listenPort) enabledNets);
        in
        {
          allowedTCPPorts = ports;
          allowedUDPPorts = ports;
        };
    }

    # networkd hands DNS=/Domains= to resolved; it must be the
    # active resolver.
    (mkIf (any (n: n.dns.enable) (attrValues enabledNets)) {
      services.resolved.enable = mkDefault true;
    })
  ]);
}
