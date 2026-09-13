# nix-darwin (launchd) counterpart of ./module.nix. Mirrors the
# `services.tincr` option surface so downstream modules can target
# both platforms.
{ crane }:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.tincr;

  netOpts =
    { name, ... }:
    {
      options = {
        enable = lib.mkOption {
          type = lib.types.bool;
          default = true;
        };
        package = lib.mkOption {
          type = lib.types.package;
          default = cfg.package;
          defaultText = lib.literalExpression "config.services.tincr.package";
        };
        nodeName = lib.mkOption {
          type = lib.types.strMatching "[a-zA-Z0-9_]+";
          default = name;
        };
        listenPort = lib.mkOption {
          type = lib.types.port;
          default = 655;
        };
        ed25519PrivateKeyFile = lib.mkOption { type = lib.types.path; };
        hosts = lib.mkOption {
          type = lib.types.attrsOf lib.types.lines;
          default = { };
        };
        connectTo = lib.mkOption {
          type = lib.types.listOf lib.types.str;
          default = [ ];
        };
        autoConnect = lib.mkOption {
          type = lib.types.bool;
          default = true;
        };
        addresses = lib.mkOption {
          type = lib.types.listOf lib.types.str;
          default = [ ];
          description = "CIDR addresses assigned to the utun interface via tinc-up.";
        };
        mtu = lib.mkOption {
          type = lib.types.int;
          default = 1377;
        };
        extraConfig = lib.mkOption {
          type = lib.types.lines;
          default = "";
        };
      };
    };

  enabledNets = lib.filterAttrs (_: n: n.enable) cfg.networks;

  mkTincConf =
    name: net:
    lib.concatStringsSep "\n" (
      [
        "Name = ${net.nodeName}"
        # Fixed unit number keeps the interface name stable across
        # restarts so routes added by tinc-up survive.
        "DeviceType = utun"
        "Device = utun10"
        "Port = ${toString net.listenPort}"
        "AutoConnect = ${if net.autoConnect then "yes" else "no"}"
        "Ed25519PrivateKeyFile = ${toString net.ed25519PrivateKeyFile}"
      ]
      ++ map (n: "ConnectTo = ${n}") net.connectTo
      ++ lib.optional (net.extraConfig != "") net.extraConfig
    )
    + "\n";

  mkTincUp =
    net:
    pkgs.writeScript "tinc-up" ''
      #!/bin/sh
      /sbin/ifconfig "$INTERFACE" mtu ${toString net.mtu}
      ${lib.concatMapStringsSep "\n" (
        cidr:
        let
          parts = lib.splitString "/" cidr;
          addr = lib.elemAt parts 0;
          plen = lib.elemAt parts 1;
          isV6 = lib.hasInfix ":" addr;
        in
        if isV6 then
          ''
            /sbin/ifconfig "$INTERFACE" inet6 ${addr} prefixlen ${plen}
            /sbin/route -n add -inet6 ${addr}/${plen} -interface "$INTERFACE" 2>/dev/null || true
          ''
        else
          ''/sbin/ifconfig "$INTERFACE" inet ${addr}/${plen} ${addr}''
      ) net.addresses}
    '';

  # Single derivation for all peer host files; avoids one etc entry
  # and store path per peer on large meshes.
  mkHostsDir =
    name: net:
    pkgs.runCommand "tinc-${name}-hosts"
      {
        __structuredAttrs = true;
        hostFiles = net.hosts;
      }
      ''
        mkdir -p "$out"
        for name in "''${!hostFiles[@]}"; do
          printf '%s' "''${hostFiles[$name]}" > "$out/$name"
        done
      '';

  etcForNet = name: net: {
    "tinc/${name}/tinc.conf".text = mkTincConf name net;
    "tinc/${name}/tinc-up".source = mkTincUp net;
    "tinc/${name}/hosts".source = mkHostsDir name net;
  };
in
{
  options.services.tincr = {
    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ./tincd.nix { craneLib = crane.mkLib pkgs; };
      defaultText = lib.literalExpression "tincr.packages.\${system}.tincd";
      description = "Default tincd package for all networks.";
    };
    networks = lib.mkOption {
      type = lib.types.attrsOf (lib.types.submodule netOpts);
      default = { };
    };
  };

  config = lib.mkIf (enabledNets != { }) {
    environment.etc = lib.mkMerge (lib.mapAttrsToList etcForNet enabledNets);

    launchd.daemons = lib.mapAttrs' (
      name: net:
      lib.nameValuePair "tincr-${name}" {
        path = [
          net.package
          pkgs.coreutils
        ];
        script = ''
          mkdir -p /var/run
          exec ${net.package}/bin/tincd -D -n ${name} --pidfile=/var/run/tincr-${name}.pid
        '';
        serviceConfig = {
          Label = "org.tincr.${name}";
          RunAtLoad = true;
          KeepAlive = {
            SuccessfulExit = false;
          };
          StandardErrorPath = "/var/log/tincr-${name}.log";
          StandardOutPath = "/var/log/tincr-${name}.log";
        };
      }
    ) enabledNets;

    environment.systemPackages = lib.mapAttrsToList (_: n: n.package) enabledNets;
  };
}
