# Shared two-node mesh for the tinc-auth NixOS tests. alpha is
# 10.20.0.1 and beta is 10.20.0.2, with a tinc-auth socket unit on
# whoever imports mkTincAuth.
{ tincd }:
let
  keys = import ./snakeoil-keys.nix;
in
{
  mkNode =
    self: peer:
    { ... }:
    {
      services.tinc.networks.mesh = {
        name = self;
        package = tincd;
        ed25519PrivateKeyFile = builtins.toFile "ed25519.priv" keys.${self}.ed25519Private;
        hostSettings = {
          alpha = {
            subnets = [ { address = "10.20.0.1"; } ];
            settings.Ed25519PublicKey = keys.alpha.ed25519Public;
          };
          beta = {
            subnets = [ { address = "10.20.0.2"; } ];
            settings.Ed25519PublicKey = keys.beta.ed25519Public;
            addresses = [ { address = peer; } ];
          };
        };
        settings = {
          DeviceType = "tun";
          ConnectTo = peer;
        };
        chroot = false;
      };

      networking.interfaces."tinc.mesh" = {
        virtual = true;
        virtualType = "tun";
        ipv4.addresses = [
          {
            address = if self == "alpha" then "10.20.0.1" else "10.20.0.2";
            prefixLength = 24;
          }
        ];
      };
      systemd.services."tinc.mesh" = {
        after = [ "network-addresses-tinc.mesh.service" ];
        requires = [ "network-addresses-tinc.mesh.service" ];
      };

      networking.useDHCP = false;
      networking.firewall.allowedTCPPorts = [ 655 ];
      networking.firewall.allowedUDPPorts = [ 655 ];

      environment.systemPackages = [ tincd ];
    };

  # tinc-auth on /run/tinc-auth.sock. extraFlags for IdP mode.
  mkTincAuth = extraFlags: {
    # Runs as root: tincd's pidfile is 0600, written before its
    # privdrop. Same constraint as `tinc -n mesh dump`.
    systemd.sockets.tinc-auth = {
      wantedBy = [ "sockets.target" ];
      listenStreams = [ "/run/tinc-auth.sock" ];
      # 0666 keeps the test simple. A real deployment would
      # 0660 + a shared group.
      socketConfig.SocketMode = "0666";
    };
    # wantedBy: serve from boot, not from the first subrequest.
    # The socket fd is still passed.
    systemd.services.tinc-auth = {
      wantedBy = [ "multi-user.target" ];
      requires = [
        "tinc-auth.socket"
        "tinc.mesh.service"
      ];
      after = [
        "tinc-auth.socket"
        "tinc.mesh.service"
      ];
      serviceConfig = {
        ExecStart = ''
          ${tincd}/bin/tinc-auth -n mesh --pidfile /run/tinc.mesh.pid ${toString extraFlags}
        '';
        # The bind check races tincd's control socket at boot.
        Restart = "on-failure";
        RestartSec = "1s";
      };
    };
  };
}
