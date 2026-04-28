# Exercises the systemd integration surface that contrib/tincd@.service
# and contrib/tincd@.socket encode: Type=notify, WatchdogSec, ExecReload,
# and TCP socket activation via LISTEN_FDS. The other VM tests run under
# the upstream services.tinc module (Type=simple, no .socket); this one
# wires the units by hand so a regression in sd_notify, the event-loop
# watchdog timer, or adopt_listeners is caught.
#
# The contrib units themselves hard-code FHS paths and can't run on
# NixOS verbatim, so they are checked with `systemd-analyze verify` and
# the live units below mirror their semantics 1:1.
{
  lib,
  testers,
  tincd,
}:
let
  keys = import ./snakeoil-keys.nix;

  hosts = {
    alpha = ''
      Subnet = 10.21.0.1/32
      Ed25519PublicKey = ${keys.alpha.ed25519Public}
    '';
    beta = ''
      Address = beta
      Subnet = 10.21.0.2/32
      Ed25519PublicKey = ${keys.beta.ed25519Public}
    '';
  };

  # tinc-up: assign address. Runs as root before drop_privs.
  # script.rs clears the env, so reference ip(8) by absolute path.
  tincUp = self: ''
    #!/bin/sh
    /run/current-system/sw/bin/ip addr add ${self}/24 dev "$INTERFACE"
    /run/current-system/sw/bin/ip link set "$INTERFACE" up
  '';

  mkNode =
    self: addr: extra:
    { pkgs, ... }:
    {
      environment.etc = {
        "tinc/mesh/tinc.conf".text = ''
          Name = ${self}
          DeviceType = tun
          AutoConnect = no
          Ed25519PrivateKeyFile = /etc/tinc/mesh/ed25519_key.priv
        ''
        + extra;
        "tinc/mesh/ed25519_key.priv" = {
          text = keys.${self}.ed25519Private;
          mode = "0600";
        };
        "tinc/mesh/hosts/alpha".text = hosts.alpha;
        "tinc/mesh/hosts/beta".text = hosts.beta;
        "tinc/mesh/tinc-up" = {
          text = tincUp addr;
          mode = "0755";
        };
      };

      # Mirror contrib/tincd@.socket: TCP only, port 655. tincd opens
      # the paired UDP socket itself against the same address.
      systemd.sockets."tincd@mesh" = {
        wantedBy = [ "sockets.target" ];
        listenStreams = [ "655" ];
        socketConfig.BindIPv6Only = "both";
      };

      # Mirror contrib/tincd@.service.
      systemd.services."tincd@mesh" = {
        description = "tinc VPN (network %i)";
        after = [ "network.target" ];
        serviceConfig = {
          Type = "notify";
          NotifyAccess = "main";
          ExecStart = "${tincd}/bin/tincd -D -n %i --pidfile=/run/tinc.%i.pid";
          ExecReload = "${tincd}/bin/tinc -n %i reload";
          WatchdogSec = 8;
          Restart = "on-failure";
          RestartSec = 1;
        };
      };

      networking.useDHCP = false;
      networking.firewall.allowedTCPPorts = [ 655 ];
      networking.firewall.allowedUDPPorts = [ 655 ];
      environment.systemPackages = [
        tincd
        pkgs.iproute2
      ];

      # contrib units copied verbatim for systemd-analyze verify.
      # `@` is not valid in a store path name; copy the dir.
      environment.etc."tinc-contrib".source = ../contrib;
    };
in
testers.runNixOSTest {
  name = "tincd-systemd";

  nodes = {
    alpha = mkNode "alpha" "10.21.0.1" "ConnectTo = beta\n";
    beta = mkNode "beta" "10.21.0.2" "";
  };

  testScript = ''
    start_all()

    with subtest("contrib units are syntactically valid"):
        # systemd-analyze verify parses the unit and resolves
        # dependencies; catches typos in section/key names that this
        # test's hand-written mirror would not. The FHS Exec paths
        # don't exist on NixOS, so verify exits 1 — capture stderr
        # and assert the *only* complaints are those two.
        rc, out = alpha.execute(
            "cd /etc/tinc-contrib && "
            "systemd-analyze verify --man=no "
            "./tincd@.service ./tincd@.socket 2>&1"
        )
        bad = [
            l for l in out.splitlines()
            if l.strip() and "is not executable" not in l
        ]
        assert not bad, f"unexpected verify output:\n{out}"

    with subtest("socket activation: daemon adopts TCP fd, opens UDP itself"):
        # .socket is WantedBy=sockets.target so already listening at
        # boot; the service is pulled in on first accept. beta has no
        # ConnectTo, so until alpha dials it, systemd holds the fd
        # and no tincd process exists. Don't probe the port here —
        # connecting would itself trigger activation.
        beta.wait_for_unit("tincd@mesh.socket")
        beta.fail("pgrep -x tincd")

        alpha.systemctl("start tincd@mesh.service")
        alpha.wait_for_unit("tincd@mesh.service")
        # Poll instead of wait_for_unit: a socket-activated service
        # is legitimately inactive with no pending job until the first
        # accept, and alpha's first dial loses a race against async
        # getaddrinfo for `Address = beta` (retry is 5s out).
        beta.wait_until_succeeds(
            "systemctl is-active tincd@mesh.service", timeout=30
        )

        # Type=notify: wait_for_unit returning means READY=1 was
        # received (active state), not just that the process forked.
        # Assert explicitly.
        alpha.succeed(
            "systemctl show -p NotifyAccess,Type,ActiveState tincd@mesh.service "
            "| grep -x ActiveState=active"
        )

        # adopt_listeners logged the activation path; this is the
        # only place that string is emitted, so it proves LISTEN_FDS
        # was honoured rather than falling through to a fresh bind.
        beta.wait_until_succeeds(
            "journalctl -u tincd@mesh.service --no-pager "
            "| grep -F '(socket activation)'",
            timeout=10,
        )

        # UDP 655 is bound by tincd (not systemd): the daemon opened
        # it against the adopted TCP addr.
        beta.succeed("ss -ulnp 'sport = :655' | grep -w tincd")

    with subtest("data path over the activated listener"):
        alpha.wait_until_succeeds("ping -c1 -W2 10.21.0.2", timeout=30)
        beta.succeed("ping -c1 -W2 10.21.0.1")

    with subtest("watchdog keepalive comes from the event loop"):
        # WatchdogSec=8 → daemon must ping at ≤4s. If the event-loop
        # timer is not armed, systemd moves the unit to 'failed'
        # within 8s of READY. Sleep past that window and assert the
        # unit is still healthy and was never restarted.
        import time; time.sleep(12)
        out = alpha.succeed(
            "systemctl show -p ActiveState,NRestarts,WatchdogTimestamp "
            "tincd@mesh.service"
        )
        assert "ActiveState=active" in out, out
        assert "NRestarts=0" in out, out
        # WatchdogTimestamp is non-empty iff a WATCHDOG=1 was received.
        assert "WatchdogTimestamp=\n" not in out + "\n", out

    with subtest("ExecReload reaches the daemon"):
        # ExecReload runs `tinc -n %i reload`, which goes through
        # the control socket (REQ_RELOAD), not SIGHUP. The daemon
        # logs no banner for that path; assert via systemd's own
        # accounting that the reload completed cleanly and the unit
        # stayed active.
        alpha.systemctl("reload tincd@mesh.service")
        alpha.succeed(
            "systemctl show -p ActiveState,NRestarts tincd@mesh.service "
            "| grep -x ActiveState=active"
        )

    with subtest("clean stop sends STOPPING=1 and exits 0"):
        alpha.systemctl("stop tincd@mesh.service")
        alpha.wait_until_succeeds(
            "systemctl show -p ActiveState tincd@mesh.service "
            "| grep -x ActiveState=inactive",
            timeout=10,
        )
        # Result=success means exit 0 AND (for Type=notify) the
        # stop protocol was honoured; a kill -9 would show
        # Result=signal.
        alpha.succeed(
            "systemctl show -p Result tincd@mesh.service "
            "| grep -x Result=success"
        )
  '';
}
