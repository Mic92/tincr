# Operating tincd

Quick reference for running and debugging the daemon. See
`tinc --help` / `tincd --help` for the full flag list.

## Running

```sh
# foreground, logs to stderr (recommended under systemd)
tincd -n NETNAME -D

# detached; logs go to LOCALSTATEDIR/log/tinc.NETNAME.log
tincd -n NETNAME
```

Under systemd use `Type=notify` and run foreground (`-D`); journald
captures stderr. A sample instanced unit is in
[`contrib/tincd@.service`](../contrib/tincd@.service).

### Socket activation

tincd honours `LISTEN_FDS`/`LISTEN_PID`. Enable
[`contrib/tincd@.socket`](../contrib/tincd@.socket) to have systemd
own the TCP meta-listener: the daemon adopts the passed fd(s) and
opens the paired UDP socket on the same address itself (so the
`.socket` unit needs only `ListenStream=`, no `ListenDatagram=`).
With socket activation, `BindToAddress`/`ListenAddress`/`Port` in
`tinc.conf` are ignored — the `.socket` unit is the bind config.

## Signals

| Signal | Effect | Control-socket equivalent |
|---|---|---|
| `TERM`/`INT`/`QUIT` | clean shutdown (runs `tinc-down`) | `tinc stop` |
| `HUP` | reload config (see below) | `tinc reload` |
| `ALRM` | reset outgoing backoff, reconnect now | `tinc retry` |
| `USR1`/`USR2` | ignored — use `tinc dump …` instead | — |

## Reload scope

`tinc reload` / `SIGHUP` re-reads `tinc.conf` and `hosts/NAME` and
applies:

- `Subnet` additions/removals (with `subnet-up`/`-down` hooks)
- `ConnectTo` additions/removals
- soft settings (`PingInterval`, `MaxTimeout`, `AutoConnect`, …)
- the invitation key
- per-connection revocation: any peer whose `hosts/NAME` mtime
  changed is disconnected

It does **not** re-apply anything that requires re-binding or
re-opening:

- `Port`, `BindToAddress`, `ListenAddress`, `AddressFamily`
- `Device`, `DeviceType`, `Interface`, `Mode`
- private key paths

The daemon warns when it sees `Port`/`AddressFamily`/`Interface`
changed on reload; for the others, restart.

## Log files and rotation

`--logfile` is opened once at startup and is **not** reopened on
`SIGHUP`. Use `copytruncate` in your logrotate config:

```
/var/log/tinc.*.log {
    weekly
    rotate 4
    copytruncate
    missingok
}
```

Under systemd, prefer `-D` and let journald handle rotation.

## Debug levels

`-d[LEVEL]`, `LogLevel=` in `tinc.conf`, or `tinc debug N` at
runtime. Mapping to Rust log levels:

| tinc level | filter |
|---|---|
| 0 | `info` |
| 1–2 | `debug` |
| 3+ | `trace` |

`RUST_LOG` overrides all of the above and accepts per-target
filters, e.g. `RUST_LOG=info,tincd::proto=trace`.

## Diagnostics cheatsheet

```sh
tinc -n NET dump nodes          # mesh members, reachability, pmtu
tinc -n NET dump edges          # meta-connection graph
tinc -n NET dump subnets        # routing table
tinc -n NET dump connections    # live TCP meta connections
tinc -n NET dump graph | dot -Tpng >mesh.png
tinc -n NET info NODE           # human summary for one node/subnet
tinc -n NET top                 # per-node traffic, live
tinc -n NET log 5               # live log stream at trace
tinc -n NET pcap | wireshark -k -i -
tinc -n NET retry               # reconnect now (after resume/NAT change)
tinc -n NET purge               # forget unreachable nodes
```
