# tincr

Experimental rust-rewrite of [tinc](https://github.com/gsliepen/tinc).

## Running

```sh
tincd -n NETNAME -D     # foreground
tinc  -n NETNAME --help # control / diagnostics CLI
```

See [docs/OPERATING.md](docs/OPERATING.md) for signals, reload
scope, log rotation, debug levels and a `tinc` subcommand
cheatsheet. A sample systemd unit is in
[contrib/tincd@.service](contrib/tincd@.service).
