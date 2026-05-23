# OpenWrt Packages

## phantun

[Phantun](https://github.com/dndx/phantun) transforms UDP streams into
obfuscated (fake) TCP streams that can traverse Layer 3 & Layer 4 (NAPT)
firewalls and NATs.

Two packages are provided:

- **phantun-client** — listens for incoming UDP and wraps it in fake TCP
- **phantun-server** — receives fake TCP and unwraps it back to UDP

### Building with the OpenWrt SDK

Download the SDK for your target from
<https://downloads.openwrt.org/releases/24.10.3/targets/>.

```sh
# Extract the SDK
tar xf openwrt-sdk-24.10.3-*.tar.*
cd openwrt-sdk-24.10.3-*/

# Add this repository as a custom feed
echo "src-link phantun /path/to/tincr/openwrt" >> feeds.conf

# Update and install feeds (packages feed is needed for Rust toolchain)
./scripts/feeds update packages phantun
./scripts/feeds install phantun-client phantun-server

# Build
make defconfig
make package/phantun/compile
```

The resulting `.ipk` files will be in `bin/packages/*/phantun/`.

### Installing on OpenWrt

```sh
opkg install phantun-client_*.ipk
# or
opkg install phantun-server_*.ipk
```

### Configuration

Both packages use UCI configuration files and procd init scripts.

#### Client (`/etc/config/phantun-client`)

```
config phantun-client 'config'
    option enabled '1'
    option local_addr '127.0.0.1:1234'
    option remote_addr 'your-server:4567'
```

#### Server (`/etc/config/phantun-server`)

```
config phantun-server 'config'
    option enabled '1'
    option local_port '4567'
    option remote_addr '127.0.0.1:1234'
```

#### Available options

| Option             | Default (client)   | Default (server)   | Description                                          |
|--------------------|--------------------|--------------------|------------------------------------------------------|
| `enabled`          | `0`                | `0`                | Enable the service                                   |
| `local_addr`       | `127.0.0.1:1234`   | —                  | Client: IP:port to listen for UDP                    |
| `local_port`       | —                  | `4567`             | Server: port to listen for TCP                       |
| `remote_addr`      | (required)         | `127.0.0.1:1234`   | Client: server address; Server: UDP forward target   |
| `tun_name`         |                    |                    | TUN interface name (auto if empty)                   |
| `tun_local`        | `192.168.200.1`    | `192.168.201.1`    | TUN local IPv4 address                               |
| `tun_peer`         | `192.168.200.2`    | `192.168.201.2`    | TUN peer IPv4 address                                |
| `tun_local6`       | `fcc8::1`          | `fcc9::1`          | TUN local IPv6 address                               |
| `tun_peer6`        | `fcc8::2`          | `fcc9::2`          | TUN peer IPv6 address                                |
| `ipv4_only`        | `0`                | `0`                | Only use IPv4                                        |
| `handshake_packet` |                    |                    | File path: content sent after TCP handshake          |

### Managing the service

```sh
service phantun-client start
service phantun-client stop
service phantun-client restart
```
