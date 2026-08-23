# Logging into web apps with mesh identity

If a request arrives over the mesh, tinc already knows which node
sent it. `tinc-auth` turns that knowledge into web authentication,
so services running on your mesh don't need passwords, user
databases, or an SSO stack.

It works in two ways. For apps that trust a header from a reverse
proxy, it acts as an nginx `auth_request` backend: nginx asks it
about every request, and the app sees `X-Tinc-Node: alice`. For
apps that want a real login flow, like Gitea or Grafana, it acts as
an OpenID Connect provider. The app sends the browser to tinc-auth,
tinc-auth looks at where the connection came from, and the browser
bounces straight back with a signed token. Nobody types anything.

One thing to be clear about up front: this authenticates the tinc
*node*, not a person. If `alice` is your laptop, that distinction
doesn't matter. If `alice` is a shared server, everyone on it logs
in as `alice`.

The flip side of "your address is your login" is that anyone who
can reach the auth socket or the IdP port can mint identities. Keep
the nginx socket private, and let tinc-auth do what it insists on
anyway: binding the IdP to a mesh address only.

## The nginx way

Point tinc-auth at your net and give it a socket for nginx. It
needs root, because tincd's pidfile is only readable by root. The
`tinc` CLI has the same constraint.

```sh
tinc-auth -n mesh --pidfile /run/tinc.mesh.pid --listen-socket /run/tinc-auth.sock
```

In production you want systemd socket activation instead of
`--listen-socket`. Then systemd owns the socket, and nginx never
sees a connection refused while tinc-auth restarts:

```ini
# tinc-auth.socket
[Socket]
ListenStream=/run/tinc-auth.sock
SocketMode=0660
SocketGroup=nginx

# tinc-auth.service
[Service]
ExecStart=tinc-auth -n mesh --pidfile /run/tinc.mesh.pid
Restart=on-failure
```

On the nginx side, one internal location for the auth check, and
`auth_request` on whatever you want to protect:

```nginx
location = /_tinc_auth {
    internal;
    proxy_pass http://unix:/run/tinc-auth.sock;
    proxy_pass_request_body off;
    proxy_set_header Remote-Addr $remote_addr;
}
location / {
    auth_request /_tinc_auth;
    auth_request_set $tinc_node $upstream_http_tinc_node;
    proxy_set_header X-Tinc-Node $tinc_node;
    proxy_pass http://backend;
}
```

A request from a mesh address gets a 204 with `Tinc-Node`,
`Tinc-User` (also served as `Remote-User` for consumers that
expect the generic name), `Tinc-Net` and `Tinc-Subnet` headers. Anything else
gets a 401. If
tincd is down, tinc-auth answers 503 and nginx denies the request,
so a dead daemon never turns into an open door.

## The OIDC way

The IdP is the same process with a few more flags:

```sh
tinc-auth -n mesh --pidfile /run/tinc.mesh.pid \
    --idp-listen 10.20.0.2:8443 \
    --issuer http://10.20.0.2:8443 \
    --clients /etc/tinc-auth/clients.json \
    --groups /etc/tinc-auth/groups.json \
    --email-domain mesh.example.com
```

`--idp-listen` has to be an address this node owns in the mesh.
tinc-auth verifies that against the running daemon and refuses to
start otherwise. That single rule carries the whole security model:
only mesh traffic can reach it, and mesh traffic carries the
identity.

Yes, the issuer is plain http. That is deliberate. The mesh already
encrypts and authenticates the transport, so TLS on top would
protect nothing. Most self-hosted apps accept an http issuer, some
behind a config flag.

The RS256 signing key appears on first start as
`CONFDIR/idp/oidc-key.pem`. You never have to touch it.

Each app that wants to log users in gets an entry in
`clients.json`. Redirect URIs are compared character for character,
so write them exactly as the app will send them:

```json
[
  {
    "id": "gitea",
    "secret": "generate-something-long",
    "redirect_uris": ["http://10.20.0.2:3000/user/oauth2/tinc/callback"]
  }
]
```

The mesh has no concept of groups, but apps like to map admin
rights from one. `groups.json` lets you assert that mapping
yourself:

```json
{ "alice": ["admin"] }
```

### What ends up in the token

| claim | value |
|-------|-------|
| `sub`, `preferred_username` | account name (see below) |
| `tinc_node` | node name |
| `tinc_net` | netname |
| `tinc_subnet` | the subnet that matched the browser's address |
| `groups` | from `--groups`, else `[]` |
| `email` | `account@DOMAIN`, only with `--email-domain` |

Apps key their accounts on `sub`. So if you rename a node without a
mapping, every app will treat it as a brand new user.

### Mapping nodes to people

By default the account name is the node name, which is right when
nodes are named after their owners. When one person has several
devices, or node names don't match your usernames, there are two
places to put the mapping.

A `--map` file, if tinc-auth should do it:

```json
{ "alice-laptop": "alice", "alice-phone": "alice" }
```

The mapped name is what appears in `Tinc-User`, in `sub` and
`preferred_username`, and as the key into `--groups`. The original
node name stays available in `Tinc-Node` and the `tinc_node` claim.
Nodes without an entry keep their own name.

Or the directory, if you have one. Anything that looks users up in
LDAP by a filter can resolve a node name to an account without
tinc-auth's help: give your users a multi-valued attribute like
`tincNode: alice-laptop` and extend the lookup filter to match it.
With Authelia for example:

```yaml
authentication_backend:
  ldap:
    users_filter: "(&(|({username_attribute}={input})(tincNode={input}))(objectClass=person))"
```

Then a lookup for `alice-laptop` finds `uid=alice` and returns the
canonical username, groups and email from the directory. In that
setup you don't need `--map`, `--groups` or `--email-domain` at
all.

### Gitea

Register the provider once:

```sh
gitea admin auth add-oauth \
    --name tinc \
    --provider openidConnect \
    --key gitea \
    --secret generate-something-long \
    --auto-discover-url http://10.20.0.2:8443/.well-known/openid-configuration
```

and let accounts create themselves in `app.ini`:

```ini
[oauth2_client]
ENABLE_AUTO_REGISTRATION = true
USERNAME = nickname
ACCOUNT_LINKING = auto
```

From then on, "Sign in with tinc" logs a browser in as its node,
creating the account on first use. Use `--email-domain`: Gitea
insists on a well-formed email claim.

### Grafana

```ini
[auth.generic_oauth]
enabled = true
name = tinc
client_id = grafana
client_secret = generate-something-long
auth_url = http://10.20.0.2:8443/authorize
token_url = http://10.20.0.2:8443/token
api_url = http://10.20.0.2:8443/userinfo
role_attribute_path = contains(groups[*], 'admin') && 'Admin' || 'Viewer'
```

## When it doesn't work

**The IdP refuses to start.** The `--idp-listen` address is not in
a subnet this node owns, or tincd isn't up yet. Compare against
`tinc -n NET dump subnets`, and order the unit after the tinc
service.

**The app shows `access_denied`.** The browser reached the IdP from
outside the mesh, often because a proxy sat in between. The browser
has to talk to the IdP directly, over the tunnel.

**The app shows `temporarily_unavailable`.** tincd's control socket
is down. tinc-auth fails closed rather than guessing.

**A mesh peer gets a 401 from nginx.** Right after a node joins,
subnet gossip can lag by a moment. It settles within seconds.
