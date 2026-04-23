# The tincr wire protocol

*TL;DR: it's the tinc 1.1 protocol. SPTPS for the crypto, a
line-oriented ASCII control channel for gossip, a thin relay prefix
on UDP for data. tincr's additions are either trailing tokens that C
tinc already ignores, or fully out of band.*

If you've read `tinc-c/src/protocol*.c` this document won't teach you
a new protocol; it's here to put the layers in one place and to be
explicit about where tincr extends them and why that's safe. For the
interop matrix see [COMPAT.md](COMPAT.md).

## The Three Layers

```mermaid
flowchart TB
    subgraph TCP ["TCP meta-connection"]
        m_sptps["SPTPS (stream mode)"]
        meta["Meta-protocol<br/>ID / ACK / ADD_EDGE / REQ_KEY / …"]
        meta --> m_sptps
    end
    subgraph UDP ["UDP data channel (per node pair)"]
        d_sptps["SPTPS (datagram mode)"]
        data["VPN packets<br/>relay prefix + type + IP/Ethernet payload"]
        data --> d_sptps
    end
    meta -. "REQ_KEY / ANS_KEY<br/>carry the UDP handshake" .-> d_sptps
    DHT["Mainline DHT<br/>(out-of-band rendezvous)"] -. "dialable address" .-> TCP
```

1. **SPTPS** is the cryptographic transport: an authenticated key
   exchange and an AEAD record layer. It's used twice — once in
   stream mode over TCP to protect the meta-connection, and once in
   datagram mode over UDP per node pair to protect the actual VPN
   traffic.

2. The **meta-protocol** is a line-oriented ASCII control channel
   carried inside the TCP SPTPS session: identity, topology gossip,
   key relay, keepalive. This is where the mesh learns about itself.

3. **Data framing** is how encrypted VPN packets ride UDP: an SPTPS
   datagram with a short cleartext routing prefix in front, so a
   relay can forward without being able to decrypt.

A fourth piece, **DHT rendezvous**, sits entirely outside the mesh
protocol and is covered at the end.

## SPTPS

Each node has a long-term Ed25519 identity. The handshake is a signed
ephemeral X25519 exchange: both sides send an ephemeral public key,
both sign the transcript with their identity key, both derive a shared
secret and expand it with SHAKE256 into directional ChaCha20-Poly1305
keys. Either side may later trigger a rekey, which runs the same
exchange under the protection of the current keys and switches over
atomically.

```mermaid
sequenceDiagram
    participant I as Initiator
    participant R as Responder
    Note over I,R: each holds a long-term Ed25519 identity<br/>and the peer's public key
    I->>R: KEX { ephemeral X25519 pub }
    R->>I: KEX { ephemeral X25519 pub }
    Note over I,R: both compute X25519 shared secret<br/>label = role ‖ both KEX records
    I->>R: SIG = Ed25519(label) under initiator identity
    R->>I: SIG = Ed25519(label) under responder identity
    Note over I,R: SHAKE256(secret, label) → directional<br/>ChaCha20-Poly1305 keys — session established
    I-->>R: encrypted records (type ‖ body, AEAD-sealed)
    R-->>I: encrypted records
    opt rekey (either side, any time)
        I->>R: KEX' (under current keys)
        R->>I: KEX' + SIG'
        I->>R: SIG'
        Note over I,R: derive next keys, switch atomically
    end
```

Once established, SPTPS carries typed *records*. In **stream** mode
(the meta-connection) records are length-prefixed and delivered in
order — it's a TLS-shaped thing over an already-ordered byte stream.
In **datagram** mode (the UDP data channel) each record is
self-contained with an explicit sequence number; the receiver runs a
sliding replay window and tolerates loss and reordering. The sequence
number doubles as the AEAD nonce, so it never repeats under a key,
and a session rekeys well before it could wrap.

The cipher suite is fixed: Ed25519, X25519, ChaCha20-Poly1305,
SHAKE256. There is no negotiation, and the legacy RSA/CBC mode that
tinc 1.1 still carries for 1.0 compatibility is not implemented at
all. That's a deliberate reduction in attack surface — see
[COMPAT.md](COMPAT.md) for the operational consequences.

### `SPTPSCipher` (tincr extension)

tincr can swap the record AEAD for **AES-256-GCM** on a per-edge
basis via the `SPTPSCipher` host-file key. This is *not* negotiated:
both ends read the value from static config, and the choice is mixed
into the SPTPS label (and therefore the SIG transcript and the PRF
seed). A mismatch fails the handshake at the SIG step with a clean
authentication error — no record key is ever derived, so misconfigured
peers can't silently corrupt data.

With the default `chacha20-poly1305` the label suffix is empty and the
wire is byte-identical to C tinc 1.1, which ignores unknown host-file
keys. AES-256-GCM keeps the 64-byte PRF key blob (first 32 bytes feed
AES-256), the 16-byte tag, and maps the 32-bit record seqno onto the
96-bit GCM nonce as `0⁸ ‖ seqno_be⁴`, so record framing is unchanged
and the existing `SEAL_KEY_LIMIT` rekey bound covers nonce uniqueness.

### Post-quantum key exchange (`SPTPSKex`)

X25519 alone is harvest-now-decrypt-later vulnerable: traffic recorded
today can be decrypted whenever a cryptographically-relevant quantum
computer materialises. `SPTPSKex = x25519-mlkem768` mixes an
ML-KEM-768 (FIPS 203) shared secret into the same KDF input so that
*both* primitives must fall before recorded traffic is readable.
Ed25519 transcript signatures stay as-is — PQ authentication is a
separate concern (a future quantum adversary can't retroactively MITM
a recording).

SPTPS sends both KEX records blind — each side calls `send_kex` from
`start` before seeing anything from the peer — so the OpenSSH-style
single-KEM layout (initiator sends `ek`, responder replies with `ct`)
doesn't fit. Instead **two** encapsulations run, one per direction:

| Record | Body (hybrid) | Size |
|---|---|--:|
| KEX (both) | `ver(1) ‖ nonce(32) ‖ X25519_pk(32) ‖ MLKEM768_ek(1184)` | 1249 |
| SIG (both) | `Ed25519_sig(64) ‖ MLKEM768_ct(1088)` | 1152 |

On receiving the peer's KEX, each side encapsulates against the peer's
`ek` and appends the resulting `ct` to its own SIG record. On
receiving the peer's SIG it decapsulates with its own `dk`. The PRF
secret becomes `X25519_ss(32) ‖ ss_i2r(32) ‖ ss_r2i(32)` (96 B), where
`ss_i2r` is the secret the initiator encapsulated and the responder
decapsulated — ordered by role so both sides agree, same trick the
classical PRF already uses for the nonces. The PRF *seed* is extended
with `SHA-512(ek_i ‖ ek_r ‖ ct_i2r ‖ ct_r2i)` appended after the
label (X-Wing–style binding, draft-connolly-cfrg-xwing-kem) so the
derived traffic keys depend on every public KEM byte that crossed the
wire, not only on the shared secrets.

The Ed25519 signature still covers only `[role-bit ‖ mykex ‖ hiskex ‖
label]` — i.e. both `ek`s but neither `ct`. With the seed binding
above a substituted `ct` perturbs the derived key directly, and
ML-KEM's implicit rejection additionally yields a different `ss`. The
X25519 leg *is* signed, so an attacker who can break ML-KEM but not
discrete-log still can't MITM.

**Key confirmation.** After deriving keys, each side sends one empty
encrypted handshake record and withholds `HandshakeDone` until the
peer's verifies. A handshake whose `ct` was tampered therefore never
completes on either side; the daemon never marks the tunnel valid.
This adds one record per direction (one extra `ANS_KEY` round-trip
for the per-tunnel handshake) and applies to the initial handshake
only — rekey SIG records are already AEAD-protected under the old
key. The classical `x25519` path is unchanged and remains
byte-identical to C tinc.

> The KDF binding and confirmation round were added after the initial
> hybrid commit; tincr builds between `8de95be4` and this change are
> wire-incompatible in hybrid mode (only). The feature is opt-in and
> was never released in that window.

**Label discriminator.** Both `SPTPSKex` and `SPTPSCipher` are mixed
into the KDF/SIG label as a two-byte suffix `[kex_byte, cipher_byte]`,
appended **only when at least one byte is non-zero** so that the
default configuration remains byte-identical to C tinc on the wire.
`kex_byte` is 0 for `x25519`, 1 for `x25519-mlkem768`; `cipher_byte`
is 0 for `chacha20-poly1305`, 1 for `aes-256-gcm`. The two knobs are
independent and may be combined.

**No negotiation.** `SPTPSKex` is static per-host configuration; both
ends must set the same value out of band. A mismatch fails at
`BadKex` (wrong KEX body length) or, if a future change made the
length check lenient, at `BadSig` (the label suffix desyncs the
transcript). C tinc silently ignores unknown host-file keys, so a
C↔Rust pair with the key set on the Rust side just fails the
handshake — it doesn't crash the C daemon.

The handshake runs over the TCP meta-connection (and the
meta-forwarded `REQ_KEY`/`ANS_KEY` for per-tunnel SPTPS), so the
~1.2 KB records are not MTU-constrained. Handshake-time only;
steady-state throughput is unchanged.

## Meta-protocol

Meta-connections are TCP. The first thing each side sends is a single
plaintext line — `ID name 17.7` — so the receiver can pick the right
host key before any crypto runs. Immediately after, the socket
switches to SPTPS stream mode and everything further is encrypted.

Inside, messages are newline-terminated, space-separated ASCII; the
first token is a numeric request code. The vocabulary:

| Message                     | Purpose                                                                          |
| --------------------------- | -------------------------------------------------------------------------------- |
| `ID`, `ACK`                 | Handshake: name, protocol version, listening port, options, initial edge weight. |
| `ADD_EDGE` / `DEL_EDGE`     | Gossip a meta-connection appearing or disappearing somewhere in the mesh, with its endpoint address and weight. Flooded. |
| `ADD_SUBNET` / `DEL_SUBNET` | Gossip which IP/MAC ranges a node owns. Flooded.                                 |
| `KEY_CHANGED`               | A node discarded its data-channel keys; everyone drops cached sessions for it.   |
| `REQ_KEY` / `ANS_KEY`       | Set up the per-pair UDP SPTPS session. Forwarded hop-by-hop along the routed path so two nodes can handshake without a direct connection; relays append the source address they observed, which both ends then use for NAT hole-punching. |
| `MTU_INFO` / `UDP_INFO`     | Share path-MTU ceilings and observed UDP endpoints along a relay path.           |
| `PING` / `PONG`             | Keepalive. The round-trip also feeds the advertised edge weight.                 |
| `PACKET`, `SPTPS_PACKET`    | Tunnel a data packet over this TCP stream when no UDP path is usable.            |

> Gossip is accepted on the authority of the direct neighbour, not
> signed by the named origin — any authenticated member can forge
> edges and subnets for any other. See [`SECURITY.md`](SECURITY.md)
> for the trust boundary and the `StrictSubnets` / `TunnelServer`
> mitigations.

```mermaid
sequenceDiagram
    participant A as Node A
    participant B as B (direct peer)
    participant C as C (via B)
    Note over A,B: TCP connect
    A->>B: ID A 17.7
    B->>A: ID B 17.7
    Note over A,B: SPTPS handshake (stream mode)
    A->>B: ACK { port, weight, options }
    B->>A: ACK { port, weight, options }
    Note over A,B: meta-connection active — edge A↔B exists
    par gossip flood
        B->>A: ADD_EDGE / ADD_SUBNET × N (B's view of the mesh)
        A->>B: ADD_EDGE / ADD_SUBNET × N (A's view)
    end
    Note over A: A now knows C exists, routed via B
    A->>B: REQ_KEY A→C { SPTPS KEX }
    B->>C: REQ_KEY (fwd,<br/>+A's observed addr)
    C->>B: ANS_KEY C→A { KEX reply }
    B->>A: ANS_KEY (fwd,<br/>+C's observed addr)
    Note over A,C: A↔C datagram SPTPS established<br/>both sides hole-punch toward the appended addrs
    A-->>C: UDP data (direct, once a path is confirmed)
    loop keepalive
        A->>B: PING
        B->>A: PONG
        Note over A: RTT feeds A↔B edge weight
    end
```

Why ASCII lines in 2026? Because that's what's deployed, and goal one
is interop. But the format has a property worth pointing out: parsing
is permissive, and extra trailing tokens on a line are ignored. That's
the entire extension mechanism. tincr uses it in three places —

- an extra "your UDP probe arrived" length on `MTU_INFO`, so a node
  whose inbound UDP is filtered can still learn its *outbound* UDP
  works;
- an extra reflexive address on `REQ_KEY` in the reverse direction,
  doubling the NAT-punch hit rate;
- re-advertising `ADD_EDGE` when measured RTT drifts, rather than
  pinning the weight at whatever the TCP handshake happened to
  measure;

— and a C tinc node parses the part it understands and ignores the
rest. No version negotiation, no capability bits, no flag day.

A separate `ID`-line form, with a hash in place of the name, drives
the invitation protocol: a fresh node connects with an invite cookie
instead of an identity, and the server provisions it with a name,
keys, and starter host files over the same SPTPS channel.

## Data framing

Once two nodes share a datagram-mode SPTPS session, VPN traffic flows
as UDP between them. Each datagram is:

```
dst_id6 ‖ src_id6 ‖ seqno ‖ type ‖ ciphertext ‖ tag
```

`dst_id6` and `src_id6` are 6-byte node identifiers (a hash of the
node name). They sit *outside* the encrypted portion so a relay can
read `dst_id6`, consult its own routing table, and forward the
datagram onward without holding any key material for it. Everything
from `seqno` onward is a standard SPTPS datagram record.

The record `type` byte says what the plaintext is: a raw IP packet
(router mode), a full Ethernet frame (switch/hub mode), the same but
compressed, or a PMTU probe. In router mode the Ethernet header is
stripped before encryption and synthesised again on the far side from
the IP version nibble — 14 bytes per packet that never hit the wire.

Direct UDP is always preferred. When it isn't available — path MTU
still unknown, UDP filtered, no address learned yet — the same
payload is wrapped as a meta-protocol `SPTPS_PACKET` and sent over
the TCP stream to the next hop instead. PMTU discovery runs in the
background, ratcheting probe sizes upward; as soon as a working size
is confirmed (by a UDP reply, or by a meta-protocol acknowledgement
when the reply direction is filtered), data moves to UDP.

```mermaid
stateDiagram-v2
    direction LR
    [*] --> NoSession
    NoSession: NoSession<br/>(traffic TCP-tunneled<br/>via nexthop)
    NoSession --> Handshaking: REQ_KEY
    Handshaking --> TcpFallback: SPTPS up,<br/>minmtu = 0
    state Established {
        direction LR
        TcpFallback --> DirectUDP: PMTU probe<br/>confirmed
        DirectUDP --> TcpFallback: UDP timeout /<br/>EMSGSIZE
    }
    Established --> Handshaking: KeyExpire /<br/>KEY_CHANGED
```

While in **NoSession** or **Handshaking**, packets for the node are
wrapped as `SPTPS_PACKET` and relayed over the TCP meta-connection to
the nexthop. **TcpFallback** has a session but no working UDP path
yet; **DirectUDP** is the steady state. Any state returns to
**NoSession** when the graph marks the node unreachable.

## DHT rendezvous (out of band)

This part has no equivalent in C tinc. Its job is to remove the last
piece of static configuration: the `Address =` line pointing at a
relay someone has to keep on a fixed IP.

The mechanism is BEP 44 mutable items on the public BitTorrent
Mainline DHT — millions of nodes, no infrastructure of ours. The
problem with publishing to a public DHT, of course, is that it's
public: a crawler shouldn't be able to enumerate mesh members or
watch a node move between networks. So two layers of blinding:

1. **The lookup key** is the node's Ed25519 identity *blinded* with a
   factor derived from the mesh name, the public key, and the current
   day. Anyone holding the node's host file can derive today's key
   and verify the signature; anyone without it sees a fresh random
   key every 24 h, unlinkable to yesterday's and to the identity. The
   DHT storer can verify the record is signed by the key it's stored
   under — that's all BEP 44 requires — without learning whose
   identity that key belongs to.

2. **The value** — the actual address list — is encrypted with
   XChaCha20-Poly1305 under a key derived from the same inputs plus
   an optional mesh-wide secret. With no secret configured, holding
   any host file is enough to read records. With one configured,
   resolution is gated to nodes that also hold the secret, so a
   leaked host file alone is useless.

A peer that wants to find a node derives today's blinded key, fetches
the item, decrypts it, and dials. Neither side needed a fixed
address; nothing on the DHT links the record to the mesh; and a C
tinc node in the same mesh is simply unaware any of this happened —
it sees an inbound connection like any other.
