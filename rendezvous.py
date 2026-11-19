#!/usr/bin/env python3
"""The Orpheic rendezvous — the one always-reachable point, doing as little as possible.

Phases E and F of docs/design/remote-streaming.md. Three jobs, and deliberately nothing else:

  1. DESKTOPS dial OUT to this server (no port forwarding, ever — outbound needs none) and
     register under their Ed25519 identity, proving it by signing a challenge. The newest
     registration for a key wins; the socket doubles as the wake-up line.
  2. A PHONE that wants its desktop opens a RELAY circuit naming that key. The desktop is
     nudged over its control socket, attaches from its side, and this server SPLICES the two
     — copying bytes it cannot read, because what flows is the Link's TLS, pinned end to end
     to the very identity used to register. The relay is blind by construction, not by
     promise: to read the stream it would need the desktop's key, and it only ever holds the
     public half. THE RELAY IS A TEMPORARY ROAD (§5.6): once hole punching is field-proven,
     this server introduces and never carries.
  3. The MEETING for that punch (Phase F): a UDP ear that answers "what do I look like from
     outside?" with the address it saw, and a punch message — the phone says "punch me to
     key X, I look like A", the desktop is told over its control socket, both ends fire
     outbound at each other's observed address, the packets cross, and the connection that
     follows is direct. A few datagrams of introduction; not one byte of music.

What this server learns, honestly: which public keys are online, from which addresses, and
who talked to whom, when, for how long. That metadata is unavoidable — it is why you run
this on YOUR OWN machine and nobody else's.

Wire:
  control  (WebSocket: public port 8750, and/or a Unix socket behind OUR nginx for wss://<host>/rv —
            ε#3, server/LEVEL-B-PLAN.md D4-D6):
    S→C  {"t":"challenge","nonce":"<b64 16B>"}
    C→S  {"t":"register","v":2,"ep":"<server name>","pub":"<b64 32B>",
          "sig":"<b64 sign('orpheic-rv-v2-register\\0' + u8 len(ep) + ep + nonce)>"}
                                                    ← v2: the signature names WHICH server it is for, so
                                                      another rendezvous cannot pass it on to us. `ep` must
                                                      be one of RV_SERVER_NAMES, byte for byte.
    C→S  {"t":"register","pub":…,"sig":"<b64 sign('orpheic-rv-v1-register'+nonce)>"}
                                                    ← v1, old desktops: ONLY on the public 8750 listener,
                                                      counted daily so its end date can be set.
    S→C  {"t":"registered"[,"doorsVersion":1,"doors":{"obs":[{host,port,proto}]}]}
                                                    ← the obs door, ONLY when RV_OBS_HOST has
                                                      split it out; the desktop observes against
                                                      it (validated public IP) and forwards it in
                                                      `welcome`. Absent ⇒ controlPort+2 convention.
    S→C  {"t":"incoming","cid":"<opaque>"}          ← someone dialed this key; attach now
    C→S  {"t":"udp","addr":"<observed ip:port>","lan":["<ip:port>",…]}   ← QUIC door update
    S→C  {"t":"punch","addr":"<ip:port>"}           ← fire your burst at this address, now
  relay    (plain TCP, port 8751), one preamble line then raw bytes both ways:
    dialer:   RV1 dial <desktopPubB64>\n
    desktop:  RV1 attach <cid>\n
    query:    RV1 query <desktopPubB64>\n           → {"cands":[…],"relay":bool,"grant":null|{…}}
    punch:    RV1 punch <desktopPubB64> <ip:port>\n → {"udp":…,"lan":[…],"relay":bool,"grant":…}
  The plaintext query/punch answers carry NO `doors`: the obs endpoint the phone will send UDP
  to rides ONLY the authenticated welcome (desktop-forwarded), never a forgeable plaintext line.
  `relay` is the LEGACY bool (retired ticketless dial/attach). The relay's real, future path
  is `grant`: null today, a per-session Ed25519-signed ticket {endpoint,ticket,expiry} when the
  paid relay ships — bound to BOTH peers' pubkeys + a pairId, verified OFFLINE at the relay door
  (`RV1 relay <ticket-b64> <role d|p>`) before one byte, so enabling it is server-side only.
  RV_RELAY=off makes this server a pure introducer: dial/attach are refused, the "relay"
  flag tells phones so they can say an honest sentence instead of dialling a wall.
  observation (UDP, port 8752), the sideline language of link/src/magic.rs:
    C→S  "ORPH1 obs? <nonce>"    S→C  "ORPH1 obs=<ip:port as this server saw it> <nonce>"   (A10 B6: 16 lower-case
                                                    hex digits, zero-padded to 80 bytes, echoed, so an answer forged
                                                    from our address with another address in it is not believed)
    C→S  "ORPH1 obs?"            S→C  "ORPH1 obs=<ip:port as this server saw it>"           (old Links, unchanged)

Every door is rate-limited per source IP (loopback exempt), with global ceilings and idle
eviction, so a flood exhausts nobody — see the "Abuse defence" block. The server holds no
secrets and carries no music, so availability is the only thing there is to protect.

Runs on: python3 + python3-websockets + python3-nacl (all in Ubuntu 24.04's apt).
Deploy: /opt/orpheic-rendezvous/ + the systemd unit (server/DEPLOY.md).
"""

import asyncio
import binascii
import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import socket
import stat
import sys
import time

import websockets
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

CONTROL_PORT = int(os.environ.get("RV_CONTROL_PORT", "8750"))
RELAY_PORT = int(os.environ.get("RV_RELAY_PORT", "8751"))
OBS_PORT = int(os.environ.get("RV_OBS_PORT", "8752"))
SIGN_PREFIX = b"orpheic-rv-v1-register"
SIGN_PREFIX_V2 = b"orpheic-rv-v2-register\0"

# --- ε#3: wss through our nginx, and a signature that names its server (server/LEVEL-B-PLAN.md D4-D6) --------------
# The names this server answers to, ALREADY in canonical form (A-label, lower case, no trailing dot; IP literals
# compressed), comma-separated. The v2 signature's name is compared to them byte for byte: this server never
# canonicalises what a desktop sends (Python's built-in IDNA is 2003 and Qt's is UTS#46: they differ, on the Greek final
# sigma among others). Unset: v2 is refused, never guessed from a Host header.
def _canonical_name(n: str) -> bool:
    """Is this entry ALREADY in the form a desktop signs? Never fixed up here: a wrong entry is refused and reported, so
    the operator sees it instead of a server that silently answers to a name no desktop will ever sign."""
    if not n or not n.isascii() or len(n) > 253 or n != n.lower() or n.endswith(".") or n.startswith("["):
        return False
    try:
        a = ipaddress.ip_address(n)
    except ValueError:
        # A name: no port, no IPv6 that failed to parse, and not a numeric spelling the desktop would rewrite
        # (01.2.3.4 or 1.2.3 are signed as 1.2.3.4 or 1.2.0.3, never as written).
        return ":" not in n and re.fullmatch(r"[0-9.]+", n) is None
    if "%" in n or (a.version == 6 and a.ipv4_mapped is not None):
        return False                 # a zone, or ::ffff:x.x.x.x (the desktop signs the IPv4)
    return str(a) == n               # IPv4 dotted, IPv6 compressed (RFC 5952): exactly as written


def _server_names(raw: str):
    """(accepted names as bytes, refused entries as written)."""
    names, bad = set(), []
    for n in (raw or "").split(","):
        n = n.strip()
        if not n:
            continue
        if _canonical_name(n):
            names.add(n.encode("ascii"))
        else:
            bad.append(n)
    return frozenset(names), bad


SERVER_NAMES, SERVER_NAMES_BAD = _server_names(os.environ.get("RV_SERVER_NAMES", ""))
# The public control listener (8750). Closing it later is THIS switch, never RV_BIND, which would also close the relay
# (8751) and obs (8752) that phones need (D6).
CONTROL_PUBLIC = os.environ.get("RV_CONTROL_PUBLIC", "on").strip().lower() not in ("off", "0", "false", "no")
# The Unix socket nginx proxies wss://<host>/rv to (D4). In a directory only this user may write to (systemd's
# RuntimeDirectory), so nobody can take its place; WHO may connect is decided by the secret below. Empty = none.
CONTROL_SOCKET = os.environ.get("RV_CONTROL_SOCKET", "").strip()
# nginx proves it is OUR nginx with this header (two values during a rotation: add the new one here, switch nginx,
# remove the old). From a root-only EnvironmentFile; never logged, never in git or in a backup. Shorter than 32
# characters counts as unset, so the socket refuses everyone rather than trust a guessable value.
def _proxy_secrets(env) -> tuple:
    return tuple(v.encode() for v in (env.get("RV_PROXY_SECRET", ""), env.get("RV_PROXY_SECRET_NEXT", "")) if len(v) >= 32)


PROXY_SECRETS = _proxy_secrets(os.environ)
# The v1 count (D6): how many DISTINCT old desktops still register the v1 way, per period — the number its end date is
# set from. Only the count is logged; the set holds a hash prefix per key, in memory, and is emptied every period.
V1_COUNT_S = int(os.environ.get("RV_V1_COUNT_S", "86400"))
V1_SEEN_MAX = 100000
v1_seen: set = set()


def v1_tick():
    """Log the period's count of distinct v1 desktops and start a new period."""
    n = len(v1_seen)
    v1_seen.clear()
    log.info("v1 desktops in the last %d s: %s", V1_COUNT_S, f"{n}+" if n >= V1_SEEN_MAX else n)
# On the socket listener (S5, R1): a handshake must finish quickly, and only so many NOT-YET-REGISTERED connections may
# be open at once, so a flood of slow connections (through nginx from the internet, or from a local process) cannot use
# up the descriptors every door needs, nor the slots of the homes already registered.
SOCKET_OPEN_TIMEOUT = 5
SOCKET_MAX_OPEN = int(os.environ.get("RV_SOCKET_MAX_OPEN", "4096"))
_socket_open = 0

# --- Advertised doors (Level B: decision 1) -----------------------------------------------
# ONE thing is advertised and movable: the obs (UDP) door. query/punch stay with the control
# box (the phone reaches them at the control host it already trusts, by convention), and the
# relay's byte-carry is a FUTURE per-session grant, never a static door. Advertise obs ONLY when
# the operator has EXPLICITLY split it out via RV_OBS_HOST — otherwise omit doors entirely and
# every client keeps the controlPort+2 convention (identical to today). NO prod default: an
# unconfigured / self-hosted / dev server advertises nothing and can never redirect its clients
# at a stranger's box. The advertised value should be a PUBLIC IP LITERAL: the client refuses a
# DNS name or a private/loopback address, because this endpoint reaches it over a plaintext,
# on-path-forgeable channel and must never be able to name a victim or a host inside its LAN.
DOORS_VERSION = 1
OBS_PUB_HOST = os.environ.get("RV_OBS_HOST")            # None ⇒ do NOT advertise (use convention)
OBS_PUB_PORT = int(os.environ.get("RV_OBS_PUB_PORT", str(OBS_PORT)))


def obs_doors():
    """The advertised doors block, or None when obs has not been explicitly split out."""
    if not OBS_PUB_HOST:
        return None
    return {"obs": [{"host": OBS_PUB_HOST, "port": OBS_PUB_PORT, "proto": "udp"}]}

# Bind address for all three doors. "::" is DUAL-STACK on Linux (net.ipv6.bindv6only=0, the
# default): one socket answers BOTH IPv6 and IPv4 — the latter arriving as ::ffff:x.x.x.x,
# which norm_ip() flattens straight back to x.x.x.x so nothing downstream sees the mapped
# form. Until this is "::", the AAAA record is an empty promise: a v6-preferring phone dials
# the IPv6 address, finds no socket listening, and never gets introduced. An operator whose
# box genuinely has no IPv6 can set RV_BIND=0.0.0.0 to go back to IPv4-only.
BIND = os.environ.get("RV_BIND", "::")

# The policy switch (§5.6): RV_RELAY=off turns this server into a PURE introducer — it
# meets, it observes, it orders punches, and it will not carry one byte of anyone's music.
# Each operator sets the policy of their own machine; the phones are told (the "relay" flag
# in query/punch answers) so they can say an honest sentence instead of dialling a wall.
# Flip it once hole punching has earned your trust in the field; until then the relay is
# the net under the acrobat.
RELAY_ON = os.environ.get("RV_RELAY", "on").strip().lower() not in ("off", "0", "false", "no")

ATTACH_TIMEOUT = 10        # desktop must attach this fast, or the dialer is told no
IDLE_TIMEOUT = 300         # a circuit with no bytes in five minutes is dead, not resting
MAX_CIRCUITS = 128         # a home's worth of listening, not a botnet's
PREAMBLE_MAX = 128

log = logging.getLogger("rendezvous")

# --- Abuse defence (§5.6/§5.7) ------------------------------------------------------------
# The rendezvous holds no secrets and carries no music, so the only thing an attacker can
# take is its AVAILABILITY. These caps stop any single source from exhausting it, while
# staying generous enough for a whole home — or a shared CGNAT address — behind one IP.
# Everything keys off the SOCKET PEER, the true remote address on all three transports today
# (the public control WS on 8750 is direct). Behind nginx (wss://<host>/rv, the socket listener) the control WS keys
# off X-Real-IP, taken ONLY with our nginx's secret (proxied_ip, D4); obs/relay stay socket-peer, always direct.
# LOOPBACK is exempt only when RV_LIMIT_LOCAL is off: the operator's own testing (production has it on).
MAX_DESKTOPS     = int(os.environ.get("RV_MAX_DESKTOPS", "5000"))    # global registry ceiling
MAX_CONN_PER_IP  = int(os.environ.get("RV_MAX_CONN_PER_IP", "32"))   # live control WS per IP
MAX_DIALS_PER_IP = int(os.environ.get("RV_MAX_DIALS_PER_IP", "8"))   # parked dials per IP
CHALLENGE_S      = int(os.environ.get("RV_CHALLENGE_S", "8"))        # register within; sign is instant


class RateLimit:
    """A token bucket per key: `capacity` tokens, refilled `rate`/second, one spent per hit.
    Lazy — each key refills on access, and `sweep()` drops idle (full) keys so the map cannot
    grow without bound. No thread, no lock: the whole server is one asyncio loop."""

    def __init__(self, capacity, rate):
        self.capacity = float(capacity)
        self.rate = float(rate)
        self.buckets: dict = {}

    def allow(self, key) -> bool:
        now = time.monotonic()
        tok, last = self.buckets.get(key, (self.capacity, now))
        tok = min(self.capacity, tok + (now - last) * self.rate)
        if tok < 1.0:
            self.buckets[key] = (tok, now)
            return False
        self.buckets[key] = (tok - 1.0, now)
        return True

    def sweep(self):
        # Refill-aware: a key is idle if it WOULD be full now, not merely if its last stored
        # value was full — tokens refill lazily on access, so a spent-then-abandoned key sits
        # below capacity forever and would never be evicted otherwise (the very leak this
        # guards against). Still-spending keys stay.
        now = time.monotonic()
        dead = [k for k, (tok, last) in self.buckets.items()
                if min(self.capacity, tok + (now - last) * self.rate) >= self.capacity]
        for k in dead:
            del self.buckets[k]


# New connections per source per second (WS and relay both): the cheapest flood to mount.
conn_rate  = RateLimit(int(os.environ.get("RV_CONN_BURST", "30")),  float(os.environ.get("RV_CONN_RATE", "5")))
# Registrations per source: a whole CGNAT of desktops fits the burst; a flood does not.
reg_rate   = RateLimit(int(os.environ.get("RV_REG_BURST", "20")),   float(os.environ.get("RV_REG_RATE", "0.5")))
# Relay preambles (query/punch/dial/attach) per source.
relay_rate = RateLimit(int(os.environ.get("RV_RELAY_BURST", "30")), float(os.environ.get("RV_RELAY_RATE", "5")))
# Obs answers per source, plus a global ceiling to bound spoofed-source reflection.
obs_rate   = RateLimit(int(os.environ.get("RV_OBS_BURST", "20")),   float(os.environ.get("RV_OBS_RATE", "5")))
obs_global = RateLimit(int(os.environ.get("RV_OBS_GLOBAL_BURST", "2000")), float(os.environ.get("RV_OBS_GLOBAL_RATE", "1000")))
MAX_LIVE = int(os.environ.get("RV_MAX_LIVE", str(2 * MAX_DESKTOPS)))  # global accept ceiling (fd backstop)
_live_conns = 0           # total control WS past accept — the /64-rotation + fd-exhaustion backstop
conns_per_ip: dict = {}   # rate_key(ip) -> live control WS count
dials_per_ip: dict = {}   # ip -> parked dial count


def norm_ip(ip: str) -> str:
    """A v4-mapped IPv6 address (::ffff:1.2.3.4) — which a dual-stack "::" socket reports for
    every IPv4 peer — is just IPv4 wearing a hat. Flatten it back to 1.2.3.4 so the punch
    protocol, the candidate strings, the rate-limit keys and the obs answer never see the
    mapped form. This matters most for the punch: the desktop's IPv4 magic socket must be told
    to fire at 1.2.3.4, not at [::ffff:1.2.3.4] which it cannot parse."""
    if ip and ip.startswith("::ffff:") and "." in ip:
        return ip[len("::ffff:"):]
    return ip


def ip_of(addr) -> str:
    return norm_ip(addr[0]) if addr else ""


def rate_key(ip: str) -> str:
    """Fairness key for the rate/conn limits. An IPv6 host owns a whole /64 by default, so keying
    on the full address lets ONE attacker mint unlimited "distinct IPs" and slip every per-IP cap
    (MAX_CONN_PER_IP, the token buckets). Collapse v6 to its /64 network; v4 keeps its full
    address. NEVER used for the punch target or candidate strings — those need the exact peer
    address (see norm_ip). Server-side audit, 4/9."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if a.version == 6:
        return str(ipaddress.ip_network((ip, 64), strict=False).network_address)
    return ip


_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def scrub(s) -> str:
    """Strip C0/C1/DEL control bytes from any attacker-supplied string before it reaches a log
    line — a raw CR/LF/ANSI would forge journal entries or spoof an admin's terminal. Same class
    as the desktop's log-scrub fix. Server-side audit, 4/9."""
    return _CTRL.sub("", s) if isinstance(s, str) else str(s)


# Set RV_LIMIT_LOCAL=1 to make loopback NON-exempt — the only way to exercise the caps from
# a test on one machine (real abuse comes from real remote IPs). Off in production.
_LIMIT_LOCAL = os.environ.get("RV_LIMIT_LOCAL", "").strip() in ("1", "true", "yes")


def is_local(ip: str) -> bool:
    if _LIMIT_LOCAL:
        return False
    return ip.startswith("127.") or ip in ("::1", "::ffff:127.0.0.1")


def canon(pub_b64: str) -> str:
    """Κανονικοποίηση του κλειδιού αναζήτησης, ίδια με το register (Fable): το raw base64 του
    αιτούντος στο relay πρέπει να ταιριάξει το κανονικό κλειδί του μητρώου. Κενό αν δεν είναι
    έγκυρο 32-byte κλειδί — τότε το desktops.get(...) δεν βρίσκει τίποτα."""
    try:
        p = base64.b64decode(pub_b64)
        return base64.b64encode(p).decode() if len(p) == 32 else ""
    except Exception:
        return ""


def _host_of(hostport: str):
    """The IP out of "ip:port" or "[v6]:port" — for binding a punch target to its asker.
    None when it does not parse, which the caller treats as "cannot verify → refuse"."""
    hostport = hostport.strip()
    if hostport.startswith("["):
        end = hostport.rfind("]")
        return hostport[1:end] if end > 0 else None
    colon = hostport.rfind(":")
    return hostport[:colon] if colon > 0 else None


def _is_public_cand(hostport: str) -> bool:
    """True only for a `host:port` whose host is a globally-routable IP. A private, link-local,
    loopback, or unparseable candidate → False, so it is dropped for any querier who is not on
    the desktop's own network."""
    h = _host_of(hostport)
    if not h:
        return False
    try:
        return ipaddress.ip_address(h).is_global
    except ValueError:
        return False


def _same_nat(peer_ip, desk_ws) -> bool:
    """Is this querier behind the SAME public IP as the desktop (≈ on its home network)? Only
    then are the desktop's LAN candidates useful — and only then is it not internal-topology
    disclosure to hand them out. Fail-closed: any unknown → treat as a stranger."""
    if peer_ip is None or desk_ws is None:
        return False
    d = desk_ip(desk_ws)     # the REAL address the desktop registered from (X-Real-IP behind nginx), not the socket peer
    return bool(d) and peer_ip == d


def _lan_filtered(cands, peer_ip, desk_ws):
    """The candidate list a NON-same-NAT querier may see: only the globally-routable door(s).
    A same-NAT querier gets the list untouched (the LAN address is its fast path)."""
    if _same_nat(peer_ip, desk_ws):
        return cands
    return [c for c in cands if _is_public_cand(c)]


# pub (b64 str) -> live control websocket of that desktop. Newest registration wins.
desktops: dict[str, websockets.ServerConnection] = {}
# pub (b64 str) -> direct-connection candidates, "host:port" strings, best first. Composed
# here: the desktop reports its LAN addresses and (when UPnP obliged) the router port it
# mapped; the PUBLIC address is what this server OBSERVED the registration arrive from —
# more truthful than anything the desktop could claim about itself.
candidates: dict[str, list[str]] = {}
# pub (b64 str) -> the desktop's QUIC door for punching: {"udp": "<observed ip:port>",
# "lan": [...], "ts": monotonic-of-arrival}. The desktop learned "udp" from OUR own ear
# (below) and reports it here, because only the desktop can ask from the right socket — the
# mapping belongs to the port. An IDLE desktop reports rarely (economy: it pays no UDP when
# nobody is listening), so a punch may find this stale — see the wait in relay().
quic: dict[str, dict] = {}
# pub (b64 str) -> event set whenever a fresh udp report lands — what a punch waits on.
fresh: dict[str, asyncio.Event] = {}
FRESH_S = 30               # a report this recent is trusted as-is; older, we ask and wait
PUNCH_WAIT_S = 2.5         # how long a dialer waits for a cold desktop to look in a mirror
# cid -> the dialer's (reader, writer), parked while the desktop attaches.
pending: dict[str, tuple[asyncio.StreamReader, asyncio.StreamWriter]] = {}
circuits = 0


_loud_at: dict = {}


def _loud(msg: str):
    """A warning that must be seen but must not flood the journal: at most once a minute per message."""
    now = time.monotonic()
    if now - _loud_at.get(msg, -1e9) >= 60:
        _loud_at[msg] = now
        log.warning(msg)


def _header_values(ws, name: str) -> list:
    """Every value of one request header, on both websockets APIs (legacy `request_headers`, new `request.headers`)."""
    req = getattr(ws, "request", None)
    h = getattr(req, "headers", None) if req is not None else None
    if h is None:
        h = getattr(ws, "request_headers", None)
    if h is None:
        return []
    try:
        return list(h.get_all(name))
    except AttributeError:
        v = h.get(name)
        return [v] if v is not None else []


def proxied_ip(ws):
    """The real client IP of a connection on the socket listener, or None = refuse (D4). Only with OUR nginx's secret
    (constant-time compare, no early exit), and only ONE X-Real-IP that is ONE valid address. A missing or wrong secret
    is never a quiet fallback to the socket peer: that would put every wss desktop behind one shared address."""
    got = _header_values(ws, "X-Orpheic-Proxy")
    ok = False
    if len(got) == 1 and PROXY_SECRETS:
        g = got[0].encode("utf-8", "replace")
        for sec in PROXY_SECRETS:
            ok = hmac.compare_digest(g, sec) or ok
    if not ok:
        _loud("proxy secret missing or wrong — check the nginx include")
        return None
    vals = _header_values(ws, "X-Real-IP")
    try:
        if len(vals) != 1 or "%" in vals[0]:
            raise ValueError
        a = ipaddress.ip_address(vals[0].strip())
    except ValueError:
        _loud("X-Real-IP missing, repeated or not one address — check the nginx block")
        return None
    if a.version == 6 and a.ipv4_mapped is not None:
        a = a.ipv4_mapped
    return norm_ip(str(a))


# ws -> the address every consumer must see: the socket peer on 8750, nginx's X-Real-IP on the socket listener.
real_ip: dict = {}


def desk_ip(ws) -> str:
    return real_ip.get(ws) or (ip_of(ws.remote_address) if ws is not None else "")


async def control_public(ws):
    """The public 8750 listener: the socket peer is the client. v1 (old desktops); v2 only when this server has NO TLS
    front (a self-hosted server without TLS). With a socket listener, a v2 desktop belongs on wss: one typed ws://…:8750
    must not quietly sign our name over plaintext (S3)."""
    await control(ws, ip_of(ws.remote_address), v1_ok=True, via="8750", v2_ok=not CONTROL_SOCKET)


async def control_proxied(ws):
    """The Unix-socket listener behind nginx: every client here is new, so v2 ONLY (D6)."""
    ip = proxied_ip(ws)
    if ip is None:
        await ws.close(1008)
        return
    if not SERVER_NAMES:
        # v2 only here, and v2 needs our names: refuse BEFORE the challenge, so check-rv-cert.sh's probe sees it.
        _loud("control socket: RV_SERVER_NAMES is not set — every registration would be refused")
        await ws.close(1011)
        return
    await control(ws, ip, v1_ok=False, via="socket")


async def _drop(ws):
    """Refuse at once, without the closing handshake: a graceful close holds the socket (and, on the socket listener, a
    slot) for up to ~10 s, which is exactly what a flood wants (R1). After the abort, WAIT for the connection to be
    closed: the legacy handler calls close() when we return, and on a line that is not yet seen as closed that close()
    fails and logs "closing handshake failed" with a traceback, one per refusal (third look, #1)."""
    t = getattr(ws, "transport", None)
    if t is not None:
        t.abort()
        try:
            await ws.wait_closed()
        except Exception:
            pass
    else:
        await ws.close()


def _release_slot(ws):
    """A registered desktop no longer counts against the socket listener's ceiling (R1): the ceiling bounds the
    connections NOT yet proven, never the homes already registered."""
    rel = getattr(ws, "release_slot", None)
    if rel is not None:
        rel()


async def control(ws, ip, v1_ok=True, via="8750", v2_ok=True):
    """Guard the connection with the per-IP caps, then serve it."""
    global _live_conns
    rk = rate_key(ip)   # v6 collapsed to /64 so a single host's address-churn can't slip the caps
    # Global accept ceiling FIRST: the /64 fix bounds one source, this bounds the fleet so a
    # botnet of many IPs (or a soft LimitNOFILE) can't fd-starve every other user's remote.
    if not is_local(ip) and _live_conns >= MAX_LIVE:
        await _drop(ws)
        return
    if not is_local(ip) and (not conn_rate.allow(rk)
                             or conns_per_ip.get(rk, 0) >= MAX_CONN_PER_IP):
        await _drop(ws)
        return
    conns_per_ip[rk] = conns_per_ip.get(rk, 0) + 1
    _live_conns += 1
    real_ip[ws] = ip
    try:
        await _control(ws, ip, v1_ok, via, v2_ok)
    finally:
        real_ip.pop(ws, None)
        _live_conns -= 1
        left = conns_per_ip.get(rk, 0) - 1
        if left > 0:
            conns_per_ip[rk] = left
        else:
            conns_per_ip.pop(rk, None)


async def confirm_public(ip, ports, key):
    """The PUBLIC door, verified rather than believed: whether it was UPnP-mapped or the user forwarded a port by hand,
    the only address worth handing out is one THIS server just knocked on and found open. A mapping a router accepted
    and then drops would otherwise cost every phone a timeout."""
    # ΠΟΤΕ μη «χτυπάς» loopback/RFC1918: με RV_LIMIT_LOCAL=1 το is_local() είναι νεκρό εδώ
    # (γι' αυτό ο άμεσος έλεγχος)· κόβει το να γίνει ο server σαρωτής εσωτερικών υπηρεσιών
    # (server-side audit 4/9). Το residual (public-IP port-scan CGNAT-γειτόνων) το φράζει το reg_rate.
    try:
        _a = ipaddress.ip_address(ip)
        if _a.is_loopback or _a.is_private or _a.is_link_local:
            return
    except ValueError:
        return
    for port in ports:
        if not (isinstance(port, int) and 1024 <= port < 65536):   # καμία προνομιακή θύρα
            continue
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=3)
            w.close()
        except Exception:
            continue
        c = candidates.get(key)
        if c is not None:
            c.insert(0, f"{ip}:{port}")
            log.info("public door confirmed %s:%d for %s…", ip, port, key[:12])
        return


async def _control(ws, ip, v1_ok=True, via="8750", v2_ok=True):
    """One desktop's control connection: challenge, verify, then hold the line."""
    nonce = secrets.token_bytes(16)
    await ws.send(json.dumps({"t": "challenge", "nonce": base64.b64encode(nonce).decode()}))
    try:
        raw = await asyncio.wait_for(ws.recv(), timeout=CHALLENGE_S)
        m = json.loads(raw)
        if not isinstance(m, dict):        # [] / 7 / "x": m.get θα έριχνε AttributeError, όχι στο except (Fable)
            await _drop(ws)
            return
        pub = base64.b64decode(m.get("pub", ""))
        sig = base64.b64decode(m.get("sig", ""))
        if m.get("t") != "register" or len(pub) != 32:
            await _drop(ws)
            return
        ver = m.get("v")
        if ver is None and v1_ok:
            VerifyKey(pub).verify(SIGN_PREFIX + nonce, sig)   # raises when it does not hold
            is_v1 = True
        elif type(ver) is int and ver == 2 and v2_ok:
            # D5: the name the desktop dialled, framed, then the nonce. Compared to OUR names byte for byte.
            ep = m.get("ep")
            epb = ep.encode("utf-8") if isinstance(ep, str) else b""
            if epb not in SERVER_NAMES:
                if not SERVER_NAMES:
                    _loud("a v2 registration refused: RV_SERVER_NAMES is not set")
                await _drop(ws)
                return
            VerifyKey(pub).verify(SIGN_PREFIX_V2 + bytes([len(epb)]) + epb + nonce, sig)
            is_v1 = False
        else:
            await _drop(ws)    # v1 where only v2 belongs (the socket listener), or an unknown version
            return
        # ΚΑΝΟΝΙΚΟ κλειδί: το raw base64 του πελάτη είναι εύπλαστο (padding/τελευταία bytes) — ένα
        # ζεύγος κλειδιών θα έπιανε πολλές θέσεις στο μητρώο. Κλειδί = re-encode των 32 bytes (Fable).
        pub_b64 = base64.b64encode(pub).decode()
    except (asyncio.TimeoutError, BadSignatureError, ValueError, TypeError, KeyError,
            json.JSONDecodeError, websockets.ConnectionClosed):
        # No answer, a bad signature, junk: refused at once. A graceful close here held an unregistered slot for
        # CHALLENGE_S + close_timeout, ~18 s (third look, #2).
        await _drop(ws)
        return

    # Past the signature — a genuine registration attempt. Bound how fast one source may make
    # them, and cap the registry globally, so no flood of free keys can exhaust memory.
    if not is_local(ip) and not reg_rate.allow(rate_key(ip)):
        await _drop(ws)
        return
    if pub_b64 not in desktops and len(desktops) >= MAX_DESKTOPS:
        log.info("registry full (%d) — refusing a new key", len(desktops))
        await _drop(ws)
        return
    if is_v1 and len(v1_seen) < V1_SEEN_MAX:
        v1_seen.add(hashlib.sha256(pub).digest()[:8])
    _release_slot(ws)

    old = desktops.get(pub_b64)
    desktops[pub_b64] = ws
    try:
        if old is not None and old is not ws:
            await old.close()          # the newest registration IS this desktop now

        # Candidates, public first: the address this registration ARRIVED from plus the router
        # port the desktop mapped (if any), then its LAN addresses for a phone that is actually
        # at home. Handing them out is safe by construction — the dialer's TLS pin means a wrong
        # or hostile address simply fails a signature.
        # Everything after `desktops[pub_b64] = ws` now runs INSIDE the try/finally below, so any
        # raise here (a bad `lan` shape, or the `registered` send hitting a client that closed the
        # instant it signed) still cleans the registry entry — no phantom desktop left "online"
        # for phones to dial forever, no free-key flood filling MAX_DESKTOPS permanently (Fable A6).
        # We still validate the `lan` shape rather than lean on the finally, so a common case does
        # not spew a traceback on every register.
        raw_lan = m.get("lan", [])
        cands = []
        if isinstance(raw_lan, list):
            for lan in raw_lan[:8]:
                if isinstance(lan, str) and 0 < len(lan) < 64:
                    cands.append(lan)
        candidates[pub_b64] = cands
        log.info("registered %s… from %s cands=%d %s via %s", pub_b64[:12], ip, len(cands), "v1" if is_v1 else "v2", via)

        # The PUBLIC door, verified rather than believed (confirm_public, above). With the REAL client address: through
        # nginx the socket peer is this machine, and the knock would go nowhere (D4).
        if ip:
            asyncio.create_task(confirm_public(ip, [m.get("mapped", 0), m.get("port", 0)], pub_b64))
        # register-ack carries the obs door ONLY when obs has been explicitly split out; the
        # desktop then observes against it (a validated public IP) and forwards it to the phone
        # in `welcome`. Unset ⇒ no keys, and the desktop keeps the controlPort+2 convention.
        ack = {"t": "registered"}
        _doors = obs_doors()
        if _doors is not None:
            ack["doorsVersion"] = DOORS_VERSION
            ack["doors"] = _doors
        await ws.send(json.dumps(ack))
        async for raw in ws:
            # The one thing a registered desktop has to say: where its QUIC door lives now.
            try:
                upd = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if not isinstance(upd, dict):   # [] / 7 / "x": .get would raise, mirror register (audit 4/9)
                continue
            if upd.get("t") != "udp":
                continue
            addr = upd.get("addr", "")
            # The desktop's SECOND door: its IPv6 QUIC port, when it has an IPv6 leg. A v6 dial
            # is handed this one; a v4 dial the v4 "addr". Both belong to the same desktop, each
            # its own family's mapping/pinhole — see the punch answer below.
            addr6 = upd.get("addr6", "")
            addr6 = addr6 if isinstance(addr6, str) and 0 < len(addr6) < 64 else None
            _lan = upd.get("lan", [])
            lans = [l for l in (_lan[:8] if isinstance(_lan, list) else [])
                    if isinstance(l, str) and 0 < len(l) < 64]
            if isinstance(addr, str) and len(addr) < 64:
                quic[pub_b64] = {"udp": addr or None, "udp6": addr6,
                                 "lan": lans, "ts": time.monotonic()}
                if pub_b64 in fresh:
                    fresh[pub_b64].set()   # a punch is waiting on exactly this
                log.info("quic door v4=%s v6=%s for %s…",
                         scrub(addr) or "(none)", scrub(addr6) or "(none)", pub_b64[:12])
    finally:
        if desktops.get(pub_b64) is ws:
            del desktops[pub_b64]
            candidates.pop(pub_b64, None)
            quic.pop(pub_b64, None)
            fresh.pop(pub_b64, None)
            log.info("gone %s…", pub_b64[:12])


async def pipe(reader, writer):
    """Copy one direction until it ends; the idle timeout kills circuits nobody is using."""
    try:
        while True:
            data = await asyncio.wait_for(reader.read(65536), timeout=IDLE_TIMEOUT)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (asyncio.TimeoutError, ConnectionError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


# ── findd (docs/design/findability.md §12–§13): the heartbeat catalog, a separate process on the same box.
# Desktops beat to it over UDP from their QUIC socket, so it knows their CURRENT doors even when this
# server's WebSocket line to them is dead (4/11: a Mac woke with a new IPv6, the line stayed "open" to an
# address that no longer existed, and the phone outside was told nothing). We ask it over a local Unix
# socket: "where <pub-hex>" → "at <ip:port> …" | "none", and "punch <pub-hex> <ip> <port>" → it sends the
# desktop a MAC'd punch order (0x18) over UDP. Empty RV_FINDD_CTL = off (the old road alone).
FINDD_CTL = os.environ.get("RV_FINDD_CTL", "/run/orpheic-findd/ctl.sock")
FINDD_TIMEOUT_S = float(os.environ.get("RV_FINDD_TIMEOUT_S", "0.5"))


async def findd_ask(line: str):
    """One question to findd; its one-line answer, or None (off, absent, slow). Never raises."""
    if not FINDD_CTL:
        return None
    # our reply address sits beside findd's socket (same directory, same user) — findd answers there.
    # A random name per question: two questions in flight can never share a reply socket (F/S: with a
    # counter modulo 1000 a phone could have been handed ANOTHER desktop's door).
    me = os.path.join(os.path.dirname(FINDD_CTL), f"rv-{secrets.token_hex(8)}.sock")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        try:
            os.unlink(me)
        except FileNotFoundError:
            pass
        s.bind(me)
        s.setblocking(False)
        loop = asyncio.get_running_loop()
        s.sendto(line.encode(), FINDD_CTL)   # a local datagram: never blocks in practice
        data = await asyncio.wait_for(loop.sock_recv(s, 512), FINDD_TIMEOUT_S)
        return data.decode(errors="replace").strip()
    except (OSError, asyncio.TimeoutError):
        return None
    finally:
        s.close()
        try:
            os.unlink(me)
        except OSError:
            pass


def pub_hex(pub_b64: str):
    try:
        raw = base64.b64decode(pub_b64, validate=True)
    except (ValueError, binascii.Error):
        return None
    return raw.hex() if len(raw) == 32 else None


async def findd_punch(pub_b64: str, target: str):
    """Order the punch through findd and return the desktop's doors {"udp": v4, "udp6": v6} as
    findd knows them (fresh: they come from the last authenticated heartbeat), or None."""
    hx = pub_hex(pub_b64)
    host = _host_of(target)
    try:
        port = int(target.rsplit(":", 1)[1])
    except (IndexError, ValueError):
        return None
    if hx is None or host is None:
        return None
    sent, where = await asyncio.gather(findd_ask(f"punch {hx} {host} {port}"), findd_ask(f"where {hx}"))
    if not where or not where.startswith("at "):
        return None
    # findd answered but sent NO punch (its rate limits, or no live family): a door with no hole punched toward it is
    # not the fresh answer it claims to be — let the WebSocket road order the punch and wait for its mirror (review 6/11).
    if sent is not None and sent.strip() == "sent 0":
        log.info("findd: %s… sent no punch — the WebSocket road answers", scrub(pub_b64[:12]))
        return None
    doors = {"udp": None, "udp6": None}
    for a in where[3:].split():
        if a.startswith("[") and doors["udp6"] is None:
            doors["udp6"] = a
        elif not a.startswith("[") and doors["udp"] is None:
            doors["udp"] = a
    if doors["udp"] is None and doors["udp6"] is None:
        return None   # nothing usable: let the WebSocket road wait for its mirror (S N7)
    log.info("findd: %s… at %s (punch %s)", scrub(pub_b64[:12]), scrub(where[3:]), scrub(sent or "?"))
    return doors


async def relay(reader, writer):
    """One relay-port connection: a dialer opening a circuit, or a desktop attaching to one."""
    global circuits
    rip = ip_of(writer.get_extra_info("peername"))
    if not is_local(rip) and not relay_rate.allow(rate_key(rip)):
        writer.close()
        return
    try:
        line = await asyncio.wait_for(reader.readline(), timeout=10)
    except asyncio.TimeoutError:
        writer.close()
        return
    except (ValueError, ConnectionError):
        # readline() raises ValueError on limit overrun — a client sending 64 KiB with no
        # newline. Uncaught, the handler died with the writer still open and the socket lived
        # until the OS reaped it: an fd leak on demand. Close and move on.
        writer.close()
        return
    parts = line.decode(errors="replace").strip().split(" ")
    if len(line) > PREAMBLE_MAX or len(parts) not in (3, 4) or parts[0] != "RV1":
        writer.close()
        return

    if parts[1] == "punch" and len(parts) == 4:
        # The meeting itself: tell the desktop where to fire, hand the dialer the desktop's
        # QUIC door, close. Both bursts then fly at once and the dial crosses the crossing.
        # A few datagrams of introduction; not one byte of music.
        #
        # A COLD desktop (idle for economy, no UDP heartbeat) may be registered with a door
        # address its router has since forgotten. The punch order tells it to look in the
        # mirror again; we hold the dialer's answer up to PUNCH_WAIT_S for that fresh report
        # — the honest second a first connection after a quiet week costs.
        ws = desktops.get(canon(parts[2]))
        info = None
        # The punch target must be the DIALER'S OWN public IP — the address this very TCP
        # connection came from. Without this bind, anyone holding a desktop's public key
        # (every phone it ever paired, revoked ones included) could aim its 10-packet burst
        # at an arbitrary victim: an unauthenticated reflector, live even with RV_RELAY=off.
        # The port may differ (the UDP ear and this socket are different mappings); the IP
        # is what a reflector would have to forge, and cannot. A phone whose TCP and UDP
        # egress via different public IPs (rare) simply falls back to the relay.
        peer = writer.get_extra_info("peername")
        peer_ip = norm_ip(peer[0]) if peer is not None else None
        target_ip = _host_of(parts[3])
        # FAIL-CLOSED: fire ONLY when we can positively prove the target IP is the asker's own
        # (both parsed AND equal). Phrased as "refuse on any mismatch", a None on either side —
        # a peername the loop couldn't read, or a target _host_of() couldn't parse while the
        # desktop's SocketAddr::parse could — would slip through and aim the burst at parts[3].
        allowed = (peer_ip is not None and target_ip is not None and target_ip == peer_ip)
        refused = not allowed
        if refused:
            log.info("punch refused: target %s is not the asker %s", scrub(target_ip), scrub(peer_ip))
            ws = None
        # findd first: it knows the desktop's doors from its last authenticated heartbeat, and its punch
        # order reaches the desktop over UDP even when the WebSocket line below is dead. Fresh by
        # construction, so when it answers we do not wait for the WebSocket road's mirror (PUNCH_WAIT_S).
        fd = await findd_punch(parts[2], parts[3]) if allowed and 0 < len(parts[3]) < 64 else None
        if ws is not None and 0 < len(parts[3]) < 64:
            try:
                await ws.send(json.dumps({"t": "punch", "addr": parts[3]}))
                log.info("punch %s… toward %s", scrub(parts[2][:12]), scrub(parts[3]))
                info = quic.get(canon(parts[2]))
                if fd is None and (info is None or time.monotonic() - info.get("ts", 0) > FRESH_S):
                    ev = fresh.setdefault(canon(parts[2]), asyncio.Event())
                    ev.clear()
                    try:
                        await asyncio.wait_for(ev.wait(), PUNCH_WAIT_S)
                    except asyncio.TimeoutError:
                        pass
                    info = quic.get(canon(parts[2]))
            except websockets.ConnectionClosed:
                info = None
        if fd is not None:
            # findd's doors win (fresher); the WebSocket registry may still add the LAN list
            info = dict(info or {}, **{k: v for k, v in fd.items() if v})
        # Hand back the desktop's door of the SAME family the phone is punching: a v6 dial
        # (target_ip has colons) needs the v6 door, a v4 dial the v4 one. One door, in "udp",
        # so the phone reads it exactly as before — it never sees the other family's port.
        out = dict(info) if info is not None else {}
        out.pop("ts", None)            # bookkeeping, not wire
        # Same-NAT gate (as in query): the desktop's LAN addresses go back only to a phone that
        # shares its public IP. A remote phone can't reach 192.168.x.x anyway, so stripping loses
        # nothing and closes the same pubkey-holder LAN-topology leak the punch path also had.
        if not _same_nat(peer_ip, desktops.get(canon(parts[2]))):
            out.pop("lan", None)
        target_is_v6 = target_ip is not None and ":" in target_ip
        out["udp"] = (info.get("udp6") if target_is_v6 else info.get("udp")) if info else None
        out.pop("udp6", None)
        out["relay"] = RELAY_ON          # legacy bool (retired path); the new relay is `grant`
        out["grant"] = None              # null = no relay; a signed per-session ticket when it ships
        # A reason the phone turns into an honest sentence when no door opens: "split" — the
        # anti-reflector refused because the asker's TCP and UDP egress via different public
        # IPs; "nofamily" — the desktop DID report its doors and has none in the family the
        # phone punched (the opposite-single-stack case). The second needs `info` — an offline
        # or door-less desktop must NOT read as a family mismatch, or a user whose desktop is
        # simply off would be told their networks disagree. Absent when a door is handed back.
        if refused:
            out["reason"] = "split"
        elif info is not None and out["udp"] is None:
            out["reason"] = "nofamily"
        writer.write((json.dumps(out) + "\n").encode())
        try:
            await writer.drain()
        except ConnectionError:
            pass
        writer.close()
        return

    if len(parts) != 3:
        writer.close()
        return

    if parts[1] == "query":
        # "Where does this key live?" One JSON line of candidates, then goodbye. The phone
        # tries these DIRECTLY before asking anyone to relay a single media byte. The
        # "relay" flag is this server's POLICY, stated up front — a phone that will find
        # every door shut deserves the truth before it dials a wall.
        ws = desktops.get(canon(parts[2]))
        cands = candidates.get(canon(parts[2]), []) if ws is not None else []
        # A LAN address here is useful only to a phone on the desktop's own network. To anyone
        # else who names the pubkey — a revoked guest, an ex-housemate — it is internal-topology
        # disclosure (and a home-IP-over-time tracker). Hand LAN out ONLY to a same-NAT querier;
        # a stranger gets just the globally-routable door. Presence + public IP stay: they are
        # inherent to an introducer and load-bearing for pairing.
        peer = writer.get_extra_info("peername")
        peer_ip = norm_ip(peer[0]) if peer is not None else None
        cands = _lan_filtered(cands, peer_ip, ws)
        # `relay` is the LEGACY bool (the retired ticketless dial/attach; off in prod) — kept so
        # old phones read a value. The new relay path is NEVER signalled here: it lives in `grant`
        # (null today; a signed per-session ticket when the paid relay ships), which old phones
        # ignore. NO `doors` here on purpose: the plaintext query answer is not trusted to name
        # where the phone sends packets — the obs endpoint rides only the authenticated welcome.
        writer.write((json.dumps({"cands": cands, "relay": RELAY_ON,
                                  "grant": None}) + "\n").encode())
        try:
            await writer.drain()
        except ConnectionError:
            pass
        writer.close()
        return

    if parts[1] == "dial":
        if not RELAY_ON:
            log.info("dial refused: relay is off by policy")
            writer.close()         # introductions only; not one byte of music
            return
        ws = desktops.get(canon(parts[2]))
        # `circuits` counts only ATTACHED splices; a dial that never gets attached sits in
        # `pending` holding a socket for ATTACH_TIMEOUT. Bound the attached count, the parked
        # count, AND how many one source may hold at once — else a single IP loops dials,
        # exhausts fds and floods the desktop with `incoming` while `circuits` reads zero.
        if ws is None or circuits >= MAX_CIRCUITS or len(pending) >= MAX_CIRCUITS \
                or (not is_local(rip) and dials_per_ip.get(rate_key(rip), 0) >= MAX_DIALS_PER_IP):
            writer.close()         # not here — the phone falls back to telling its user
            return
        cid = secrets.token_urlsafe(9)
        pending[cid] = (reader, writer)
        dials_per_ip[rate_key(rip)] = dials_per_ip.get(rate_key(rip), 0) + 1
        try:
            try:
                await ws.send(json.dumps({"t": "incoming", "cid": cid}))
            except websockets.ConnectionClosed:
                del pending[cid]
                writer.close()
                return
            # The desktop has ATTACH_TIMEOUT to attach; its side completes the splice.
            await asyncio.sleep(ATTACH_TIMEOUT)
            if pending.pop(cid, None) is not None:
                writer.close()         # nobody came
        finally:
            left = dials_per_ip.get(rate_key(rip), 0) - 1
            if left > 0:
                dials_per_ip[rate_key(rip)] = left
            else:
                dials_per_ip.pop(rate_key(rip), None)
        return

    if parts[1] == "attach":
        if not RELAY_ON:
            writer.close()         # no circuit was parked; nothing to attach to
            return
        parked = pending.pop(parts[2], None)
        if parked is None:
            writer.close()         # too late, or a guess
            return
        d_reader, d_writer = parked
        circuits += 1
        log.info("circuit up (%d live)", circuits)
        try:
            await asyncio.gather(pipe(d_reader, writer), pipe(reader, d_writer))
        finally:
            circuits -= 1
            log.info("circuit down (%d live)", circuits)
        return

    writer.close()


class ObsEar(asyncio.DatagramProtocol):
    """The UDP ear: answers "what do I look like?" with the address the datagram came from.
    Two datagrams, no state, no verification — the answer is worthless to anyone but the
    asker, because a NAT mapping only admits packets back to the socket that asked."""

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        # A10 B6: the old ask exactly, or the ask with a nonce to echo: 16 lower-case hex digits, then zeros to 80 bytes,
        # so the answer (at most 74 bytes, an IPv6 address with its port and the nonce) is never larger than the ask.
        if data == b"ORPH1 obs?":
            echo = b""
        elif (len(data) == 80 and data.startswith(b"ORPH1 obs? ") and re.fullmatch(rb"[0-9a-f]{16}", data[11:27])
              and not data[27:].strip(b"\0")):
            echo = b" " + data[11:27]
        else:
            return
        ip = norm_ip(addr[0])
        # A rate-limited ear answers nobody, silently. The per-source bucket stops one asker
        # flooding; the global one bounds total reflection when the source is spoofed.
        # PER-SOURCE FIRST (measured 26/9 on a local copy): checked the other way round, every
        # packet of ONE flooding source spent a global token before its own bucket refused it —
        # 580k pkts/s from a single IP drained the shared bucket and honest desktops/phones got
        # no answer at all. Now a single source only ever spends its own 5/s of the global pool.
        if not is_local(ip) and (not obs_rate.allow(rate_key(ip)) or not obs_global.allow("*")):
            return
        host = f"[{ip}]" if ":" in ip else ip
        self.transport.sendto(f"ORPH1 obs={host}:{addr[1]}".encode() + echo, addr)


def _listen_sock(port, dgram=False):
    """A bound socket for `port`. When BIND is "::" this is a TRUE dual-stack socket
    (IPV6_V6ONLY=0), so ONE socket answers BOTH IPv6 and IPv4 (the latter as ::ffff:x).
    This is the whole point and it is NOT automatic: a plain bind to "::" inherits the box's
    net.ipv6.bindv6only, which on some hosts is 1 — then the socket is IPv6-ONLY and REFUSES
    every IPv4 client. Desktops register over IPv4, so that silently makes them unfindable.
    Forcing the option off is what makes "listen on both" real. RV_BIND=0.0.0.0 → plain IPv4."""
    v6 = (":" in BIND) or (BIND in ("", "::"))
    s = socket.socket(socket.AF_INET6 if v6 else socket.AF_INET,
                      socket.SOCK_DGRAM if dgram else socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if v6:
        try:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except OSError:
            pass
    s.bind((BIND, port))
    s.setblocking(False)
    return s


async def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")

    async def sweeper():
        # Idle rate-limit keys refill to full and are dropped, so the buckets track only
        # who is ACTIVE — the maps cannot grow without bound from a parade of one-shot IPs.
        while True:
            await asyncio.sleep(60)
            for rl in (conn_rate, reg_rate, relay_rate, obs_rate, obs_global):
                rl.sweep()
    asyncio.create_task(sweeper())

    async def v1_counter():
        # D6: how many distinct desktops still register the old way. The COUNT only — no key, no address.
        while True:
            await asyncio.sleep(V1_COUNT_S)
            v1_tick()
    asyncio.create_task(v1_counter())

    relay_srv = await asyncio.start_server(relay, sock=_listen_sock(RELAY_PORT))
    await asyncio.get_running_loop().create_datagram_endpoint(
        ObsEar, sock=_listen_sock(OBS_PORT, dgram=True))
    # Pings every FOUR MINUTES, not 25 s: they exist to keep each desktop's outbound TCP
    # alive through its NAT (conservative timeouts start around 5–10 min) and to notice a
    # silently dead peer. At 10k idle desktops the difference is ~250 GB/month of nothing.
    # max_size caps every control frame at 4 KiB: register (pub/sig) and the periodic udp updates
    # are tens of bytes, so the 1 MiB websockets default was a free json.loads/b64decode amplifier
    # for a registered peer. Well above any real message, well below anything worth parsing.
    ws_opts = dict(ping_interval=240, ping_timeout=60, max_size=4096)
    control_srvs = []
    if CONTROL_PUBLIC:
        control_srvs.append(await websockets.serve(control_public, sock=_listen_sock(CONTROL_PORT), **ws_opts))
    if CONTROL_SOCKET:
        # S1: the socket is the NEW door; its failure must never take the old ones (8750/8751/8752) down with it, or
        # one wrong path would crash-loop the whole meeting point. Said loudly, and the rest serves.
        # ANY exception: on 18/11 a keyword the installed websockets did not know raised TypeError, and a narrower
        # catch let it take the whole server down.
        try:
            control_srvs.append(await serve_control_socket(CONTROL_SOCKET, ws_opts))
        except (Exception, SystemExit) as ex:
            log.error("control socket %s NOT serving (%s: %s) — wss desktops cannot register; 8750/8751/8752 go on",
                      CONTROL_SOCKET, type(ex).__name__, scrub(str(ex)))
        if not PROXY_SECRETS:
            log.warning("control socket %s refuses EVERY connection: no RV_PROXY_SECRET of 32+ characters", CONTROL_SOCKET)
        if not SERVER_NAMES:
            log.warning("control socket %s accepts only v2, and RV_SERVER_NAMES is not set: every registration refused",
                        CONTROL_SOCKET)
    if SERVER_NAMES_BAD:
        log.warning("RV_SERVER_NAMES entries ignored (not canonical: lower-case A-label, no trailing dot): %s",
                    scrub(",".join(SERVER_NAMES_BAD)))
    log.info("bind %s · control :%d %s · socket %s · relay :%d (%s) · obs :%d/udp · v2 names %d · proxy secrets %d",
             BIND, CONTROL_PORT, "public" if CONTROL_PUBLIC else "CLOSED (RV_CONTROL_PUBLIC=off)",
             CONTROL_SOCKET or "(none)", RELAY_PORT, "on" if RELAY_ON else "OFF — introductions only", OBS_PORT,
             len(SERVER_NAMES), len(PROXY_SECRETS))
    async with relay_srv:
        await relay_srv.serve_forever()


def _capped_protocol() -> dict:
    """S5/R1: a ceiling on the socket listener's connections that are NOT YET REGISTERED, counted from the accept (before
    any header, so before the secret) until the registration succeeds or the line closes; a registered desktop gives its
    slot back, so the ceiling can never be filled by the homes it protects. Over the ceiling, and a handshake not done
    within SOCKET_OPEN_TIMEOUT: abort(), no closing handshake. On the websockets API this server runs (legacy, Ubuntu
    24.04's 10.x, which has no open_timeout) through its protocol class. On websockets 14+ there is no such hook here:
    no ceiling, only the library's own handshake timeout, and that is said once at start (R8)."""
    base = None
    try:
        from websockets.legacy.server import WebSocketServerProtocol as base   # noqa: N813
    except ImportError:
        pass
    if base is None or not getattr(websockets.unix_serve, "__module__", "").startswith("websockets.legacy"):
        log.warning("control socket: no connection ceiling on this websockets version (%s)",
                    getattr(websockets, "__version__", "?"))
        return {}

    class Capped(base):
        counted = False

        def release_slot(self):
            global _socket_open
            if self.counted:
                self.counted = False
                _socket_open -= 1

        def connection_made(self, transport):
            global _socket_open
            super().connection_made(transport)
            if _socket_open >= SOCKET_MAX_OPEN:
                _loud("control socket: too many unregistered connections open at once — refusing new ones")
                transport.abort()
                return
            _socket_open += 1
            self.counted = True

            def slow():   # still no finished handshake: a slow-loris, not nginx
                if getattr(getattr(self, "state", None), "name", "") == "CONNECTING":
                    _loud("control socket: a handshake took too long — dropped")
                    transport.abort()
            asyncio.get_running_loop().call_later(SOCKET_OPEN_TIMEOUT, slow)

        def connection_lost(self, exc):
            self.release_slot()
            super().connection_lost(exc)

    return {"create_protocol": Capped}


async def serve_control_socket(path, ws_opts):
    """The listener nginx proxies wss://<host>/rv to (D4). A stale socket from a killed run is removed first; anything
    else at that path is left alone and THIS listener does not start (main() says so loudly and serves the rest, S1).
    Born 0660: never wider, not even for an instant."""
    try:
        if stat.S_ISSOCK(os.lstat(path).st_mode):
            os.unlink(path)
        else:
            raise OSError(f"{path} exists and is not a socket: not touching it")
    except FileNotFoundError:
        pass
    old = os.umask(0o117)
    try:
        # close_timeout 2 s: the only graceful closes left here are the 1008/1011 the probe reads (third look, #2).
        srv = await websockets.unix_serve(control_proxied, path, **_capped_protocol(), **{**ws_opts, "close_timeout": 2})
    finally:
        os.umask(old)
    os.chmod(path, 0o660)
    return srv


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
