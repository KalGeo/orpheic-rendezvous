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
  control  (WebSocket, port 8750):
    S→C  {"t":"challenge","nonce":"<b64 16B>"}
    C→S  {"t":"register","pub":"<b64 32B>","sig":"<b64 sign('orpheic-rv-v1-register'+nonce)>"}
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
    C→S  "ORPH1 obs?"            S→C  "ORPH1 obs=<ip:port as this server saw it>"

Every door is rate-limited per source IP (loopback exempt), with global ceilings and idle
eviction, so a flood exhausts nobody — see the "Abuse defence" block. The server holds no
secrets and carries no music, so availability is the only thing there is to protect.

Runs on: python3 + python3-websockets + python3-nacl (all in Ubuntu 24.04's apt).
Deploy: /opt/orpheic-rendezvous/ + the systemd unit (server/DEPLOY.md).
"""

import asyncio
import base64
import ipaddress
import json
import logging
import os
import secrets
import socket
import sys
import time

import websockets
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

CONTROL_PORT = int(os.environ.get("RV_CONTROL_PORT", "8750"))
RELAY_PORT = int(os.environ.get("RV_RELAY_PORT", "8751"))
OBS_PORT = int(os.environ.get("RV_OBS_PORT", "8752"))
SIGN_PREFIX = b"orpheic-rv-v1-register"

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
# (the control WS is direct, not yet behind nginx; when it moves to wss://…/rv per §5.7 it
# keys off CF-Connecting-IP instead, and obs/relay stay socket-peer, always direct).
# LOOPBACK is exempt: the operator's own testing, and later the trusted local proxy.
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
conns_per_ip: dict = {}   # ip -> live control WS count
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
    if peer_ip is None or desk_ws is None or not desk_ws.remote_address:
        return False
    return peer_ip == ip_of(desk_ws.remote_address)


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


async def control(ws):
    """Guard the connection with the per-IP caps, then serve it."""
    ip = ip_of(ws.remote_address)
    if not is_local(ip) and (not conn_rate.allow(ip)
                             or conns_per_ip.get(ip, 0) >= MAX_CONN_PER_IP):
        await ws.close()
        return
    conns_per_ip[ip] = conns_per_ip.get(ip, 0) + 1
    try:
        await _control(ws, ip)
    finally:
        left = conns_per_ip.get(ip, 0) - 1
        if left > 0:
            conns_per_ip[ip] = left
        else:
            conns_per_ip.pop(ip, None)


async def _control(ws, ip):
    """One desktop's control connection: challenge, verify, then hold the line."""
    nonce = secrets.token_bytes(16)
    await ws.send(json.dumps({"t": "challenge", "nonce": base64.b64encode(nonce).decode()}))
    try:
        raw = await asyncio.wait_for(ws.recv(), timeout=CHALLENGE_S)
        m = json.loads(raw)
        if not isinstance(m, dict):        # [] / 7 / "x": m.get θα έριχνε AttributeError, όχι στο except (Fable)
            await ws.close()
            return
        pub = base64.b64decode(m.get("pub", ""))
        sig = base64.b64decode(m.get("sig", ""))
        if m.get("t") != "register" or len(pub) != 32:
            await ws.close()
            return
        VerifyKey(pub).verify(SIGN_PREFIX + nonce, sig)   # raises when it does not hold
        # ΚΑΝΟΝΙΚΟ κλειδί: το raw base64 του πελάτη είναι εύπλαστο (padding/τελευταία bytes) — ένα
        # ζεύγος κλειδιών θα έπιανε πολλές θέσεις στο μητρώο. Κλειδί = re-encode των 32 bytes (Fable).
        pub_b64 = base64.b64encode(pub).decode()
    except (asyncio.TimeoutError, BadSignatureError, ValueError, KeyError,
            json.JSONDecodeError, websockets.ConnectionClosed):
        await ws.close()
        return

    # Past the signature — a genuine registration attempt. Bound how fast one source may make
    # them, and cap the registry globally, so no flood of free keys can exhaust memory.
    if not is_local(ip) and not reg_rate.allow(ip):
        await ws.close()
        return
    if pub_b64 not in desktops and len(desktops) >= MAX_DESKTOPS:
        log.info("registry full (%d) — refusing a new key", len(desktops))
        await ws.close()
        return

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
        log.info("registered %s… from %s cands=%d", pub_b64[:12], ws.remote_address, len(cands))

        # The PUBLIC door, verified rather than believed: whether it was UPnP-mapped or the user
        # forwarded a port by hand, the only address worth handing out is one THIS server just
        # knocked on and found open. A mapping a router accepted and then drops would otherwise
        # cost every phone a timeout.
        async def confirm_public(ip, ports, key):
            if is_local(ip):        # μη «χτυπάς» localhost υπηρεσίες του ίδιου του server (Fable)
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
        if ws.remote_address:
            asyncio.create_task(confirm_public(
                norm_ip(ws.remote_address[0]),
                [m.get("mapped", 0), m.get("port", 0)],
                pub_b64))
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
            if upd.get("t") != "udp":
                continue
            addr = upd.get("addr", "")
            # The desktop's SECOND door: its IPv6 QUIC port, when it has an IPv6 leg. A v6 dial
            # is handed this one; a v4 dial the v4 "addr". Both belong to the same desktop, each
            # its own family's mapping/pinhole — see the punch answer below.
            addr6 = upd.get("addr6", "")
            addr6 = addr6 if isinstance(addr6, str) and 0 < len(addr6) < 64 else None
            lans = [l for l in upd.get("lan", [])[:8]
                    if isinstance(l, str) and 0 < len(l) < 64]
            if isinstance(addr, str) and len(addr) < 64:
                quic[pub_b64] = {"udp": addr or None, "udp6": addr6,
                                 "lan": lans, "ts": time.monotonic()}
                if pub_b64 in fresh:
                    fresh[pub_b64].set()   # a punch is waiting on exactly this
                log.info("quic door v4=%s v6=%s for %s…",
                         addr or "(none)", addr6 or "(none)", pub_b64[:12])
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


async def relay(reader, writer):
    """One relay-port connection: a dialer opening a circuit, or a desktop attaching to one."""
    global circuits
    rip = ip_of(writer.get_extra_info("peername"))
    if not is_local(rip) and not relay_rate.allow(rip):
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
            log.info("punch refused: target %s is not the asker %s", target_ip, peer_ip)
            ws = None
        if ws is not None and 0 < len(parts[3]) < 64:
            try:
                await ws.send(json.dumps({"t": "punch", "addr": parts[3]}))
                log.info("punch %s… toward %s", parts[2][:12], parts[3])
                info = quic.get(canon(parts[2]))
                if info is None or time.monotonic() - info.get("ts", 0) > FRESH_S:
                    ev = fresh.setdefault(canon(parts[2]), asyncio.Event())
                    ev.clear()
                    try:
                        await asyncio.wait_for(ev.wait(), PUNCH_WAIT_S)
                    except asyncio.TimeoutError:
                        pass
                    info = quic.get(canon(parts[2]))
            except websockets.ConnectionClosed:
                info = None
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
                or (not is_local(rip) and dials_per_ip.get(rip, 0) >= MAX_DIALS_PER_IP):
            writer.close()         # not here — the phone falls back to telling its user
            return
        cid = secrets.token_urlsafe(9)
        pending[cid] = (reader, writer)
        dials_per_ip[rip] = dials_per_ip.get(rip, 0) + 1
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
            left = dials_per_ip.get(rip, 0) - 1
            if left > 0:
                dials_per_ip[rip] = left
            else:
                dials_per_ip.pop(rip, None)
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
        if data != b"ORPH1 obs?":
            return
        ip = norm_ip(addr[0])
        # A rate-limited ear answers nobody, silently. The per-source bucket stops one asker
        # flooding; the global one bounds total reflection when the source is spoofed.
        if not is_local(ip) and (not obs_global.allow("*") or not obs_rate.allow(ip)):
            return
        host = f"[{ip}]" if ":" in ip else ip
        self.transport.sendto(f"ORPH1 obs={host}:{addr[1]}".encode(), addr)


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

    relay_srv = await asyncio.start_server(relay, sock=_listen_sock(RELAY_PORT))
    await asyncio.get_running_loop().create_datagram_endpoint(
        ObsEar, sock=_listen_sock(OBS_PORT, dgram=True))
    # Pings every FOUR MINUTES, not 25 s: they exist to keep each desktop's outbound TCP
    # alive through its NAT (conservative timeouts start around 5–10 min) and to notice a
    # silently dead peer. At 10k idle desktops the difference is ~250 GB/month of nothing.
    # max_size caps every control frame at 4 KiB: register (pub/sig) and the periodic udp updates
    # are tens of bytes, so the 1 MiB websockets default was a free json.loads/b64decode amplifier
    # for a registered peer. Well above any real message, well below anything worth parsing.
    async with websockets.serve(control, sock=_listen_sock(CONTROL_PORT), ping_interval=240,
                                ping_timeout=60, max_size=4096):
        log.info("bind %s · control :%d · relay :%d (%s) · obs :%d/udp", BIND, CONTROL_PORT,
                 RELAY_PORT, "on" if RELAY_ON else "OFF — introductions only", OBS_PORT)
        async with relay_srv:
            await relay_srv.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
