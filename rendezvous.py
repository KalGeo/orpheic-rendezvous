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
    S→C  {"t":"registered"}
    S→C  {"t":"incoming","cid":"<opaque>"}          ← someone dialed this key; attach now
    C→S  {"t":"udp","addr":"<observed ip:port>","lan":["<ip:port>",…]}   ← QUIC door update
    S→C  {"t":"punch","addr":"<ip:port>"}           ← fire your burst at this address, now
  relay    (plain TCP, port 8751), one preamble line then raw bytes both ways:
    dialer:   RV1 dial <desktopPubB64>\n
    desktop:  RV1 attach <cid>\n
    query:    RV1 query <desktopPubB64>\n           → one JSON line {"cands":[…],"relay":bool}
    punch:    RV1 punch <desktopPubB64> <ip:port>\n → one JSON line {"udp":…,"lan":[…],"relay":bool}
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
import json
import logging
import os
import secrets
import sys
import time

import websockets
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

CONTROL_PORT = int(os.environ.get("RV_CONTROL_PORT", "8750"))
RELAY_PORT = int(os.environ.get("RV_RELAY_PORT", "8751"))
OBS_PORT = int(os.environ.get("RV_OBS_PORT", "8752"))
SIGN_PREFIX = b"orpheic-rv-v1-register"

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


def ip_of(addr) -> str:
    return addr[0] if addr else ""


# Set RV_LIMIT_LOCAL=1 to make loopback NON-exempt — the only way to exercise the caps from
# a test on one machine (real abuse comes from real remote IPs). Off in production.
_LIMIT_LOCAL = os.environ.get("RV_LIMIT_LOCAL", "").strip() in ("1", "true", "yes")


def is_local(ip: str) -> bool:
    if _LIMIT_LOCAL:
        return False
    return ip.startswith("127.") or ip in ("::1", "::ffff:127.0.0.1")


def _host_of(hostport: str):
    """The IP out of "ip:port" or "[v6]:port" — for binding a punch target to its asker.
    None when it does not parse, which the caller treats as "cannot verify → refuse"."""
    hostport = hostport.strip()
    if hostport.startswith("["):
        end = hostport.rfind("]")
        return hostport[1:end] if end > 0 else None
    colon = hostport.rfind(":")
    return hostport[:colon] if colon > 0 else None

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
        pub_b64 = m.get("pub", "")
        pub = base64.b64decode(pub_b64)
        sig = base64.b64decode(m.get("sig", ""))
        if m.get("t") != "register" or len(pub) != 32:
            await ws.close()
            return
        VerifyKey(pub).verify(SIGN_PREFIX + nonce, sig)   # raises when it does not hold
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
    if old is not None and old is not ws:
        await old.close()          # the newest registration IS this desktop now

    # Candidates, public first: the address this registration ARRIVED from plus the router
    # port the desktop mapped (if any), then its LAN addresses for a phone that is actually
    # at home. Handing them out is safe by construction — the dialer's TLS pin means a wrong
    # or hostile address simply fails a signature.
    # A `lan` that is not a list (an int, a dict, a bare string) would raise HERE — after
    # `desktops[pub_b64] = ws` landed but OUTSIDE the try/finally that cleans it up — leaking
    # the registry entry forever and reporting a phantom desktop as online. Anyone can sign a
    # challenge, so it must not be crashable. Validate the shape before iterating.
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
        for port in ports:
            if not (isinstance(port, int) and 0 < port < 65536):
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
            ws.remote_address[0],
            [m.get("mapped", 0), m.get("port", 0)],
            pub_b64))
    await ws.send(json.dumps({"t": "registered"}))
    try:
        async for raw in ws:
            # The one thing a registered desktop has to say: where its QUIC door lives now.
            try:
                upd = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if upd.get("t") != "udp":
                continue
            addr = upd.get("addr", "")
            lans = [l for l in upd.get("lan", [])[:8]
                    if isinstance(l, str) and 0 < len(l) < 64]
            if isinstance(addr, str) and len(addr) < 64:
                quic[pub_b64] = {"udp": addr or None, "lan": lans, "ts": time.monotonic()}
                if pub_b64 in fresh:
                    fresh[pub_b64].set()   # a punch is waiting on exactly this
                log.info("quic door %s for %s…", addr or "(none)", pub_b64[:12])
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
        ws = desktops.get(parts[2])
        info = None
        # The punch target must be the DIALER'S OWN public IP — the address this very TCP
        # connection came from. Without this bind, anyone holding a desktop's public key
        # (every phone it ever paired, revoked ones included) could aim its 10-packet burst
        # at an arbitrary victim: an unauthenticated reflector, live even with RV_RELAY=off.
        # The port may differ (the UDP ear and this socket are different mappings); the IP
        # is what a reflector would have to forge, and cannot. A phone whose TCP and UDP
        # egress via different public IPs (rare) simply falls back to the relay.
        peer = writer.get_extra_info("peername")
        target_ip = _host_of(parts[3])
        if peer is not None and target_ip is not None and target_ip != peer[0]:
            log.info("punch refused: target %s is not the asker %s", target_ip, peer[0])
            ws = None
        if ws is not None and 0 < len(parts[3]) < 64:
            try:
                await ws.send(json.dumps({"t": "punch", "addr": parts[3]}))
                log.info("punch %s… toward %s", parts[2][:12], parts[3])
                info = quic.get(parts[2])
                if info is None or time.monotonic() - info.get("ts", 0) > FRESH_S:
                    ev = fresh.setdefault(parts[2], asyncio.Event())
                    ev.clear()
                    try:
                        await asyncio.wait_for(ev.wait(), PUNCH_WAIT_S)
                    except asyncio.TimeoutError:
                        pass
                    info = quic.get(parts[2])
            except websockets.ConnectionClosed:
                info = None
        out = dict(info) if info is not None else {"udp": None}
        out.pop("ts", None)            # bookkeeping, not wire
        out["relay"] = RELAY_ON
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
        ws = desktops.get(parts[2])
        cands = candidates.get(parts[2], []) if ws is not None else []
        writer.write((json.dumps({"cands": cands, "relay": RELAY_ON}) + "\n").encode())
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
        ws = desktops.get(parts[2])
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
        ip = addr[0]
        # A rate-limited ear answers nobody, silently. The per-source bucket stops one asker
        # flooding; the global one bounds total reflection when the source is spoofed.
        if not is_local(ip) and (not obs_global.allow("*") or not obs_rate.allow(ip)):
            return
        host = f"[{ip}]" if ":" in ip else ip
        self.transport.sendto(f"ORPH1 obs={host}:{addr[1]}".encode(), addr)


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

    relay_srv = await asyncio.start_server(relay, "0.0.0.0", RELAY_PORT)
    await asyncio.get_running_loop().create_datagram_endpoint(
        ObsEar, local_addr=("0.0.0.0", OBS_PORT))
    # Pings every FOUR MINUTES, not 25 s: they exist to keep each desktop's outbound TCP
    # alive through its NAT (conservative timeouts start around 5–10 min) and to notice a
    # silently dead peer. At 10k idle desktops the difference is ~250 GB/month of nothing.
    async with websockets.serve(control, "0.0.0.0", CONTROL_PORT, ping_interval=240,
                                ping_timeout=60):
        log.info("control :%d · relay :%d (%s) · obs :%d/udp", CONTROL_PORT, RELAY_PORT,
                 "on" if RELAY_ON else "OFF — introductions only", OBS_PORT)
        async with relay_srv:
            await relay_srv.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
