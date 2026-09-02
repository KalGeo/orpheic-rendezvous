# Orpheic Rendezvous

The introducer for [Orpheic Remote](https://orpheic.com) — it helps your phone and your
desktop **find** each other through the modern internet's walls, and carries nothing of yours.

Orpheic ships pointing at an official rendezvous, so it works out of the box. This is that
same server, so you can run **your own** and trust no one — not even us.

## What it does, and what it never does

- **Desktops dial OUT** to it (no port forwarding, ever) and register under their Ed25519
  identity, proving it by signing a challenge. The open socket doubles as a wake-up line.
- **A phone that wants its desktop** learns where it lives and connects **directly** — a
  UDP "address ear" lets both ends discover their public mapping and punch a hole through
  their NATs. What follows is peer-to-peer, end-to-end encrypted, pinned to the very key
  used at pairing.
- **A blind relay** is the fallback for the ~10–20% of networks where punching cannot work.
  It splices two sockets and copies bytes it **cannot read** — what flows is the Link's TLS,
  pinned end to end to the desktop's identity. (Turn it off entirely with `RV_RELAY=off`;
  then the server only ever introduces.)

What it can see is only metadata: which public keys are online, from which addresses, and
who talked to whom, when. That is unavoidable for any introducer — which is exactly why the
option to make it **yours** matters. It holds **no secrets, no keys, and no music**, ever,
and writes nothing to disk.

## Requirements

- A small server with a **public IP** (the cheapest VPS is plenty).
- **Python 3** with `websockets` and `pynacl` (both in a normal package manager —
  on Debian/Ubuntu: `sudo apt install python3-websockets python3-nacl`).
- **Three ports** reachable: `8750/tcp` (control), `8751/tcp` (relay, optional),
  `8752/udp` (the address ear — required for hole punching).

## Install

```sh
sudo mkdir -p /opt/orpheic-rendezvous
sudo cp rendezvous.py /opt/orpheic-rendezvous/
# a dedicated unprivileged user for the service (the unit runs as `orpheic-rv`)
sudo useradd --system --no-create-home --shell /usr/sbin/nologin orpheic-rv
sudo chown -R orpheic-rv:orpheic-rv /opt/orpheic-rendezvous
sudo cp orpheic-rendezvous.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now orpheic-rendezvous
sudo systemctl status orpheic-rendezvous     # → "control :8750 · relay :8751 (…) · obs :8752/udp"

# firewall (if you run ufw)
sudo ufw allow 8750:8751/tcp
sudo ufw allow 8752/udp
```

Then in Orpheic: **Settings → Advanced → Rendezvous server**, and enter the address. A plain
`IP:port` is perfectly fine — e.g. `203.0.113.10:8750`. If you'd rather, point a DNS name at
the server (e.g. `rendezvous.example.com:8750`) so its address can later change without
re-pointing a single device — nicer, but entirely optional. Your phone learns it the next
time you connect at home.

## Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `RV_CONTROL_PORT` | `8750` | control WebSocket (desktops register here) |
| `RV_RELAY_PORT` | `8751` | blind relay (fallback) |
| `RV_OBS_PORT` | `8752` | UDP address ear (for hole punching) |
| `RV_RELAY` | `on` | `off` makes this a pure introducer — it never carries a byte |

Every door is rate-limited per source IP with global ceilings and idle eviction, all tunable
via `RV_*` variables (see the top of `rendezvous.py`). The defaults are generous enough for a
whole home behind one address and tight enough to shrug off a flood.

## How it works on the wire

The whole protocol is documented in the header of [`rendezvous.py`](rendezvous.py): a signed
WebSocket registration, a line-preamble TCP relay (`RV1 dial|attach|query|punch`), and a
two-datagram UDP "what do I look like?" exchange. It is deliberately small — one file, one
event loop, no database.

## Security

Found a vulnerability? Please email **hello@orpheic.com** — see [SECURITY.md](SECURITY.md).
Don't open a public issue for a security problem. (The server holds no keys, no data, and no
media, and the end-to-end crypto doesn't trust it — so the concern here is availability, not
disclosure.)

## License

MIT — see [LICENSE](LICENSE). Run it, change it, redistribute it; it is yours.
