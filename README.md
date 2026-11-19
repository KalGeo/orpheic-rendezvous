# Orpheic Rendezvous

This is the meeting point used by [Orpheic](https://orpheic.com/), a free music player for the music files you own.

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
- **A name and a certificate.** Orpheic reaches its meeting point over an encrypted connection,
  at `wss://<your name>/rv` on port 443. So the server needs a DNS name, a TLS certificate for it
  (Let's Encrypt is free), and a web server in front that passes `/rv` on to the rendezvous:
  [`nginx-rendezvous.conf`](nginx-rendezvous.conf) is the nginx block we run. Without that, see
  [Without encryption](#without-encryption) below.
- **Ports** reachable: `443/tcp` (control, encrypted), `80/tcp` (only for the certificate),
  `8751/tcp` (relay, optional), `8752/udp` (the address ear — required for hole punching).
  `8750/tcp` only for Orpheic 0.9.9 and older, and for the unencrypted way.

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

## The encrypted door (wss on port 443)

In the examples your server's name is `rv.example.org`; use yours.

**1. The rendezvous's own settings.** `sudo systemctl edit orpheic-rendezvous`, and add:

```ini
[Service]
Environment=RV_SERVER_NAMES=rv.example.org
Environment=RV_CONTROL_SOCKET=/run/orpheic-rv/control.sock
EnvironmentFile=/etc/orpheic-rendezvous/proxy.env
ExecStartPre=+/usr/bin/install -d -m 2750 -o orpheic-rv -g www-data /run/orpheic-rv
ReadWritePaths=-/run/orpheic-rv
```

- `RV_SERVER_NAMES` is the name exactly as you will type it in Orpheic, in lower case. Orpheic
  signs in for one named server, so a sign-in meant for yours cannot be passed on to another one;
  without this line the rendezvous refuses every current Orpheic.
- `RV_CONTROL_SOCKET` is where nginx hands over `wss://rv.example.org/rv`. Its folder belongs to
  the service; the group is the one nginx's workers run as (the `user` line of your
  `nginx.conf`: `www-data` on Debian and Ubuntu), so that nginx, and only nginx, can connect.

**2. The shared secret.** nginx proves to the rendezvous that it is *your* nginx with a header
only the two of them know. Make it once, on the server, without ever printing it:

```sh
sudo sh -c '
umask 077
d=/etc/orpheic-rendezvous
install -d -m 0700 "$d"
k=$(openssl rand -hex 32)
printf "RV_PROXY_SECRET=%s\n" "$k" > "$d/proxy.env"
printf "proxy_set_header X-Orpheic-Proxy \"%s\";\n" "$k" > "$d/nginx-proxy-secret.conf"
'
```

Hex, because `$` means a variable to nginx. A value shorter than 32 characters counts as none,
and the socket then refuses everyone. Keep both files out of git and out of backups, and never
paste the output of `nginx -T`: it prints the secret. To change it: put the new value in
`RV_PROXY_SECRET_NEXT` and restart the rendezvous, switch nginx's file and reload nginx, then move
the new value to `RV_PROXY_SECRET`, remove `RV_PROXY_SECRET_NEXT`, and restart again.

**3. The certificate and nginx.** Copy [`nginx-rendezvous.conf`](nginx-rendezvous.conf) to
`/etc/nginx/sites-available/`, replace every `rv.example.org` in it with your name, and link it
from `sites-enabled`. Until the certificate exists, keep only its port-80 `server` block, then:

```sh
sudo install -d /var/www/letsencrypt
sudo nginx -t && sudo systemctl reload nginx
sudo certbot certonly --webroot -w /var/www/letsencrypt -d rv.example.org \
     --deploy-hook "systemctl reload nginx"
```

Then put the whole file in place, and:

```sh
sudo nginx -t && sudo systemctl reload nginx
sudo systemctl restart orpheic-rendezvous
sudo ufw allow 443/tcp && sudo ufw allow 80/tcp
```

**4. In Orpheic:** **Settings → Advanced → Rendezvous server**, and enter your `host:port` (for
example `rv.example.org:8750`). Leave **Control address** empty: Orpheic then uses
`wss://rv.example.org/rv`. Your phone learns it the next time you connect at home.

### Without encryption

On a server without a certificate, or for a test at home, leave `RV_CONTROL_SOCKET` and the
secret out, and type `ws://<your server>:8750` as the **Control address** in Orpheic. Your phone
can still find the computer from anywhere, but that line is not encrypted, and Orpheic says so in
Settings. `RV_SERVER_NAMES` is needed this way too; a plain IP is fine there
(`RV_SERVER_NAMES=203.0.113.10`).

### If you already run one

Orpheic versions after 0.9.9 open the encrypted line described above. A rendezvous that runs
without encryption stops being reachable from away after the update, until you put encryption in
front of it or type the `ws://` address. Older Orpheic versions keep working on port 8750 as
before.

## Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `RV_CONTROL_PORT` | `8750` | control WebSocket (desktops register here) |
| `RV_RELAY_PORT` | `8751` | blind relay (fallback) |
| `RV_OBS_PORT` | `8752` | UDP address ear (for hole punching) |
| `RV_RELAY` | `on` | `off` makes this a pure introducer — it never carries a byte |
| `RV_FINDD_CTL` | `/run/orpheic-findd/ctl.sock` | where to ask findd (see below); if nothing answers there, it carries on without it |
| `RV_SERVER_NAMES` | (none) | this server's own names, comma-separated, lower case, exactly as typed in Orpheic; without it the current sign-in is refused |
| `RV_CONTROL_SOCKET` | (none) | the Unix socket nginx passes `wss://<name>/rv` on to |
| `RV_PROXY_SECRET`, `RV_PROXY_SECRET_NEXT` | (none) | the header value nginx proves itself with (32 characters or more, from a root-only file) |
| `RV_CONTROL_PUBLIC` | `on` | `off` closes the old unencrypted control door, `8750/tcp` |

Every door is rate-limited per source IP with global ceilings and idle eviction, all tunable
via `RV_*` variables (see the top of `rendezvous.py`). The defaults are generous enough for a
whole home behind one address and tight enough to shrug off a flood.

## How it works on the wire

The whole protocol is documented in the header of [`rendezvous.py`](rendezvous.py): a signed
WebSocket registration, a line-preamble TCP relay (`RV1 dial|attach|query|punch`), and a
two-datagram UDP "what do I look like?" exchange. It is deliberately small — one file, one
event loop, no database.

About the code: the comments in both programs refer to sections of our design notes (for
example `LEVEL-B-PLAN.md D4`, or §12 and §13), which are not published. A few comments and log
lines are in Greek.

`python3 -I rv_obs_test.py` checks the UDP ear without a network: the old question gets the old
answer, the new one (with a random number to echo) gets its number back, anything else gets
nothing.

## findd: where each desktop is, right now

The [`findd/`](findd/) folder is the second program on our server, written in Rust, on UDP port `8753`.
Desktops send it a short authenticated heartbeat from the same port a phone will use, so it always knows
each desktop's current public address. When a phone asks for its desktop, the meeting point asks
findd over a local socket (`RV_FINDD_CTL`), and findd tells the desktop that a phone is coming.

findd keeps everything in memory: a restart forgets every desktop, and each one joins again on its
own. It holds one secret, its signing key in `/etc/orpheic-findd/`, which proves to Orpheic that it
is our findd. The meeting point's unit is not allowed to read that folder.

**You don't need findd to run your own meeting point.** A released Orpheic only trusts the key of
our findd, so a findd you run yourself would not be used, and your own meeting point works without
one. It is here so you can read exactly what runs on our server.

- `findd/release.sh` is how we build it: the committed lockfile, the pinned Rust version, a refusal
  of the load-test build, and the sha256 of the result.
- [`orpheic-findd.service`](orpheic-findd.service) is the unit we run. It reads `FINDD_PUBLIC`, the
  server's own public addresses, from `/etc/orpheic-findd/env`: a desktop's handshake signed for any other
  address is refused.

## Security

Found a vulnerability? Please email **hello@orpheic.com** — see [SECURITY.md](SECURITY.md).
Don't open a public issue for a security problem. (The server holds no keys, no data, and no
media, and the end-to-end crypto doesn't trust it — so the concern here is availability, not
disclosure.)

## License

MIT — see [LICENSE](LICENSE). Run it, change it, redistribute it; it is yours.
