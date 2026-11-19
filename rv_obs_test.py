#!/usr/bin/env python3
# Test driver for Orpheic's own rendezvous; run it against your own instance.
"""A10 B6 (19/11/2026): the rendezvous's UDP ear, with no network. An old ask gets the old answer (old phones and
desktops), a new ask (80 bytes: the nonce, then zeros) gets its nonce echoed, and anything else gets nothing.

    python3 -I rv_obs_test.py [path/to/rendezvous.py]
"""
import importlib.util, os, sys

path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "rendezvous.py")
spec = importlib.util.spec_from_file_location("rendezvous_under_test", path)
rv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rv)

class Wire:
    def __init__(self): self.sent = []
    def sendto(self, data, addr): self.sent.append((data, addr))

fails = 0
def check(what, ok, saw=""):
    global fails
    fails += not ok
    print(("  ok: " if ok else "  FAILED: ") + what + (f"  [{saw}]" if saw else ""))

def ask(data, addr=("127.0.0.1", 40000)):
    ear, w = rv.ObsEar(), Wire()
    ear.connection_made(w)
    ear.datagram_received(data, addr)
    return [d for d, _ in w.sent]

nonce = b"0123456789abcdef"
def new_ask(n=nonce, pad=b"\0"):
    a = b"ORPH1 obs? " + n
    return a + pad * (80 - len(a))
check("an old ask gets the old answer", ask(b"ORPH1 obs?") == [b"ORPH1 obs=127.0.0.1:40000"], ask(b"ORPH1 obs?"))
check("a new ask gets the nonce echoed", ask(new_ask()) == [b"ORPH1 obs=127.0.0.1:40000 " + nonce], ask(new_ask()))
v6 = ask(new_ask(), ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 65535))
check("IPv6 (the longest address): in brackets, then the nonce, and never larger than the ask",
      v6 == [b"ORPH1 obs=[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535 " + nonce] and len(v6[0]) <= 80, f"{v6} {len(v6[0]) if v6 else 0}")
for bad in (new_ask(b"0123456789ABCDEF"), new_ask(b"0123456789abcdeg"), b"ORPH1 obs? " + nonce,
            new_ask()[:79], new_ask() + b"\0", new_ask(pad=b"x"), new_ask()[:79] + b"\x01",
            b"ORPH1 obs?\n", b"ORPH1 obs"):
    check(f"no answer to {bad[:30]!r}… ({len(bad)} bytes)", ask(bad) == [], ask(bad))
print("rv_obs_test: " + ("all ok" if not fails else f"{fails} FAILED"))
sys.exit(1 if fails else 0)
