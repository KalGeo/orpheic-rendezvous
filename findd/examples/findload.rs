//! Load + scenario tool for findd (findability.md §13 Π10). Not part of the server.
//!   findload <server> <port> <server-pub-hex> <desktops> <sockets> <packets/s> <seconds> [mode]
//! mode: normal (default) · junk (random rowids with bit0, bad MACs, garbage) · move (every desktop
//! changes its source port once, half-way).
//! sockets: use as many as desktops — the server allows ≤ 2 rows per ip:port (§13 Π1).
//! Each desktop: hello → cookie → ONE pending handshake (re-made with ctr+1 at +2″, +5″ — B3) → beats;
//! bit0 on the first beat after the handshake and on 1 in 8 after that (random phase).
use findd::{addr::Addr, client::Desk, wire};
use ring::agreement::EphemeralPrivateKey;
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

enum St { New, Cookie, Hs { cookie: [u8; 16], eph: Option<EphemeralPrivateKey>, xpub: [u8; 32], at: Instant, tries: u8 }, Up { first: bool, suspect: bool } }

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let srv: SocketAddr = (a[1].as_str(), a[2].parse::<u16>().unwrap()).to_socket_addrs().unwrap().next().unwrap();
    let spub: Vec<u8> = (0..32).map(|i| u8::from_str_radix(&a[3][2 * i..2 * i + 2], 16).unwrap()).collect();
    let (nd, ns, rate, secs): (usize, usize, f64, f64) = (a[4].parse().unwrap(), a[5].parse().unwrap(), a[6].parse().unwrap(), a[7].parse().unwrap());
    let mode = a.get(8).map(|s| s.as_str()).unwrap_or("normal");
    let bind = if srv.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let mut socks: Vec<UdpSocket> = (0..ns).map(|_| { let s = UdpSocket::bind(bind).unwrap(); s.set_nonblocking(true).unwrap(); s }).collect();
    let dummy = Addr::v4([0, 0, 0, 0], 0);
    let mut ds: Vec<(Desk, St, usize, u64)> = (0..nd).map(|k| {
        let mut d = Desk::new(dummy, (1u64 << 32) | k as u64); d.ctr = (k as u64) << 24;
        (d, St::New, k % ns, (k as u64 * 2654435761) % 8)
    }).collect();
    let mut by_ctr: HashMap<(usize, u64), usize> = HashMap::new();
    let (mut sent, mut got, mut ups, mut moved) = (0u64, 0u64, 0usize, false);
    let mut kinds = [0u64; 256];
    let mut rb = [0u8; 512];
    let t0 = Instant::now(); let mut tick = Instant::now(); let mut i = 0usize;
    let gap = Duration::from_secs_f64(1.0 / rate); let mut next = Instant::now();
    let mut junk = 0u64; let mut j = 0usize;
    while t0.elapsed().as_secs_f64() < secs {
        if mode == "move" && !moved && t0.elapsed().as_secs_f64() > secs / 2.0 {
            socks = (0..ns).map(|_| { let s = UdpSocket::bind(bind).unwrap(); s.set_nonblocking(true).unwrap(); s }).collect();
            moved = true; println!("— όλοι οι υπολογιστές άλλαξαν θύρα —");
        }
        if i % 128 == 0 {
            for (si, s) in socks.iter().enumerate() {
                while let Ok((n, _)) = s.recv_from(&mut rb) {
                    got += 1; kinds[rb[0] as usize] += 1;
                    match (rb[0], n) {
                        (wire::COOKIE, wire::COOKIE_LEN) => {
                            for k in (si..nd).step_by(ns) {
                                if let St::Cookie = ds[k].1 {
                                    let (pkt, eph, xpub) = ds[k].0.hs(&rb[1..17]);
                                    by_ctr.insert((si, ds[k].0.ctr), k);
                                    let _ = s.send_to(&pkt, srv); sent += 1;
                                    let mut cookie = [0u8; 16]; cookie.copy_from_slice(&rb[1..17]);
                                    ds[k].1 = St::Hs { cookie, eph: Some(eph), xpub, at: Instant::now(), tries: 0 };
                                }
                            }
                        }
                        (wire::HSOK, wire::HSOK_LEN) => {
                            let c = u64::from_be_bytes(rb[41..49].try_into().unwrap());
                            if let Some(&k) = by_ctr.get(&(si, c)) {
                                let d = &mut ds[k];
                                if let St::Hs { eph, xpub, .. } = &mut d.1 {
                                    if d.0.ctr == c { // only the PENDING handshake's answer (§13 Π3)
                                        let (e, x) = (eph.take().unwrap(), *xpub);
                                        if d.0.accept(&rb[..n], e, x, &spub) { d.1 = St::Up { first: true, suspect: false }; ups += 1; } else { d.1 = St::New; }
                                    }
                                }
                            }
                        }
                        (wire::MOVE, wire::MOVE_LEN) => {
                            let rid = u64::from_be_bytes(rb[1..9].try_into().unwrap());
                            if let Some(k) = (si..nd).step_by(ns).find(|&k| ds[k].0.rowid == rid) {
                                if let Some(nonce) = ds[k].0.move_nonce(&rb[..n]) { // verified, never blind (F MED-5)
                                    let p = ds[k].0.beat(true, Some(nonce)); let _ = s.send_to(&p, srv); sent += 1;
                                }
                            }
                        }
                        (wire::ACK, wire::ACK_LEN) => {
                            let rid = u64::from_be_bytes(rb[1..9].try_into().unwrap());
                            if let Some(k) = (si..nd).step_by(ns).find(|&k| ds[k].0.rowid == rid) {
                                let c = ds[k].0.ctr; let recent: Vec<u64> = (c.saturating_sub(16)..=c).collect();
                                if ds[k].0.ack_ok(&rb[..n], &recent) { if let St::Up { suspect, .. } = &mut ds[k].1 { *suspect = false; } }
                            }
                        }
                        (wire::UNKNOWN, wire::UNKNOWN_LEN) => {
                            let rid = u64::from_be_bytes(rb[1..9].try_into().unwrap());
                            // §13 Π5: a 0x17 is only a hint — first one → the next beat asks; a second in a row → new handshake
                            if let Some(k) = (si..nd).step_by(ns).find(|&k| ds[k].0.rowid == rid && matches!(ds[k].1, St::Up { .. })) {
                                if let St::Up { suspect, .. } = &mut ds[k].1 { if *suspect { ds[k].1 = St::New; ups -= 1; } else { *suspect = true; } }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        let now = Instant::now();
        if now < next { if next - now > Duration::from_micros(200) { std::thread::sleep(Duration::from_micros(100)); } continue; }
        next += gap; if now > next + Duration::from_millis(50) { next = now; }
        if mode == "junk" && (i + j) % 2 == 1 {
            // garbage of every kind, from the same sockets: random rowid with bit0, bad MAC on a live rowid, wrong lengths
            let mut p = vec![0u8; wire::BEAT_LEN]; p[0] = wire::BEAT; p[17] = 1;
            let r = (j as u64 + 1).wrapping_mul(0x9E3779B97F4A7C15);
            match j % 3 { 0 => p[1..9].copy_from_slice(&r.to_be_bytes()),
                          1 => { let k = (0..nd).map(|x| (x + r as usize) % nd).find(|&x| matches!(ds[x].1, St::Up { .. })).unwrap_or(0); p[1..9].copy_from_slice(&ds[k].0.rowid.to_be_bytes()); p[9..17].copy_from_slice(&u64::MAX.to_be_bytes()); }
                          _ => { p.truncate(7); } }
            let _ = socks[j % ns].send_to(&p, srv); junk += 1; j += 1; continue;
        }
        let k = i % nd; i += 1;
        let si = ds[k].2;
        match &mut ds[k].1 {
            St::New => { let _ = socks[si].send_to(&Desk::hello(), srv); ds[k].1 = St::Cookie; sent += 1; }
            St::Cookie => { let _ = socks[si].send_to(&Desk::hello(), srv); sent += 1; }
            St::Hs { cookie, at, tries, .. } => {
                if at.elapsed() > Duration::from_secs(if *tries == 0 { 2 } else { 5 }) {
                    if *tries >= 2 { ds[k].1 = St::New; } else {
                        let (c, t) = (*cookie, *tries + 1);
                        let (pkt, eph, xpub) = ds[k].0.hs(&c); // B3: a NEW handshake, not the same bytes
                        by_ctr.insert((si, ds[k].0.ctr), k);
                        let _ = socks[si].send_to(&pkt, srv); sent += 1;
                        ds[k].1 = St::Hs { cookie: c, eph: Some(eph), xpub, at: Instant::now(), tries: t };
                    }
                }
            }
            St::Up { first, suspect } => {
                let f = *first || *suspect; *first = false;
                let want = f || (ds[k].0.ctr + ds[k].3) % 8 == 0;
                let p = ds[k].0.beat(want, None); let _ = socks[si].send_to(&p, srv); sent += 1;
            }
        }
        if tick.elapsed().as_secs() >= 5 {
            println!("στάλθηκαν {sent} · απαντήσεις {got} (cookie {} hsok {} ack {} move {} 0x17 {}) · σε λειτουργία {ups}/{nd} · σκουπίδια {junk}",
                kinds[0x12], kinds[0x14], kinds[0x13], kinds[0x16], kinds[0x17]);
            tick = Instant::now();
        }
    }
}
