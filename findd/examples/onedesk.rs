//! One test desktop for end-to-end checks of the rendezvous ↔ findd bridge (remote/tool/findd_e2e.py):
//!   onedesk <findd host:port> <server-pub-hex> <desktop-seed-hex>
//! Prints "pub <b64>", then "up <rowid>" once joined, then "punch <ip>:<port>" for every verified 0x18.
use findd::{addr::Addr, client::Desk, wire};
use std::net::{ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

fn hex32(s: &str) -> [u8; 32] { findd::crypto::hex32(s).expect("64 hex") }

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let srv = a[1].to_socket_addrs().unwrap().next().unwrap();
    let spub = hex32(&a[2]);
    let mut d = Desk::new_from_seed(&hex32(&a[3]), Addr::v4([0, 0, 0, 0], 0), 1 << 32);
    let b64 = { use std::fmt::Write; let t = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut o = String::new(); for c in d.pub_.chunks(3) { let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
            for i in 0..4 { if i <= c.len() { o.push(t[(n >> (18 - 6 * i) & 63) as usize] as char) } else { o.push('=') } } } let _ = write!(o, ""); o };
    println!("pub {b64}");
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
    let mut buf = [0u8; 256];
    s.send_to(&Desk::hello(), srv).unwrap();
    let (mut eph, mut xpub) = (None, [0u8; 32]);
    let mut last_punch = 0u64;
    let mut next = Instant::now() + Duration::from_secs(3600);
    loop {
        if Instant::now() >= next { let b = d.beat(true, None); s.send_to(&b, srv).unwrap(); next = Instant::now() + Duration::from_secs(5); }
        let Ok((n, _)) = s.recv_from(&mut buf) else { continue };
        let p = &buf[..n];
        match p[0] {
            wire::COOKIE => { let (hs, e, x) = d.hs(&p[1..17]); eph = Some(e); xpub = x; s.send_to(&hs, srv).unwrap(); }
            wire::HSOK => if let Some(e) = eph.take() {
                if d.accept_keys(p, e, xpub, &[spub]) {
                    println!("up {}", d.rowid);
                    next = Instant::now(); // first beat now (a test, not a router)
                }
            },
            wire::PUNCH => if let Some((c, ip, port)) = d.punch_ok(p, last_punch) {
                last_punch = c;
                println!("punch {}", std::net::SocketAddr::new(std::net::Ipv6Addr::from(ip).to_canonical(), port));
            },
            _ => {}
        }
        use std::io::Write; let _ = std::io::stdout().flush();
    }
}
