//! findd — the heartbeat catalog of findability.md §12 + §13 on one UDP port (dual stack).
//!
//!   findd <udp-port> <server-key-file (32-byte Ed25519 seed)> [control-socket-path]
//!
//! One thread owns the catalog (§11.3). recvmmsg/sendmmsg in batches of 64 with an adaptive
//! sleep when a batch comes back short (§11.16, §13 Π9). Counters every minute on stdout
//! (→ journal). The control socket (Unix datagram, local only) lets the existing rendezvous ask
//!   "where <pub-hex>"                → "at <ip>:<port> …" | "none"
//!   "punch <pub-hex> <ip> <port>"    → "sent <n>"
use findd::addr::Addr;
use findd::crypto::hex32;
use findd::engine::{Config, Engine};
use std::io::Write;
use std::os::unix::net::UnixDatagram;
use std::time::{Duration, Instant};

const B: usize = 64;

fn control(e: &mut Engine, ctl: &UnixDatagram, fd: i32, now: u64) {
    let mut buf = [0u8; 512];
    for _ in 0..16 { // capped: the control socket can never starve the UDP loop (F MED-3)
        let Ok((n, from)) = ctl.recv_from(&mut buf) else { break };
        let line = String::from_utf8_lossy(&buf[..n]).to_string();
        let f: Vec<&str> = line.split_whitespace().collect();
        let reply = match f.as_slice() {
            ["where", p] => match hex32(p) {
                Some(k) => { let v = e.where_is(&k, now); if v.is_empty() { "none".into() } else {
                    format!("at {}", v.iter().map(|a| a.to_sockaddr().to_string()).collect::<Vec<_>>().join(" ")) } }
                None => "error pub".into(),
            },
            ["punch", p, ip, port] => match (hex32(p), ip.parse::<std::net::IpAddr>(), port.parse::<u16>()) {
                (Some(k), Ok(ip), Ok(port)) => {
                    let ip16 = match ip { std::net::IpAddr::V4(v) => v.to_ipv6_mapped().octets(), std::net::IpAddr::V6(v) => v.octets() };
                    let pk = e.punch(&k, Addr { ip: ip16, port }, now);
                    for (to, p) in &pk { send_one(fd, to, p); }
                    format!("sent {}", pk.len())
                }
                _ => "error args".into(),
            },
            _ => "error command".into(),
        };
        if let Some(path) = from.as_pathname() { let _ = ctl.send_to(reply.as_bytes(), path); }
    }
}

fn sockaddr(a: &Addr) -> libc::sockaddr_in6 {
    let mut s: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    s.sin6_family = libc::AF_INET6 as _; s.sin6_port = a.port.to_be(); s.sin6_addr.s6_addr = a.ip; s
}
fn send_one(fd: i32, to: &Addr, p: &[u8]) {
    let sa = sockaddr(to);
    unsafe { libc::sendto(fd, p.as_ptr() as _, p.len(), libc::MSG_DONTWAIT, &sa as *const _ as _, std::mem::size_of::<libc::sockaddr_in6>() as _); }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 { eprintln!("usage: findd <udp-port> <server-key-file> [control-socket]"); std::process::exit(2); }
    let port: u16 = args[1].parse().expect("port");
    let seed: [u8; 32] = std::fs::read(&args[2]).ok().and_then(|v| v.try_into().ok()).expect("server key file: exactly 32 bytes");
    let mut cfg = Config::default();
    // `--features bench` + FINDD_BENCH=1: a load test from ONE machine — every desktop shares one host,
    // so the per-host and per-net limits would (correctly) stop it. Absent from the production build.
    #[cfg(feature = "bench")]
    if std::env::var("FINDD_BENCH").as_deref() == Ok("1") {
        eprintln!("findd: FINDD_BENCH=1 — per-host/per-net limits OFF (load test only)");
        cfg.cap_per_host = usize::MAX; cfg.cap_per_net = usize::MAX; cfg.cap_per_addr = 2;
        cfg.hs_host = (1e9, 1e9); cfg.hs_net = (1e9, 1e9); cfg.unknown_dst = (1e9, 1e9);
    }
    // FINDD_PUBLIC="ip:port,[ip6]:port": this server's own public addresses — a handshake signed for any other was
    // relayed by someone a desktop was misdirected to (DNS audit 5/11 #2). Unset = no check (and said so).
    match std::env::var("FINDD_PUBLIC") {
        Ok(v) if !v.trim().is_empty() => {
            for part in v.split(',').map(str::trim).filter(|x| !x.is_empty()) {
                let sa: std::net::SocketAddr = part.parse().unwrap_or_else(|_| panic!("FINDD_PUBLIC: not ip:port: {part}"));
                let ip = match sa.ip() { std::net::IpAddr::V4(a) => a.to_ipv6_mapped().octets(), std::net::IpAddr::V6(a) => a.octets() };
                cfg.public_addrs.push(Addr { ip, port: sa.port() });
            }
            eprintln!("findd: handshakes must be signed for {} address(es)", cfg.public_addrs.len());
        }
        _ => eprintln!("findd: FINDD_PUBLIC not set — the signed destination of handshakes is NOT checked"),
    }
    let mut e = Engine::new(cfg, &seed);
    let ctl = args.get(3).map(|p| {
        let _ = std::fs::remove_file(p);
        let s = UnixDatagram::bind(p).expect("control socket");
        // owner only (F MED-3): only the rendezvous, running as the same user, may ask or order
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).expect("chmod control socket");
        s.set_nonblocking(true).unwrap(); s
    });

    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    assert!(fd >= 0, "socket");
    unsafe {
        let zero: libc::c_int = 0;
        libc::setsockopt(fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, &zero as *const _ as _, 4);
        let rcv: libc::c_int = 8 << 20; // capped by net.core.rmem_max — raise it on the VPS (§12.4)
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, &rcv as *const _ as _, 4);
        let tv = libc::timeval { tv_sec: 0, tv_usec: 100_000 };
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const _ as _, std::mem::size_of::<libc::timeval>() as _);
        let mut sa: libc::sockaddr_in6 = std::mem::zeroed();
        sa.sin6_family = libc::AF_INET6 as _; sa.sin6_port = port.to_be();
        assert!(libc::bind(fd, &sa as *const _ as _, std::mem::size_of::<libc::sockaddr_in6>() as _) == 0, "bind: port busy?");
    }
    let sl = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
    let mut rbuf = vec![[0u8; 256]; B];
    let mut raddr: Vec<libc::sockaddr_in6> = vec![unsafe { std::mem::zeroed() }; B];
    let mut riov: Vec<libc::iovec> = (0..B).map(|i| libc::iovec { iov_base: rbuf[i].as_mut_ptr() as _, iov_len: 256 }).collect();
    let mut rmsg: Vec<libc::mmsghdr> = (0..B).map(|i| { let mut m: libc::mmsghdr = unsafe { std::mem::zeroed() };
        m.msg_hdr.msg_name = &mut raddr[i] as *mut _ as _; m.msg_hdr.msg_iov = &mut riov[i]; m.msg_hdr.msg_iovlen = 1; m }).collect();
    let mut sbuf = vec![[0u8; 160]; B];
    let mut saddr: Vec<libc::sockaddr_in6> = vec![unsafe { std::mem::zeroed() }; B];
    let mut siov: Vec<libc::iovec> = (0..B).map(|i| libc::iovec { iov_base: sbuf[i].as_mut_ptr() as _, iov_len: 0 }).collect();
    let mut smsg: Vec<libc::mmsghdr> = (0..B).map(|i| { let mut m: libc::mmsghdr = unsafe { std::mem::zeroed() };
        m.msg_hdr.msg_name = &mut saddr[i] as *mut _ as _; m.msg_hdr.msg_iov = &mut siov[i]; m.msg_hdr.msg_iovlen = 1; m }).collect();

    let t0 = Instant::now();
    let mut last_print = 0u64;
    let print_ms: u64 = std::env::var("FINDD_PRINT_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(60_000);
    let mut prev = e.n.clone();
    let _ = writeln!(std::io::stdout(), "findd: UDP {port}, control {}", args.get(3).map_or("none", |s| s.as_str()));
    loop {
        let now = t0.elapsed().as_millis() as u64;
        if now - last_print >= print_ms {
            let n = &e.n;
            let _ = writeln!(std::io::stdout(), "findd/λεπτό: γραμμές {} · παλμοί {} · απαντ. {} · χειραψίες {} · cookies {} · mac✗ {} · ctr✗ {} · sig✗ {} · cookie✗ {} · move {}/{} · 0x17 {} (σιωπή {}) · έξωση {} · λήξη {} · όρια host/net/όλοι {} · πεταμένες απαντ. {} · x25519✗ {} · άκυρα {} · dst✗ {} · punch {} (όριο {}) · probes {}/{}",
                e.rows(), n.beats - prev.beats, n.acks - prev.acks, n.handshakes - prev.handshakes, n.cookies - prev.cookies,
                n.mac_bad - prev.mac_bad, n.ctr_old - prev.ctr_old, n.sig_bad - prev.sig_bad, n.cookie_bad - prev.cookie_bad,
                n.move_ok - prev.move_ok, n.move_sent - prev.move_sent, n.unknown_sent - prev.unknown_sent, n.unknown_silent - prev.unknown_silent,
                n.evicted - prev.evicted, n.expired - prev.expired, format!("{}/{}/{}", n.drop_host - prev.drop_host, n.drop_net - prev.drop_net, n.drop_global - prev.drop_global), n.reply_drop - prev.reply_drop,
                n.x25519_bad - prev.x25519_bad, n.malformed - prev.malformed, n.dst_bad - prev.dst_bad,
                n.punches - prev.punches, n.punch_drop - prev.punch_drop,
                n.probes - prev.probes, n.canaries - prev.canaries);
            prev = e.n.clone(); last_print = now;
        }
        if let Some(c) = &ctl { control(&mut e, c, fd, now); }
        for (to, p) in e.due_canaries(now) { send_one(fd, &to, &p); }   // router learning (§13.4)
        e.sweep(now);

        for m in rmsg.iter_mut() { m.msg_hdr.msg_namelen = sl; }
        let n = unsafe { libc::recvmmsg(fd, rmsg.as_mut_ptr(), B as _, libc::MSG_WAITFORONE, std::ptr::null_mut()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EAGAIN) | Some(libc::EINTR) => continue, // the 100 ms receive timeout, or a signal
                _ => { eprintln!("findd: recvmmsg: {err} — exiting (systemd restarts)"); std::process::exit(1); }
            }
        }
        if n == 0 { continue; }
        let now = t0.elapsed().as_millis() as u64; // one `now` per batch (§13 Π9)
        let mut ns = 0;
        for i in 0..n as usize {
            let src = Addr { ip: raddr[i].sin6_addr.s6_addr, port: u16::from_be(raddr[i].sin6_port) };
            let len = rmsg[i].msg_len as usize;
            if let Some(l) = e.handle(src, &rbuf[i][..len], now, &mut sbuf[ns]) {
                saddr[ns] = raddr[i]; siov[ns].iov_len = l; ns += 1;
            }
        }
        let mut off = 0;
        while off < ns {
            for m in smsg.iter_mut().take(ns).skip(off) { m.msg_hdr.msg_namelen = sl; }
            // never block the loop; a message the kernel refuses is skipped, not retried forever (S fix 7)
            let m = unsafe { libc::sendmmsg(fd, smsg.as_mut_ptr().add(off), (ns - off) as _, libc::MSG_DONTWAIT) };
            if m <= 0 { e.n.reply_drop += 1; off += 1; } else { off += m as usize; }
        }
        // adaptive sleep (§13 Π9): short batches → let more arrive
        let wait = if (n as usize) < 8 { 5_000 } else if (n as usize) < 32 { 2_000 } else { 0 };
        if wait > 0 { std::thread::sleep(Duration::from_micros(wait)); }
    }
}
