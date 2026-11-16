//! The catalog and the protocol logic of findability.md §12 + §13 — no sockets, no clock:
//! the caller passes the source, the bytes and the monotonic time in ms. Every reply goes to the
//! packet's own source and is never larger than the packet (§13 Π7).
//! Reviewed: docs/review/{fable,sonnet}-2026-11-04-findd-code.md — the fixes are marked by their finding.
use crate::addr::Addr;
use crate::buckets::Buckets;
use crate::crypto::{self, SessionKeys};
use crate::wire::{self, Packet};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{self, Ed25519KeyPair};
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};

pub struct Config {
    pub cap_per_addr: usize,      // rows created from one ip:port (§13 Π1: 2)
    pub cap_per_host: usize,      // … from one IPv4 host / IPv6 /64
    pub cap_per_net: usize,       // … from one IPv4 /24 / IPv6 /48
    pub max_rows: usize,          // ~650 B/row today (F C2): 500k ≈ 325 MB
    pub grace_ms: u64,            // after start: no per-NET handshake budget (§11.15-7; F MED-1: the host budget stays)
    pub hs_host: (f32, f32),      // handshakes per source host: (per second, burst)
    pub hs_net: (f32, f32),
    pub hs_known: (f32, f32),     // global pool: pub already has a row
    pub hs_unknown: (f32, f32),   // global pool: new pub
    pub cookie_all: (f32, f32),   // S N1: no per-destination cookie limit (a cookie is smaller than its Hello)
    pub unknown_dst: (f32, f32),  // 0x17 per destination host
    pub unknown_all: (f32, f32),
    pub unauthed_life_ms: u64,    // a row needs one authenticated beat within this (§13 Π8: 90″)
    pub move_gap_ms: u64,         // ≤ 1 MOVE per row per family per this (§13 Π2: 2″)
    pub sweep_pass_ms: u64,       // the whole catalog is walked once per this (S N3 / F C3)
    pub max_probes: usize,        // pending canaries (router learning, §13.4) — one per row at most
    pub probe_wait_s: (u16, u16), // allowed canary delays (wire::PROBE_MIN_S..PROBE_MAX_S; tests use shorter)
    /// This server's own public addresses (FINDD_PUBLIC). A handshake whose SIGNED destination is not one of them was
    /// relayed by someone the desktop was misdirected to (DNS) — refused. Empty = no check (tests, local runs).
    pub public_addrs: Vec<Addr>,
    pub bucket_slots: usize,
    /// Punches toward ONE phone host (IPv4 host / IPv6 /64), ONE phone network (IPv4 /24 / IPv6 /48), and all together
    /// (security audit 6/11): whoever controls the control socket (the rendezvous) must not turn the desktops into a
    /// reflector toward a victim. The global one is only a backstop far above any real peak: a small global budget let
    /// ~100 attacker /64s drain it and block everyone's punches (second review 6/11), so the per-network one does the work.
    pub punch_target: (f32, f32),
    pub punch_net: (f32, f32),
    pub punch_all: (f32, f32),
}

impl Default for Config {
    fn default() -> Config {
        Config {
            cap_per_addr: 2, cap_per_host: 2_000, cap_per_net: 20_000, max_rows: 500_000,
            grace_ms: 5 * 60_000,
            hs_host: (20.0, 200.0), hs_net: (200.0, 2_000.0), hs_known: (2_500.0, 5_000.0), hs_unknown: (1_500.0, 3_000.0),
            cookie_all: (250_000.0, 500_000.0),
            unknown_dst: (20.0, 40.0), unknown_all: (5_000.0, 10_000.0),
            unauthed_life_ms: 90_000, move_gap_ms: 2_000, sweep_pass_ms: 30_000, max_probes: 200_000,
            probe_wait_s: (wire::PROBE_MIN_S, wire::PROBE_MAX_S), public_addrs: Vec::new(), bucket_slots: 1 << 16,
            punch_target: (5.0, 20.0), punch_net: (50.0, 200.0), punch_all: (20_000.0, 40_000.0),
        }
    }
}

#[derive(Default, Clone, Debug)]
pub struct Counters {
    pub beats: u64, pub acks: u64, pub handshakes: u64, pub cookies: u64,
    pub mac_bad: u64, pub ctr_old: u64, pub sig_bad: u64, pub x25519_bad: u64, pub cookie_bad: u64,
    pub move_sent: u64, pub move_ok: u64, pub unknown_sent: u64, pub unknown_silent: u64,
    pub evicted: u64, pub expired: u64, pub drop_host: u64, pub drop_net: u64, pub drop_global: u64,
    pub reply_drop: u64, pub malformed: u64, pub punches: u64, pub punch_drop: u64,
    pub probes: u64, pub canaries: u64, pub dst_bad: u64,
}

struct FamState { addr: Addr, ctr: u64, seen: u64 }

struct Row {
    keys: SessionKeys,
    pub_: [u8; 32],
    boot: u64,
    ctr_max: u64,
    interval_ms: u64,
    fam: [Option<FamState>; 2],
    born: u64,
    authed: bool,
    punch_ctr: u64,
    last_move: [u64; 2],
    origin: Addr,
    gpos: usize, // index in Engine::all
    probe: Option<(u64, usize, u64)>, // pending canary: (due ms, family, ctr of the probe)
}

impl Row {
    fn last_seen(&self) -> u64 { self.fam.iter().flatten().map(|f| f.seen).max().unwrap_or(self.born).max(self.born) }
    fn life_ms(&self) -> u64 { 2 * self.interval_ms + 20_000 }
    fn alive(&self, now: u64, unauthed_life: u64) -> bool {
        // a desktop measuring its router stays silent until its canary is due: it is alive meanwhile (§13.4)
        if self.probe.is_some_and(|(due, _, _)| now <= due + 15_000) { return true; }
        if self.authed { now.saturating_sub(self.last_seen()) <= self.life_ms() } else { now.saturating_sub(self.born) <= unauthed_life }
    }
    /// Eviction order (§13 Π1, F MED-2.1 + S): dead rows, then rows that never beat, then the stalest by
    /// (now − seen) / interval — the declared interval capped at 4′, so a 10′ «door open» claim buys nothing.
    fn evict_score(&self, now: u64, unauthed_life: u64) -> f64 {
        if !self.alive(now, unauthed_life) { return f64::MAX; }
        if !self.authed { return 1e12 + now.saturating_sub(self.born) as f64; }
        now.saturating_sub(self.last_seen()) as f64 / self.interval_ms.min(240_000) as f64
    }
}

pub struct Engine {
    cfg: Config,
    ks: hmac::Key,
    rng: SystemRandom,
    sk: Ed25519KeyPair,
    rows: HashMap<u64, Row>,
    all: Vec<u64>, // every rowid once, for sweeping and global sampling without snapshots (S N3, F C1)
    by_pub: HashMap<[u8; 32], u64>,
    by_addr: HashMap<Addr, Vec<u64>>,
    by_host: HashMap<u128, HashSet<u64>>,
    by_net: HashMap<u128, HashSet<u64>>,
    b_hs_host: Buckets, b_hs_net: Buckets, b_hs_known: Buckets, b_hs_unknown: Buckets,
    b_cookie_all: Buckets, b_unknown_dst: Buckets, b_unknown_all: Buckets,
    b_punch_target: Buckets, b_punch_net: Buckets, b_punch_all: Buckets,
    sweep_pos: usize,
    sweep_last: u64,
    canaries: BinaryHeap<Reverse<(u64, u64, u64)>>, // (due ms, rowid, ctr)
    pub n: Counters,
}

fn interval_ms(s: u16, flags: u8) -> u64 {
    if flags & wire::HSFLAG_DOOR_OPEN != 0 { 600_000 } else { (s.clamp(15, 240) as u64) * 1000 }
}

enum Bucket { Addr, Host, Net, Global }

impl Engine {
    /// `seed` = the server's Ed25519 identity (its public half is embedded in Orpheic).
    pub fn new(cfg: Config, seed: &[u8; 32]) -> Engine {
        let rng = SystemRandom::new();
        let mut ks = [0u8; 32];
        rng.fill(&mut ks).expect("rng");
        let b = |(r, burst): (f32, f32), slots: usize| Buckets::new(slots, r, burst);
        let s = cfg.bucket_slots;
        Engine {
            ks: hmac::Key::new(hmac::HMAC_SHA256, &ks), sk: Ed25519KeyPair::from_seed_unchecked(seed).expect("seed"), rng,
            rows: HashMap::new(), all: Vec::new(), by_pub: HashMap::new(), by_addr: HashMap::new(), by_host: HashMap::new(), by_net: HashMap::new(),
            b_hs_host: b(cfg.hs_host, s), b_hs_net: b(cfg.hs_net, s), b_hs_known: b(cfg.hs_known, 1), b_hs_unknown: b(cfg.hs_unknown, 1),
            b_cookie_all: b(cfg.cookie_all, 1), b_unknown_dst: b(cfg.unknown_dst, s), b_unknown_all: b(cfg.unknown_all, 1),
            b_punch_target: b(cfg.punch_target, s), b_punch_net: b(cfg.punch_net, s), b_punch_all: b(cfg.punch_all, 1),
            sweep_pos: 0, sweep_last: 0, canaries: BinaryHeap::new(), n: Counters::default(), cfg,
        }
    }

    pub fn rows(&self) -> usize { self.rows.len() }

    /// One datagram in; at most one reply (to `src`) written into `out`, its length returned.
    pub fn handle(&mut self, src: Addr, d: &[u8], now: u64, out: &mut [u8]) -> Option<usize> {
        if src.unanswerable() { self.n.malformed += 1; return None; }
        let Some(p) = wire::parse(d) else { self.n.malformed += 1; return None };
        let r = match p {
            Packet::Hello => self.on_hello(src, now, out),
            Packet::Hs(h) => self.on_hs(src, h, now, out),
            Packet::Beat(b) => self.on_beat(src, b, now, out),
            Packet::Probe(p) => { self.on_probe(src, p, now); None }
        };
        if let Some(l) = r { debug_assert!(l <= d.len(), "reply larger than its request"); }
        r
    }

    fn on_hello(&mut self, src: Addr, now: u64, out: &mut [u8]) -> Option<usize> {
        if !self.b_cookie_all.allow(0u8, now) { self.n.reply_drop += 1; return None; }
        self.n.cookies += 1;
        Some(wire::put_cookie(out, &crypto::cookie(&self.ks, &src.ip, src.port, now / 60_000)))
    }

    fn cookie_ok(&self, src: Addr, c: &[u8], now: u64) -> bool {
        let t = now / 60_000;
        crypto::ct_eq(c, &crypto::cookie(&self.ks, &src.ip, src.port, t))
            || (t > 0 && crypto::ct_eq(c, &crypto::cookie(&self.ks, &src.ip, src.port, t - 1)))
    }

    fn on_hs(&mut self, src: Addr, h: wire::Hs, now: u64, out: &mut [u8]) -> Option<usize> {
        // 1. cookie: the source address is real (§12.1 A)
        if !self.cookie_ok(src, h.cookie, now) { self.n.cookie_bad += 1; return None; }
        // 2. budgets keyed by SOURCE, never by pub — the narrow ones FIRST, so one host can never empty a
        //    shared pool (F HIGH-1); during grace only the per-net budget is lifted (F MED-1)
        if !self.b_hs_host.allow(src.host_key(), now) { self.n.drop_host += 1; return None; }
        if now >= self.cfg.grace_ms && !self.b_hs_net.allow(src.net_key(), now) { self.n.drop_net += 1; return None; }
        // a dead-but-unswept row does not count (F B1: a reinstall with a lower boot must get through)
        let existing = self.by_pub.get(&h.pub_).copied()
            .filter(|id| self.rows.get(id).is_some_and(|r| r.alive(now, self.cfg.unauthed_life_ms)));
        let pool_ok = if existing.is_some() { self.b_hs_known.allow(0u8, now) } else { self.b_hs_unknown.allow(0u8, now) };
        if !pool_ok { self.n.drop_global += 1; return None; }
        // 3. cheap row check: an older boot, or the same boot without a newer ctr → replay (§13 Π1)
        if let Some(rid) = existing {
            let r = &self.rows[&rid];
            if h.boot < r.boot || (h.boot == r.boot && h.ctr <= r.ctr_max) { self.n.ctr_old += 1; return None; }
        }
        // 4. Ed25519 over "orpheic-hb-v1" | bytes[0..100]
        let mut m = [0u8; 13 + wire::HS_SIGNED];
        m[..13].copy_from_slice(wire::CTX_HS); m[13..].copy_from_slice(h.signed);
        if signature::UnparsedPublicKey::new(&signature::ED25519, &h.pub_).verify(&m, h.sig).is_err() { self.n.sig_bad += 1; return None; }
        // the desktop signed WHERE it sent this: it must be us (after the signature, so the field is the desktop's own word)
        if !self.cfg.public_addrs.is_empty()
            && !self.cfg.public_addrs.iter().any(|a| a.ip == h.dst_ip && a.port == h.dst_port) {
            self.n.dst_bad += 1; return None;
        }
        // 5. X25519 → session keys
        let Some((xpub_s, keys)) = crypto::server_agree(&self.rng, h.xpub, &h.pub_, h.boot) else { self.n.x25519_bad += 1; return None };
        // 6. only now touch the catalog: drop this pub's old row (any origin), then make room (S fix 3:
        //    one eviction at a time, re-checking, from the narrowest full bucket)
        if let Some(old) = self.by_pub.get(&h.pub_).copied() { self.remove(old); }
        while let Some(b) = self.full_bucket(src) { if !self.evict_one(b, src, now) { break; } }
        let rowid = self.new_rowid();
        let mut fam: [Option<FamState>; 2] = [None, None];
        fam[src.fam() as usize] = Some(FamState { addr: src, ctr: h.ctr, seen: now });
        self.rows.insert(rowid, Row {
            keys, pub_: h.pub_, boot: h.boot, ctr_max: h.ctr, interval_ms: interval_ms(h.interval_s, h.flags),
            fam, born: now, authed: false, punch_ctr: 0, last_move: [0; 2], origin: src, gpos: self.all.len(), probe: None,
        });
        self.all.push(rowid);
        self.by_pub.insert(h.pub_, rowid);
        self.by_addr.entry(src).or_default().push(rowid);
        self.by_host.entry(src.host_key()).or_default().insert(rowid);
        self.by_net.entry(src.net_key()).or_default().insert(rowid);
        // 7. HSOK: head | confirm | sig_s over "orpheic-hb-v1/s" | bytes[0..65] | pub | xpub (§13 Π3)
        wire::put_hsok_head(out, rowid, &xpub_s, h.ctr);
        let confirm = crypto::mac16(&self.rows[&rowid].keys.conf, &[b"c", &[wire::HSOK], &rowid.to_be_bytes(), &h.ctr.to_be_bytes()]);
        out[49..65].copy_from_slice(&confirm);
        let mut sm = Vec::with_capacity(15 + 65 + 64);
        sm.extend_from_slice(wire::CTX_HSOK); sm.extend_from_slice(&out[..65]); sm.extend_from_slice(&h.pub_); sm.extend_from_slice(h.xpub);
        out[65..129].copy_from_slice(self.sk.sign(&sm).as_ref());
        self.n.handshakes += 1;
        Some(wire::HSOK_LEN)
    }

    /// The narrowest bucket that has no room for one more row from `src`.
    fn full_bucket(&self, src: Addr) -> Option<Bucket> {
        if self.by_addr.get(&src).map_or(0, |v| v.len()) >= self.cfg.cap_per_addr { return Some(Bucket::Addr); }
        if self.by_host.get(&src.host_key()).map_or(0, |s| s.len()) >= self.cfg.cap_per_host { return Some(Bucket::Host); }
        if self.by_net.get(&src.net_key()).map_or(0, |s| s.len()) >= self.cfg.cap_per_net { return Some(Bucket::Net); }
        if self.rows.len() >= self.cfg.max_rows { return Some(Bucket::Global); }
        None
    }

    fn rand_usize(&self) -> usize { let mut r = [0u8; 8]; let _ = self.rng.fill(&mut r); u64::from_be_bytes(r) as usize }

    /// Evict ONE row from bucket `b`: the worst of 32 sampled from a random starting point (F MED-2.2).
    fn evict_one(&mut self, b: Bucket, src: Addr, now: u64) -> bool {
        let ul = self.cfg.unauthed_life_ms;
        let score = |id: &u64| self.rows.get(id).map(|r| (*id, r.evict_score(now, ul)));
        let best = |it: &mut dyn Iterator<Item = (u64, f64)>| it.max_by(|a, b| a.1.total_cmp(&b.1)).map(|x| x.0);
        let victim = match b {
            Bucket::Addr => self.by_addr.get(&src).and_then(|v| best(&mut v.iter().filter_map(score))),
            Bucket::Host | Bucket::Net => {
                let set = if let Bucket::Host = b { self.by_host.get(&src.host_key()) } else { self.by_net.get(&src.net_key()) };
                set.and_then(|s| { let k = self.rand_usize() % s.len().max(1);
                    best(&mut s.iter().cycle().skip(k).take(32.min(s.len())).filter_map(score)) })
            }
            Bucket::Global => {
                if self.all.is_empty() { None } else {
                    let n = self.all.len();
                    best(&mut (0..32.min(n)).map(|_| self.all[self.rand_usize() % n]).filter_map(|id| score(&id)))
                }
            }
        };
        match victim { Some(v) => { self.remove(v); self.n.evicted += 1; true } None => false }
    }

    fn new_rowid(&self) -> u64 {
        loop {
            let mut b = [0u8; 8]; self.rng.fill(&mut b).expect("rng");
            let id = u64::from_be_bytes(b);
            if id != 0 && !self.rows.contains_key(&id) { return id; }
        }
    }

    fn remove(&mut self, rowid: u64) {
        let Some(r) = self.rows.remove(&rowid) else { return };
        // O(1) removal from `all`: move the last id into the hole and fix its gpos
        let last = self.all.pop().expect("all in step with rows");
        if last != rowid { self.all[r.gpos] = last; if let Some(m) = self.rows.get_mut(&last) { m.gpos = r.gpos; } }
        if self.by_pub.get(&r.pub_) == Some(&rowid) { self.by_pub.remove(&r.pub_); }
        if let Some(v) = self.by_addr.get_mut(&r.origin) { v.retain(|&x| x != rowid); if v.is_empty() { self.by_addr.remove(&r.origin); } }
        let hk = r.origin.host_key();
        if let Some(s) = self.by_host.get_mut(&hk) { s.remove(&rowid); if s.is_empty() { self.by_host.remove(&hk); } }
        let nk = r.origin.net_key();
        if let Some(s) = self.by_net.get_mut(&nk) { s.remove(&rowid); if s.is_empty() { self.by_net.remove(&nk); } }
    }

    fn ack(r: &Row, rowid: u64, ctr: u64, out: &mut [u8]) -> usize {
        wire::put_ack_head(out, rowid, ctr, 0);
        let m = crypto::mac16(&r.keys.mac, &[&out[..18]]);
        out[18..34].copy_from_slice(&m);
        wire::ACK_LEN
    }

    fn on_beat(&mut self, src: Addr, b: wire::Beat, now: u64, out: &mut [u8]) -> Option<usize> {
        let want = b.flags & wire::FLAG_WANT_REPLY != 0;
        let Some(r) = self.rows.get_mut(&b.rowid) else {
            // §13 Π5: unknown rowid → 0x17 only when asked, under budgets
            if !want { self.n.unknown_silent += 1; return None; }
            if !self.b_unknown_dst.allow(src.host_key(), now) || !self.b_unknown_all.allow(0u8, now) { self.n.reply_drop += 1; return None; }
            self.n.unknown_sent += 1;
            return Some(wire::put_unknown(out, b.rowid));
        };
        let fi = src.fam() as usize;
        let same_addr = r.fam[fi].as_ref().is_some_and(|f| f.addr == src);
        // cheap pre-check, nothing written before the MAC (§13 Π7)
        if same_addr && b.ctr <= r.fam[fi].as_ref().unwrap().ctr { self.n.ctr_old += 1; return None; }
        if !crypto::ct_eq(&crypto::mac16(&r.keys.mac, &[b.maced]), b.mac) { self.n.mac_bad += 1; return None; }
        if same_addr {
            let f = r.fam[fi].as_mut().unwrap();
            f.ctr = b.ctr; f.seen = now;
            r.ctr_max = r.ctr_max.max(b.ctr); r.authed = true;
            self.n.beats += 1;
            if want { self.n.acks += 1; return Some(Self::ack(r, b.rowid, b.ctr, out)); }
            return None;
        }
        // other address (or an empty family): §13 Π2 — change NOTHING unless the echo proves the new address
        let t = now / 60_000;
        let nonce_ok = b.echo.is_some_and(|e| {
            e == crypto::move_nonce(&self.ks, b.rowid, &src.ip, src.port, t)
                || (t > 0 && e == crypto::move_nonce(&self.ks, b.rowid, &src.ip, src.port, t - 1))
        });
        let newer = r.fam[fi].as_ref().map_or(true, |f| b.ctr > f.ctr);
        if nonce_ok && newer {
            r.fam[fi] = Some(FamState { addr: src, ctr: b.ctr, seen: now });
            r.ctr_max = r.ctr_max.max(b.ctr); r.authed = true;
            self.n.move_ok += 1; self.n.beats += 1;
            if want { self.n.acks += 1; return Some(Self::ack(r, b.rowid, b.ctr, out)); }
            return None;
        }
        if r.last_move[fi] != 0 && now.saturating_sub(r.last_move[fi]) < self.cfg.move_gap_ms { self.n.reply_drop += 1; return None; }
        r.last_move[fi] = now.max(1);
        let nonce = crypto::move_nonce(&self.ks, b.rowid, &src.ip, src.port, t);
        wire::put_move_head(out, b.rowid, nonce);
        let m = crypto::mac16(&r.keys.mac, &[&out[..17]]);
        out[17..33].copy_from_slice(&m);
        self.n.move_sent += 1;
        Some(wire::MOVE_LEN)
    }

    /// «Send me a canary in `wait_s` seconds» (§13.4): only from the row's own, current address in that family
    /// (the canary goes back the SAME way — it measures the real flow, never a third party), MAC'd, newer ctr.
    /// Never an immediate answer. The declared interval is taken (authenticated), so the row's life follows
    /// the desktop's learned pace.
    fn on_probe(&mut self, src: Addr, p: wire::Probe, now: u64) {
        let Some(r) = self.rows.get_mut(&p.rowid) else { self.n.unknown_silent += 1; return };
        let fi = src.fam() as usize;
        let Some(f) = r.fam[fi].as_ref() else { return };
        if f.addr != src || p.ctr <= f.ctr { self.n.ctr_old += 1; return; }
        if !crypto::ct_eq(&crypto::mac16(&r.keys.mac, &[p.maced]), p.mac) { self.n.mac_bad += 1; return; }
        // one pending probe per row, and the cap counts every queued entry (S night H2: overwriting left the old heap entry
        // behind, so one row with rising ctr could fill memory)
        if r.probe.is_some() || self.canaries.len() >= self.cfg.max_probes { self.n.reply_drop += 1; return; }
        let f = r.fam[fi].as_mut().unwrap();
        f.ctr = p.ctr; f.seen = now;
        r.ctr_max = r.ctr_max.max(p.ctr); r.authed = true;
        r.interval_ms = interval_ms(p.interval_s, 0);
        let due = now + p.wait_s.clamp(self.cfg.probe_wait_s.0, self.cfg.probe_wait_s.1) as u64 * 1000;
        r.probe = Some((due, fi, p.ctr));
        self.canaries.push(Reverse((due, p.rowid, p.ctr)));
        self.n.probes += 1;
    }

    /// The canaries due by `now`: one packet each, to the row's address in the probe's family — if the row, its
    /// probe and that address are all still what they were (a moved or re-joined desktop gets nothing).
    pub fn due_canaries(&mut self, now: u64) -> Vec<(Addr, [u8; wire::CANARY_LEN])> {
        let mut v = Vec::new();
        while let Some(Reverse((due, rowid, ctr))) = self.canaries.peek().copied() {
            if due > now { break; }
            self.canaries.pop();
            let Some(r) = self.rows.get_mut(&rowid) else { continue };
            let Some((pdue, fi, pctr)) = r.probe else { continue };
            if pdue != due || pctr != ctr { continue; }
            r.probe = None;
            let Some(f) = r.fam[fi].as_ref() else { continue };
            let mut c = [0u8; wire::CANARY_LEN];
            wire::put_canary_head(&mut c, rowid, ctr);
            let m = crypto::mac16(&r.keys.mac, &[&c[..17]]);
            c[17..33].copy_from_slice(&m);
            v.push((f.addr, c));
            self.n.canaries += 1;
        }
        v
    }

    /// Where a desktop can be reached now: the live family addresses of its row (§12.6).
    pub fn where_is(&self, pub_: &[u8; 32], now: u64) -> Vec<Addr> {
        let Some(r) = self.by_pub.get(pub_).and_then(|id| self.rows.get(id)) else { return Vec::new() };
        if !r.authed { return Vec::new(); }
        r.fam.iter().flatten().filter(|f| now.saturating_sub(f.seen) <= r.life_ms()).map(|f| f.addr).collect()
    }

    /// Tell a desktop that a phone at `phone` wants it (§12.6, 0x18): one packet per live family.
    /// The counter advances ONLY when something is sent (F MED-4).
    pub fn punch(&mut self, pub_: &[u8; 32], phone: Addr, now: u64) -> Vec<(Addr, [u8; wire::PUNCH_LEN])> {
        if phone.unanswerable() { return Vec::new(); }
        let Some(&rowid) = self.by_pub.get(pub_) else { return Vec::new() };
        let to: Vec<Addr> = {
            let Some(r) = self.rows.get(&rowid) else { return Vec::new() };
            if !r.authed { return Vec::new(); }
            let life = r.life_ms();
            r.fam.iter().flatten().filter(|f| now.saturating_sub(f.seen) <= life).map(|f| f.addr).collect()
        };
        if to.is_empty() { return Vec::new(); }
        // Only a punch that WOULD be sent spends a token (the target is the phone, the reflected traffic goes there).
        if !self.b_punch_target.allow(phone.host_key(), now) || !self.b_punch_net.allow(phone.net_key(), now)
            || !self.b_punch_all.allow(0u8, now) {
            self.n.punch_drop += 1;
            return Vec::new();
        }
        let Some(r) = self.rows.get_mut(&rowid) else { return Vec::new() };
        r.punch_ctr += 1;
        let mut v = Vec::new();
        for a in to {
            let mut p = [0u8; wire::PUNCH_LEN];
            wire::put_punch_head(&mut p, rowid, r.punch_ctr, &phone.ip, phone.port);
            let m = crypto::mac16(&r.keys.mac, &[&p[..35]]);
            p[35..51].copy_from_slice(&m);
            v.push((a, p));
        }
        self.n.punches += v.len() as u64;
        v
    }

    /// Paced sweep (§12.4, S N3): one pass over the whole catalog per `sweep_pass_ms`, by index — no snapshot.
    pub fn sweep(&mut self, now: u64) {
        let dt = now.saturating_sub(self.sweep_last);
        if dt == 0 || self.all.is_empty() { self.sweep_last = now; return; }
        let n = self.all.len();
        let budget = ((n as u64 * dt / self.cfg.sweep_pass_ms.max(1)) as usize).clamp(1, n);
        self.sweep_last = now;
        for _ in 0..budget {
            if self.all.is_empty() { break; }
            if self.sweep_pos >= self.all.len() { self.sweep_pos = 0; }
            let id = self.all[self.sweep_pos];
            if self.rows.get(&id).is_some_and(|r| !r.alive(now, self.cfg.unauthed_life_ms)) {
                self.remove(id); self.n.expired += 1; // the last id moved into this slot: look at it next
            } else {
                self.sweep_pos += 1;
            }
        }
    }
}

#[cfg(test)]
pub mod tests;
