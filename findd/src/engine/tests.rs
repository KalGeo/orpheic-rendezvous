//! Engine tests with a minimal desktop written from §13 alone (the C++ desktop must behave the same).
use super::*;
use crate::client::Desk;
use ring::signature::KeyPair;

const SEED: [u8; 32] = [42u8; 32];

fn server_pub() -> Vec<u8> { Ed25519KeyPair::from_seed_unchecked(&SEED).unwrap().public_key().as_ref().to_vec() }
pub fn engine() -> Engine { Engine::new(Config::default(), &SEED) }
fn send(e: &mut Engine, from: Addr, p: &[u8], now: u64) -> Option<Vec<u8>> {
    let mut o = [0u8; 256];
    let r = e.handle(from, p, now, &mut o).map(|l| o[..l].to_vec());
    if let Some(ref v) = r { assert!(v.len() <= p.len(), "reply {} > request {}", v.len(), p.len()); }
    r
}
/// Full handshake at `now`; returns true when the desktop accepted it.
pub fn join(e: &mut Engine, d: &mut Desk, now: u64) -> bool {
    let c = send(e, d.addr, &Desk::hello(), now).expect("cookie");
    let (hs, eph, xpub) = d.hs(&c[1..17]);
    let Some(ok) = send(e, d.addr, &hs, now) else { return false };
    d.accept(&ok, eph, xpub, &server_pub())
}
fn a(last: u8, port: u16) -> Addr { Addr::v4([10, 0, 0, last], port) }

#[test]
fn happy_path() {
    let mut e = engine();
    let mut d = Desk::new(a(1, 5000), 1 << 32);
    assert!(join(&mut e, &mut d, 1_000));
    assert!(e.where_is(&d.pub_, 2_000).is_empty(), "not online before the first authenticated beat");
    let b = d.beat(false, None);
    assert!(send(&mut e, d.addr, &b, 4_000).is_none(), "no reply unless asked");
    let b = d.beat(true, None);
    let r = send(&mut e, d.addr, &b, 5_000).expect("ack");
    assert_eq!(r[0], wire::ACK);
    assert!(d.mac_ok(&r, 18));
    assert_eq!(e.where_is(&d.pub_, 6_000), vec![d.addr]);
}

#[test]
fn bad_mac_and_replay_change_nothing() {
    let mut e = engine();
    let mut d = Desk::new(a(1, 5000), 1 << 32);
    assert!(join(&mut e, &mut d, 0));
    let good = d.beat(true, None);
    let mut bad = good.clone(); bad[20] ^= 1;
    assert!(send(&mut e, d.addr, &bad, 1_000).is_none());
    assert_eq!(e.n.mac_bad, 1);
    assert!(send(&mut e, d.addr, &good, 1_100).is_some());
    assert!(send(&mut e, d.addr, &good, 1_200).is_none(), "replay");
    assert_eq!(e.n.ctr_old, 1);
}

#[test]
fn forwarded_copy_from_elsewhere_does_not_burn_the_counter() {
    // F HIGH-1 / S: an on-path forwarder resends D's beat from his own address
    let mut e = engine();
    let mut d = Desk::new(a(1, 5000), 1 << 32);
    assert!(join(&mut e, &mut d, 0));
    let b1 = d.beat(false, None);
    let mv = send(&mut e, a(66, 6000), &b1, 1_000).expect("move challenge to the forwarder");
    assert_eq!(mv[0], wire::MOVE);
    // the honest original still counts, the row did not move
    assert!(send(&mut e, d.addr, &b1, 1_001).is_none());
    assert_eq!(e.n.beats, 1);
    assert_eq!(e.where_is(&d.pub_, 2_000), vec![d.addr]);
}

#[test]
fn real_move_with_echo() {
    let mut e = engine();
    let mut d = Desk::new(a(1, 5000), 1 << 32);
    assert!(join(&mut e, &mut d, 0));
    send(&mut e, d.addr, &d.beat(false, None), 500);
    d.addr = a(1, 7777); // router changed the port
    let mv = send(&mut e, d.addr, &d.beat(false, None), 10_000).expect("move");
    assert!(d.mac_ok(&mv, 17));
    let nonce = u64::from_be_bytes(mv[9..17].try_into().unwrap());
    let r = send(&mut e, d.addr, &d.beat(true, Some(nonce)), 10_100).expect("ack after move");
    assert_eq!(r[0], wire::ACK);
    assert_eq!(e.where_is(&d.pub_, 11_000), vec![d.addr]);
    assert_eq!(e.n.move_ok, 1);
}

#[test]
fn nonce_for_one_address_does_not_move_to_another() {
    let mut e = engine();
    let mut d = Desk::new(a(1, 5000), 1 << 32);
    assert!(join(&mut e, &mut d, 0));
    send(&mut e, d.addr, &d.beat(false, None), 500);
    let mv = send(&mut e, a(2, 5000), &d.beat(false, None), 10_000).unwrap();
    let nonce = u64::from_be_bytes(mv[9..17].try_into().unwrap());
    // the echo arrives from a THIRD address: no move, only (rate-limited) another challenge
    let r = send(&mut e, a(3, 5000), &d.beat(true, Some(nonce)), 10_100);
    assert!(r.is_none_or(|v| v[0] == wire::MOVE));
    assert_eq!(e.where_is(&d.pub_, 11_000), vec![a(1, 5000)]);
}

#[test]
fn unknown_rowid_only_when_asked() {
    let mut e = engine();
    let mut d = Desk::new(a(1, 5000), 1 << 32);
    assert!(join(&mut e, &mut d, 0));
    let mut e2 = engine(); // "the server restarted"
    assert!(send(&mut e2, d.addr, &d.beat(false, None), 1_000).is_none());
    let r = send(&mut e2, d.addr, &d.beat(true, None), 2_000).unwrap();
    assert_eq!(r.len(), wire::UNKNOWN_LEN);
    assert_eq!(r[0], wire::UNKNOWN);
}

#[test]
fn handshake_replay_and_older_boot_are_refused() {
    let mut e = engine();
    let mut d = Desk::new(a(1, 5000), 5 << 32);
    let c = send(&mut e, d.addr, &Desk::hello(), 0).unwrap();
    let (hs, eph, xpub) = d.hs(&c[1..17]);
    let ok = send(&mut e, d.addr, &hs, 0).unwrap();
    assert!(d.accept(&ok, eph, xpub, &server_pub()));
    assert!(send(&mut e, d.addr, &hs, 1_000).is_none(), "same handshake again");
    d.boot = 4 << 32; // same key, older boot (a replay from before a restart of Orpheic)
    let (hs2, _, _) = d.hs(&c[1..17]);
    assert!(send(&mut e, d.addr, &hs2, 2_000).is_none(), "older boot");
    assert_eq!(e.rows(), 1);
}

#[test]
fn pub_without_private_key_cannot_displace() {
    let mut e = engine();
    let mut d = Desk::new(a(1, 5000), 1 << 32);
    assert!(join(&mut e, &mut d, 0));
    send(&mut e, d.addr, &d.beat(false, None), 100);
    let mut evil = Desk::new(a(9, 5000), 9 << 32);
    let c = send(&mut e, evil.addr, &Desk::hello(), 200).unwrap();
    let (mut hs, _, _) = evil.hs(&c[1..17]);
    hs[17..49].copy_from_slice(&d.pub_); // victim's pub, evil's signature
    assert!(send(&mut e, evil.addr, &hs, 200).is_none());
    assert_eq!(e.n.sig_bad, 1);
    assert_eq!(e.where_is(&d.pub_, 300), vec![d.addr]);
}

#[test]
fn wrong_or_foreign_cookie_is_silent() {
    let mut e = engine();
    let mut d = Desk::new(a(1, 5000), 1 << 32);
    let c = send(&mut e, a(2, 5000), &Desk::hello(), 0).unwrap(); // cookie for another address
    let (hs, _, _) = d.hs(&c[1..17]);
    assert!(send(&mut e, d.addr, &hs, 0).is_none());
    let (hs, _, _) = d.hs(&[0u8; 16]);
    assert!(send(&mut e, d.addr, &hs, 0).is_none());
    assert_eq!(e.n.cookie_bad, 2);
    // a cookie lives two minutes, not three
    let c = send(&mut e, d.addr, &Desk::hello(), 0).unwrap();
    let (hs, _, _) = d.hs(&c[1..17]);
    assert!(send(&mut e, d.addr, &hs, 3 * 60_000).is_none());
}

#[test]
fn third_row_on_one_address_evicts_the_stalest() {
    let mut e = engine();
    let mut d1 = Desk::new(a(1, 5000), 1 << 32);
    let mut d2 = Desk::new(a(1, 5000), 1 << 32);
    let mut d3 = Desk::new(a(1, 5000), 1 << 32);
    assert!(join(&mut e, &mut d1, 0));
    assert!(join(&mut e, &mut d2, 0));
    send(&mut e, d2.addr, &d2.beat(false, None), 50_000); // d2 fresh, d1 stale
    assert!(join(&mut e, &mut d3, 60_000));
    assert_eq!(e.rows(), 2);
    assert_eq!(e.n.evicted, 1);
    assert!(e.where_is(&d1.pub_, 60_000).is_empty());
    assert!(!e.where_is(&d2.pub_, 60_000).is_empty());
}

#[test]
fn sweep_removes_dead_rows() {
    let mut e = engine();
    let mut d = Desk::new(a(1, 5000), 1 << 32);
    let mut q = Desk::new(a(2, 5000), 1 << 32);
    assert!(join(&mut e, &mut d, 0));
    assert!(join(&mut e, &mut q, 0)); // never beats
    send(&mut e, d.addr, &d.beat(false, None), 3_000);
    e.sweep(91_000);
    assert_eq!(e.rows(), 1, "the row without an authenticated beat is gone after 90″");
    e.sweep(3_000 + 2 * 60_000 + 20_001);
    assert_eq!(e.rows(), 0, "2·interval + 20″ after the last beat");
}

#[test]
fn punch_reaches_the_live_address() {
    let mut e = engine();
    let mut d = Desk::new(a(1, 5000), 1 << 32);
    assert!(join(&mut e, &mut d, 0));
    assert!(e.punch(&d.pub_, a(200, 9000), 10).is_empty(), "not before the first beat");
    send(&mut e, d.addr, &d.beat(false, None), 3_000);
    let p = e.punch(&d.pub_, a(200, 9000), 4_000);
    assert_eq!(p.len(), 1);
    assert_eq!(p[0].0, d.addr);
    assert!(d.mac_ok(&p[0].1, 35));
    assert_eq!(u64::from_be_bytes(p[0].1[9..17].try_into().unwrap()), 1);
}

#[test]
fn host_budget_after_grace() {
    let mut cfg = Config::default(); cfg.grace_ms = 0; cfg.hs_host = (0.0, 3.0);
    let mut e = Engine::new(cfg, &SEED);
    let mut ok = 0;
    for i in 0..6 { let mut d = Desk::new(Addr::v4([10, 0, 0, 1], 5000 + i), 1 << 32); if join(&mut e, &mut d, 1_000) { ok += 1; } }
    assert_eq!(ok, 3);
    assert_eq!(e.n.drop_host, 3);
}

#[test]
fn privileged_source_port_is_ignored() {
    let mut e = engine();
    assert!(send(&mut e, a(1, 53), &Desk::hello(), 0).is_none());
}

// ---- tests from docs/review/{fable,sonnet}-2026-11-04-findd-code.md (T = Fable, S = Sonnet) ----

fn hs_for(e: &mut Engine, d: &mut Desk, now: u64) -> Vec<u8> {
    let c = send(e, d.addr, &Desk::hello(), now).expect("cookie");
    d.hs(&c[1..17]).0
}

#[test]
fn t1_host_over_budget_does_not_touch_the_global_pool() {
    let mut cfg = Config::default(); cfg.grace_ms = 0; cfg.hs_host = (0.0, 2.0); cfg.hs_unknown = (0.0, 10.0);
    let mut e = Engine::new(cfg, &SEED);
    let mut a = Desk::new(Addr::v4([10, 0, 0, 1], 5000), 1 << 32);
    let mut hs = hs_for(&mut e, &mut a, 0);
    hs[120] ^= 1; // garbage signature
    for _ in 0..50 { send(&mut e, a.addr, &hs, 0); }
    let mut b = Desk::new(Addr::v4([10, 0, 9, 1], 5000), 1 << 32);
    assert!(join(&mut e, &mut b, 0), "another host still joins");
    assert_eq!(e.n.drop_host, 48);
    assert_eq!(e.n.drop_global, 0);
}

#[test]
fn t2_grace_lifts_only_the_net_budget() {
    let mut cfg = Config::default(); cfg.hs_host = (0.0, 5.0); cfg.hs_net = (0.0, 0.0); // grace is on (5′)
    let mut e = Engine::new(cfg, &SEED);
    let mut ok = 0;
    for i in 0..20 { let mut d = Desk::new(Addr::v4([10, 0, 0, 1], 5000 + i), 1 << 32); if join(&mut e, &mut d, 1_000) { ok += 1; } }
    assert_eq!(ok, 5, "the host budget still applies in grace");
    let mut n = Desk::new(Addr::v4([10, 0, 0, 2], 5000), 1 << 32);
    assert!(join(&mut e, &mut n, 1_000), "a neighbour in the same /24 joins: net budget lifted in grace");
}

#[test]
fn t3_bad_signature_never_evicts() {
    let mut e = engine();
    let mut d1 = Desk::new(a(1, 5000), 1 << 32); let mut d2 = Desk::new(a(1, 5000), 1 << 32);
    assert!(join(&mut e, &mut d1, 0)); assert!(join(&mut e, &mut d2, 0));
    send(&mut e, d1.addr, &d1.beat(false, None), 3_000); send(&mut e, d2.addr, &d2.beat(false, None), 3_000);
    let mut x = Desk::new(a(1, 5000), 1 << 32);
    let mut hs = hs_for(&mut e, &mut x, 4_000); hs[110] ^= 1;
    assert!(send(&mut e, x.addr, &hs, 4_000).is_none());
    assert_eq!(e.rows(), 2); assert_eq!(e.n.evicted, 0);
    assert!(!e.where_is(&d1.pub_, 5_000).is_empty() && !e.where_is(&d2.pub_, 5_000).is_empty());
}

#[test]
fn t4_door_open_row_is_not_immune_to_eviction() {
    let mut e = engine();
    let mut liar = Desk::new(a(1, 5000), 1 << 32);
    let c = send(&mut e, liar.addr, &Desk::hello(), 0).unwrap();
    let (mut hs, eph, xpub) = liar.hs(&c[1..17]);
    hs[99] = wire::HSFLAG_DOOR_OPEN; // re-sign with the flag
    let mut m = wire::CTX_HS.to_vec(); m.extend_from_slice(&hs[..wire::HS_SIGNED]);
    let sg = liar.kp.sign(&m); hs[wire::HS_SIGNED..wire::HS_LEN].copy_from_slice(sg.as_ref());
    let ok = send(&mut e, liar.addr, &hs, 0).unwrap();
    assert!(liar.accept(&ok, eph, xpub, &server_pub()));
    send(&mut e, liar.addr, &liar.beat(false, None), 1_000);           // last seen 1″ → 500″ ago at 501″
    let mut honest = Desk::new(a(1, 5000), 1 << 32);
    assert!(join(&mut e, &mut honest, 400_000));
    send(&mut e, honest.addr, &honest.beat(false, None), 446_000);     // 55″ ago at 501″
    let mut third = Desk::new(a(1, 5000), 1 << 32);
    assert!(join(&mut e, &mut third, 501_000));
    assert!(e.where_is(&liar.pub_, 501_000).is_empty(), "500″/240″ is staler than 55″/60″");
    assert!(!e.where_is(&honest.pub_, 501_000).is_empty());
}

#[test]
fn t5_eviction_considers_the_whole_bucket() {
    // 30 rows < the 32-row sample: the whole bucket is looked at, whatever the start (F T5)
    let mut cfg = Config::default(); cfg.cap_per_host = 30; cfg.cap_per_addr = 30;
    let mut e = Engine::new(cfg, &SEED);
    let mut ds: Vec<Desk> = (0..30).map(|i| Desk::new(Addr::v4([10, 0, 0, 1], 6000 + i), 1 << 32)).collect();
    for d in ds.iter_mut() { assert!(join(&mut e, d, 0)); }
    let stale = 17;
    for (i, d) in ds.iter_mut().enumerate() { let t = if i == stale { 1_000 } else { 100_000 }; send(&mut e, d.addr, &d.beat(false, None), t); }
    let mut n = Desk::new(Addr::v4([10, 0, 0, 1], 7000), 1 << 32);
    assert!(join(&mut e, &mut n, 110_000));
    assert_eq!(e.rows(), 30);
    assert_eq!(e.n.evicted, 1);
    assert!(e.where_is(&ds[stale].pub_, 110_000).is_empty(), "the stale one went, wherever it sat in the set");
}

#[test]
fn t7_punch_ctr_does_not_advance_when_no_family_is_live() {
    let mut e = engine();
    let mut d = Desk::new(a(1, 5000), 1 << 32);
    assert!(join(&mut e, &mut d, 0));
    send(&mut e, d.addr, &d.beat(false, None), 3_000);
    let late = 3_000 + 2 * 60_000 + 20_001;
    for _ in 0..70 { assert!(e.punch(&d.pub_, a(200, 9000), late).is_empty()); }
    send(&mut e, d.addr, &d.beat(false, None), late);
    let p = e.punch(&d.pub_, a(200, 9000), late + 1);
    assert_eq!(u64::from_be_bytes(p[0].1[9..17].try_into().unwrap()), 1);
}

#[test]
fn punches_toward_one_target_are_limited_others_still_pass() { // security audit 6/11: no reflector toward a victim
    let mut e = engine();
    let mut d = Desk::new(a(1, 5000), 1 << 32);
    assert!(join(&mut e, &mut d, 0));
    send(&mut e, d.addr, &d.beat(false, None), 3_000);
    let burst = Config::default().punch_target.1 as usize;
    let sent = (0..burst + 30).filter(|_| !e.punch(&d.pub_, a(200, 9000), 4_000).is_empty()).count();
    assert_eq!(sent, burst, "only the burst toward one phone host, at one instant");
    assert!(e.n.punch_drop >= 30);
    assert!(!e.punch(&d.pub_, a(201, 9000), 4_000).is_empty(), "another phone host is not affected");
    assert!(!e.punch(&d.pub_, a(200, 9000), 5_000).is_empty(), "and the bucket refills");
}

#[test]
fn punches_toward_one_network_are_limited_another_network_still_passes() { // second review 6/11: no global drain
    let mut e = engine();
    let mut d = Desk::new(a(1, 5000), 1 << 32);
    assert!(join(&mut e, &mut d, 0));
    send(&mut e, d.addr, &d.beat(false, None), 3_000);
    let net_burst = Config::default().punch_net.1 as usize;
    // Many hosts of ONE /24 (each under its own per-host burst): the per-network burst is what stops them.
    let mut sent = 0;
    for h in 0..=254u8 { for _ in 0..2 { if !e.punch(&d.pub_, Addr::v4([172, 16, 5, h], 9000), 4_000).is_empty() { sent += 1; } } }
    assert_eq!(sent, net_burst, "one /24 gets the per-network burst, no more");
    assert!(!e.punch(&d.pub_, Addr::v4([172, 16, 6, 1], 9000), 4_000).is_empty(), "another /24 is not affected");
}

fn v6(last: u8, port: u16) -> Addr { let mut ip = [0u8; 16]; ip[0] = 0x2a; ip[15] = last; Addr { ip, port } }

#[test]
fn t8_second_family_joins_only_through_echo_and_both_are_listed() {
    let mut e = engine();
    let mut d = Desk::new(a(1, 5000), 1 << 32);
    assert!(join(&mut e, &mut d, 0));
    send(&mut e, d.addr, &d.beat(false, None), 3_000);
    let mv = send(&mut e, v6(1, 5000), &d.beat(false, None), 4_000).unwrap();
    assert_eq!(mv[0], wire::MOVE);
    assert_eq!(e.where_is(&d.pub_, 4_000), vec![d.addr]);
    let nonce = u64::from_be_bytes(mv[9..17].try_into().unwrap());
    assert!(send(&mut e, v6(1, 5000), &d.beat(true, Some(nonce)), 4_100).is_some());
    assert_eq!(e.where_is(&d.pub_, 5_000).len(), 2);
    // only v6 keeps beating: the row lives
    let t = 3_000 + 2 * 60_000 + 20_000 + 5_000; // the v4 address is past its life, the v6 one just beat
    send(&mut e, v6(1, 5000), &d.beat(false, None), t);
    e.sweep(t + 1);
    assert_eq!(e.rows(), 1);
    assert_eq!(e.where_is(&d.pub_, t + 1), vec![v6(1, 5000)]);
}

#[test]
fn t10_move_nonce_accepted_in_previous_minute_only() {
    let mut e = engine();
    let mut d = Desk::new(a(1, 5000), 1 << 32);
    assert!(join(&mut e, &mut d, 0));
    send(&mut e, d.addr, &d.beat(false, None), 1_000);
    let mv = send(&mut e, a(1, 6000), &d.beat(false, None), 59_900).unwrap();
    let nonce = u64::from_be_bytes(mv[9..17].try_into().unwrap());
    assert_eq!(send(&mut e, a(1, 6000), &d.beat(true, Some(nonce)), 60_100).unwrap()[0], wire::ACK);
    let mv = send(&mut e, a(1, 7000), &d.beat(false, None), 62_200).unwrap();
    let nonce = u64::from_be_bytes(mv[9..17].try_into().unwrap());
    assert_eq!(send(&mut e, a(1, 7000), &d.beat(true, Some(nonce)), 180_100).unwrap()[0], wire::MOVE, "two minutes later: a new challenge");
}

#[test]
fn t11_cookie_boundary() {
    let mut e = engine();
    let mut d = Desk::new(a(1, 5000), 1 << 32);
    let c = send(&mut e, d.addr, &Desk::hello(), 59_999).unwrap();
    let (hs, _, _) = d.hs(&c[1..17]);
    assert!(send(&mut e, d.addr, &hs, 119_999).is_some());
    let c = send(&mut e, d.addr, &Desk::hello(), 59_999).unwrap();
    let (hs, _, _) = d.hs(&c[1..17]);
    assert!(send(&mut e, d.addr, &hs, 120_000).is_none());
}

#[test]
fn t12_unknown_rowid_budget_per_destination() {
    let mut cfg = Config::default(); cfg.unknown_dst = (0.0, 3.0);
    let mut e = Engine::new(cfg, &SEED);
    let mut d = Desk::new(a(1, 5000), 1 << 32);
    assert!(join(&mut e, &mut d, 0));
    let mut e2 = Engine::new({ let mut c = Config::default(); c.unknown_dst = (0.0, 3.0); c }, &SEED);
    for _ in 0..3 { assert!(send(&mut e2, d.addr, &d.beat(true, None), 1_000).is_some()); }
    assert!(send(&mut e2, d.addr, &d.beat(true, None), 1_000).is_none());
    assert_eq!(e2.n.reply_drop, 1);
    assert!(send(&mut e2, a(2, 5000), &d.beat(true, None), 1_000).is_some(), "another host still gets its 0x17");
    let _ = e;
}

#[test]
fn t13_rehandshake_replaces_row_and_old_rowid_is_unknown() {
    let mut e = engine();
    let mut d = Desk::new(a(1, 5000), 1 << 32);
    assert!(join(&mut e, &mut d, 0));
    let old = d.rowid;
    assert!(join(&mut e, &mut d, 1_000));
    assert_eq!(e.rows(), 1);
    let new = d.rowid; d.rowid = old;
    assert_eq!(send(&mut e, d.addr, &d.beat(true, None), 2_000).unwrap()[0], wire::UNKNOWN);
    let _ = new;
}

#[test]
fn t14_sweep_reaches_rows_inserted_later_without_snapshots() {
    let mut e = engine();
    let mut ds: Vec<Desk> = (0..3).map(|i| Desk::new(a(i + 1, 5000), 1 << 32)).collect();
    for d in ds.iter_mut() { assert!(join(&mut e, d, 0)); }
    e.sweep(1);
    let mut late = Desk::new(a(9, 5000), 1 << 32);
    assert!(join(&mut e, &mut late, 2));
    e.sweep(200_000); e.sweep(400_000);
    assert_eq!(e.rows(), 0);
    assert!(e.all.is_empty());
}

#[test]
fn t15_reflected_server_packets_are_dropped() {
    let mut e = engine();
    for (t, l) in [(wire::ACK, wire::ACK_LEN), (wire::MOVE, wire::MOVE_LEN), (wire::PUNCH, wire::PUNCH_LEN),
                   (wire::HSOK, wire::HSOK_LEN), (wire::UNKNOWN, wire::UNKNOWN_LEN), (wire::COOKIE, wire::COOKIE_LEN)] {
        let mut p = vec![0u8; l]; p[0] = t;
        assert!(send(&mut e, a(1, 5000), &p, 0).is_none());
    }
    assert_eq!(e.n.malformed, 6);
}

#[test]
fn t16_max_rows_eviction() {
    let mut cfg = Config::default(); cfg.max_rows = 8;
    let mut e = Engine::new(cfg, &SEED);
    let mut ds: Vec<Desk> = (0..9).map(|i| Desk::new(a(i + 1, 5000), 1 << 32)).collect();
    for (i, d) in ds.iter_mut().enumerate().take(8) { assert!(join(&mut e, d, 0)); send(&mut e, d.addr, &d.beat(false, None), if i == 3 { 1_000 } else { 50_000 }); }
    assert!(join(&mut e, &mut ds[8], 60_000));
    assert_eq!(e.rows(), 8);
    assert_eq!(e.n.evicted, 1);
}

#[test]
fn t17_dead_row_does_not_block_reinstall() {
    let mut e = engine();
    let mut d = Desk::new(a(1, 5000), 5 << 32);
    assert!(join(&mut e, &mut d, 0));
    send(&mut e, d.addr, &d.beat(false, None), 1_000);
    d.boot = 4 << 32; d.ctr = 0; // reinstall: the boot counter went back
    assert!(join(&mut e, &mut d, 1_000 + 2 * 60_000 + 20_001), "dead row (not yet swept) must not block");
    assert_eq!(e.rows(), 1);
}

#[test]
fn t18_hs_with_low_order_xpub_is_refused() {
    let mut e = engine();
    let mut d = Desk::new(a(1, 5000), 1 << 32);
    let c = send(&mut e, d.addr, &Desk::hello(), 0).unwrap();
    let (mut hs, _, _) = d.hs(&c[1..17]);
    hs[65..97].fill(0);
    let mut m = wire::CTX_HS.to_vec(); m.extend_from_slice(&hs[..wire::HS_SIGNED]);
    let sg = d.kp.sign(&m); hs[wire::HS_SIGNED..wire::HS_LEN].copy_from_slice(sg.as_ref());
    assert!(send(&mut e, d.addr, &hs, 0).is_none());
    assert_eq!(e.rows(), 0);
    assert_eq!(e.n.x25519_bad, 1);
}

#[test]
fn t20_off_by_one_lengths_are_dropped() {
    let mut e = engine();
    for (t, l) in [(wire::HS, wire::HS_LEN + 1), (wire::BEAT, wire::BEAT_LEN + 1), (wire::BEAT, wire::BEAT_ECHO_LEN - 1), (wire::HELLO, wire::HELLO_LEN - 1)] {
        let mut p = vec![0u8; l]; p[0] = t;
        assert!(send(&mut e, a(1, 5000), &p, 0).is_none());
    }
}

#[test]
fn s1_many_hellos_from_one_host_all_get_cookies() {
    let mut e = engine();
    for i in 0..200 { assert!(send(&mut e, a(1, 5000 + i), &Desk::hello(), 0).is_some()); }
}

#[test]
fn s3_rehandshake_from_other_origin_respects_caps() {
    let mut e = engine();
    let mut d1 = Desk::new(a(1, 5000), 1 << 32); let mut d2 = Desk::new(a(1, 5000), 1 << 32);
    assert!(join(&mut e, &mut d1, 0)); assert!(join(&mut e, &mut d2, 0));
    let mut d3 = Desk::new(a(2, 5000), 1 << 32);
    assert!(join(&mut e, &mut d3, 0));
    d3.addr = a(1, 5000); // the same pub re-handshakes from the full address
    assert!(join(&mut e, &mut d3, 10_000));
    assert_eq!(e.by_addr.get(&a(1, 5000)).map(|v| v.len()), Some(2), "the cap holds: one of the two was evicted");
    assert_eq!(e.rows(), 2);
}

#[test]
fn s4_one_eviction_per_newcomer() {
    let mut cfg = Config::default(); cfg.cap_per_addr = 2; cfg.cap_per_host = 2;
    let mut e = Engine::new(cfg, &SEED);
    let mut d1 = Desk::new(a(1, 5000), 1 << 32); let mut d2 = Desk::new(a(1, 5000), 1 << 32);
    assert!(join(&mut e, &mut d1, 0)); assert!(join(&mut e, &mut d2, 0));
    let mut d3 = Desk::new(a(1, 5000), 1 << 32);
    assert!(join(&mut e, &mut d3, 1_000));
    assert_eq!(e.n.evicted, 1);
    assert_eq!(e.rows(), 2);
}

#[test]
fn s6_hs_from_other_family_replaces_row_with_new_carrier() {
    let mut e = engine();
    let mut d = Desk::new(a(1, 5000), 1 << 32);
    assert!(join(&mut e, &mut d, 0));
    send(&mut e, d.addr, &d.beat(false, None), 1_000);
    d.addr = v6(7, 5000);
    assert!(join(&mut e, &mut d, 2_000));
    send(&mut e, d.addr, &d.beat(false, None), 5_000);
    assert_eq!(e.where_is(&d.pub_, 6_000), vec![v6(7, 5000)]);
    assert_eq!(e.rows(), 1);
}

#[test]
fn s7_dead_unauthed_row_is_not_listed_before_the_sweep() {
    let mut e = engine();
    let mut d = Desk::new(a(1, 5000), 1 << 32);
    assert!(join(&mut e, &mut d, 0));
    assert!(e.where_is(&d.pub_, 100_000).is_empty());
    assert!(e.punch(&d.pub_, a(9, 9000), 100_000).is_empty());
}

#[test]
fn s8_foreign_beat_cannot_extend_life() {
    let mut e = engine();
    let mut d = Desk::new(a(1, 5000), 1 << 32);
    assert!(join(&mut e, &mut d, 0));
    send(&mut e, d.addr, &d.beat(false, None), 1_000);
    for t in (10_000..400_000).step_by(10_000) { send(&mut e, a(66, 6000), &d.beat(false, None), t); }
    e.sweep(400_000);
    assert_eq!(e.rows(), 0, "copies from another address never refreshed the row");
}

#[test]
fn punch_to_unanswerable_target_is_refused() {
    let mut e = engine();
    let mut d = Desk::new(a(1, 5000), 1 << 32);
    assert!(join(&mut e, &mut d, 0));
    send(&mut e, d.addr, &d.beat(false, None), 1_000);
    assert!(e.punch(&d.pub_, Addr::v4([0, 0, 0, 0], 9000), 2_000).is_empty());
    assert!(e.punch(&d.pub_, a(9, 80), 2_000).is_empty());
}

#[test]
fn one_full_pass_removes_every_dead_row() {
    // remove() moves the LAST id into the hole; the sweep must look at that slot again, not skip it.
    // First 10 rows alive, last 10 dead: a skipping sweep would wrap round and miss half the dead.
    let mut e = engine();
    let mut ds: Vec<Desk> = (0..20).map(|i| Desk::new(a(i + 1, 5000), 1 << 32)).collect();
    for d in ds.iter_mut() { assert!(join(&mut e, d, 0)); }
    for d in ds.iter_mut().take(10) { send(&mut e, d.addr, &d.beat(false, None), 100_000); }
    e.sweep(1);       // starts the pace clock (looks at one row)
    let before = e.n.expired;
    e.sweep(121_000); // dt ≥ one pass → budget = every row once; the unauthed ten are dead (born 0, life 90″)
    assert_eq!(e.n.expired - before, 10);
    assert_eq!(e.rows(), 10);
}

#[test]
fn t19_desk_rejects_forged_move_ack_and_punch() {
    let mut e = engine();
    let mut d = Desk::new(a(1, 5000), 1 << 32);
    assert!(join(&mut e, &mut d, 0));
    let b = d.beat(true, None); let sent = d.ctr;
    let ack = send(&mut e, d.addr, &b, 3_000).unwrap();
    assert!(d.ack_ok(&ack, &[sent]));
    assert!(!d.ack_ok(&ack, &[sent + 7]), "a ctr_echo we did not send");
    let mut f = ack.clone(); f[20] ^= 1; assert!(!d.ack_ok(&f, &[sent]));
    let mv = send(&mut e, a(1, 6000), &d.beat(false, None), 4_000).unwrap();
    assert!(d.move_nonce(&mv).is_some());
    let mut f = mv.clone(); f[30] ^= 1; assert!(d.move_nonce(&f).is_none());
    let p = e.punch(&d.pub_, a(200, 9000), 5_000);
    assert_eq!(d.punch_ok(&p[0].1, 0).map(|x| x.0), Some(1));
    assert!(d.punch_ok(&p[0].1, 1).is_none(), "replayed punch");
    let mut f = p[0].1; f[40] ^= 1; assert!(d.punch_ok(&f, 0).is_none());
}

#[test]
fn probe_canary_round_trip_and_life() {
    let mut e = engine();
    let mut d = Desk::new(a(1, 5000), 1 << 32);
    assert!(join(&mut e, &mut d, 0));
    send(&mut e, d.addr, &d.beat(false, None), 1_000);
    let p = d.probe(120, 90);
    assert!(send(&mut e, d.addr, &p, 2_000).is_none(), "no immediate answer");
    let pc = d.ctr;
    assert!(e.due_canaries(2_000 + 119_999).is_empty());
    // silent for 120″: the row stays alive past its old life (2·60+20 = 140″ from the probe is fine, but check the sweep)
    e.sweep(1); e.sweep(2_000 + 121_000);
    assert_eq!(e.rows(), 1);
    let c = e.due_canaries(2_000 + 120_000);
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].0, d.addr);
    assert!(d.canary_ok(&c[0].1, pc));
    assert!(!d.canary_ok(&c[0].1, pc + 1));
    assert!(e.due_canaries(10_000_000).is_empty(), "one canary per probe");
}

#[test]
fn probe_from_another_address_or_forged_does_nothing() {
    let mut e = engine();
    let mut d = Desk::new(a(1, 5000), 1 << 32);
    assert!(join(&mut e, &mut d, 0));
    send(&mut e, d.addr, &d.beat(false, None), 1_000);
    let p = d.probe(60, 60);
    assert!(send(&mut e, a(66, 7000), &p, 2_000).is_none());
    let mut f = d.probe(60, 60); f[30] ^= 1;
    assert!(send(&mut e, d.addr, &f, 2_000).is_none());
    assert!(e.due_canaries(1_000_000).is_empty(), "no canary to a third party, none for a forged probe");
    assert_eq!(e.n.probes, 0);
}

#[test]
fn moved_desktop_gets_no_stale_canary() {
    let mut e = engine();
    let mut d = Desk::new(a(1, 5000), 1 << 32);
    assert!(join(&mut e, &mut d, 0));
    send(&mut e, d.addr, &d.beat(false, None), 1_000);
    send(&mut e, d.addr, &d.probe(60, 60), 2_000);
    assert!(join(&mut e, &mut d, 3_000)); // re-joined: a new row, the old probe is void
    assert!(e.due_canaries(1_000_000).is_empty());
}

#[test]
fn handshake_signed_for_another_server_is_refused() {
    // Fable DNS #2: a relay at R hands the desktop R's cookie; the desktop signs dst=R; findd at S refuses it
    let s_addr = Addr::v4([203, 0, 113, 1], 8753);
    let mut cfg = Config::default(); cfg.public_addrs = vec![s_addr];
    let mut e = Engine::new(cfg, &SEED);
    let mut d = Desk::new(a(1, 5000), 1 << 32);
    let c = send(&mut e, d.addr, &Desk::hello(), 0).unwrap();
    let (hs, _, _) = d.hs_with(&c[1..17], 60, false, Addr::v4([198, 51, 100, 7], 8753));
    assert!(send(&mut e, d.addr, &hs, 0).is_none());
    assert_eq!(e.n.dst_bad, 1);
    let (hs, eph, xpub) = d.hs_with(&c[1..17], 60, false, s_addr);
    let ok = send(&mut e, d.addr, &hs, 0).expect("signed for us");
    assert!(d.accept(&ok, eph, xpub, &server_pub()));
}

#[test]
fn a_pending_probe_is_not_overwritten() {
    let mut e = engine();
    let mut d = Desk::new(a(1, 5000), 1 << 32);
    assert!(join(&mut e, &mut d, 0));
    send(&mut e, d.addr, &d.beat(false, None), 1_000);
    send(&mut e, d.addr, &d.probe(60, 60), 2_000);
    for i in 0..50 { send(&mut e, d.addr, &d.probe(60, 60), 3_000 + i); }
    assert_eq!(e.n.probes, 1, "one pending probe per row");
    assert_eq!(e.canaries.len(), 1, "nothing piles up in the queue");
}

// ── A10 B1 (19/11/2026): the HELLO with a nonce, and old and new desktops side by side ──
#[test]
fn a10_b1_a_nonce_hello_gets_its_nonce_back_and_the_same_cookie() {
    let mut e = engine();
    let d = Desk::new(a(1, 5000), 1 << 32);
    let old = send(&mut e, d.addr, &Desk::hello(), 1_000).expect("an old desktop's HELLO still gets a cookie");
    assert_eq!(old.len(), wire::COOKIE_LEN, "and in the old form: an old desktop reads exactly 17 bytes");
    let nonce = [7u8, 1, 2, 3, 4, 5, 6, 9];
    let new = send(&mut e, d.addr, &Desk::hello_n(&nonce), 1_000).expect("a new desktop's HELLO gets a cookie");
    assert_eq!(new.len(), wire::COOKIE_N_LEN);
    assert_eq!(new[0], wire::COOKIE);
    assert_eq!(&new[17..25], &nonce, "the nonce comes back");
    assert_eq!(&new[1..17], &old[1..17], "the cookie itself is the same one");
}

#[test]
fn a10_b1_the_echoed_cookie_admits_the_handshake_like_the_old_one() {
    let mut e = engine();
    let mut d = Desk::new(a(1, 5000), 1 << 32);
    let c = send(&mut e, d.addr, &Desk::hello_n(&[1u8; 8]), 2_000).expect("cookie");
    let (hs, eph, xpub) = d.hs(&c[1..17]);
    let ok = send(&mut e, d.addr, &hs, 2_000).expect("hsok");
    assert!(d.accept(&ok, eph, xpub, &server_pub()));
    // and an old desktop beside it still joins the old way
    let mut old = Desk::new(a(2, 5000), 1 << 32);
    assert!(join(&mut e, &mut old, 2_000));
}

#[test]
fn a10_b1_other_hello_lengths_stay_unanswered() {
    let mut e = engine();
    let mut b = vec![0u8; wire::HELLO_N_LEN + 1];
    b[0] = wire::HELLO;
    assert!(send(&mut e, a(1, 5000), &b, 0).is_none());
    assert!(send(&mut e, a(1, 5000), &b[..wire::HELLO_N_LEN - 1], 0).is_none());
    // the 19 bytes after the nonce must be zero
    let mut h = Desk::hello_n(&[5u8; 8]);
    h[wire::HELLO_N_LEN - 1] = 1;
    assert!(send(&mut e, a(1, 5000), &h, 0).is_none(), "a nonce HELLO whose padding is not zero is not answered");
}
