//! A reference desktop for the protocol (findability.md §13) — used by the engine tests and by
//! the load tool. The C++ desktop must produce the same bytes.
use crate::{addr::Addr, crypto::{self, SessionKeys}, wire};
use ring::{agreement, rand::SystemRandom, signature::{self, Ed25519KeyPair, KeyPair}};

pub struct Desk {
    pub kp: Ed25519KeyPair,
    pub pub_: [u8; 32],
    pub boot: u64,
    pub ctr: u64,
    pub rowid: u64,
    pub keys: Option<SessionKeys>,
    pub addr: Addr,
}

impl Desk {
    pub fn new(addr: Addr, boot: u64) -> Desk {
        let rng = SystemRandom::new();
        let doc = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap();
        let mut pub_ = [0u8; 32]; pub_.copy_from_slice(kp.public_key().as_ref());
        Desk { kp, pub_, boot, ctr: 0, rowid: 0, keys: None, addr }
    }
    /// The desktop's real identity: its 32-byte Ed25519 seed.
    pub fn new_from_seed(seed: &[u8; 32], addr: Addr, boot: u64) -> Desk {
        let kp = Ed25519KeyPair::from_seed_unchecked(seed).expect("seed");
        let mut pub_ = [0u8; 32]; pub_.copy_from_slice(kp.public_key().as_ref());
        Desk { kp, pub_, boot, ctr: 0, rowid: 0, keys: None, addr }
    }
    pub fn hello() -> Vec<u8> { let mut v = vec![0u8; wire::HELLO_LEN]; v[0] = wire::HELLO; v }
    /// A10 B1: a HELLO whose COOKIE answer must echo `nonce` (wire::HELLO_N_LEN).
    pub fn hello_n(nonce: &[u8; 8]) -> Vec<u8> {
        let mut v = vec![0u8; wire::HELLO_N_LEN]; v[0] = wire::HELLO; v[1..9].copy_from_slice(nonce); v
    }

    /// Build an HS; returns (packet, ephemeral key, xpub) so the test can finish the exchange.
    pub fn hs(&mut self, cookie: &[u8]) -> (Vec<u8>, agreement::EphemeralPrivateKey, [u8; 32]) {
        self.hs_with(cookie, 60, false, Addr::v4([0, 0, 0, 0], 0))
    }
    /// A handshake with the desktop's declared interval and «door open» flag.
    /// `dst` = the server address this handshake is SENT to (signed; findd checks it is one of its own).
    pub fn hs_with(&mut self, cookie: &[u8], interval_s: u16, door_open: bool, dst: Addr) -> (Vec<u8>, agreement::EphemeralPrivateKey, [u8; 32]) {
        let rng = SystemRandom::new();
        let eph = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).unwrap();
        let mut xpub = [0u8; 32]; xpub.copy_from_slice(eph.compute_public_key().unwrap().as_ref());
        self.ctr += 1;
        let mut p = vec![0u8; wire::HS_LEN];
        p[0] = wire::HS; p[1..17].copy_from_slice(cookie); p[17..49].copy_from_slice(&self.pub_);
        p[49..57].copy_from_slice(&self.boot.to_be_bytes()); p[57..65].copy_from_slice(&self.ctr.to_be_bytes());
        p[65..97].copy_from_slice(&xpub); p[97..99].copy_from_slice(&interval_s.to_be_bytes()); p[99] = if door_open { wire::HSFLAG_DOOR_OPEN } else { 0 };
        p[100..116].copy_from_slice(&dst.ip); p[116..118].copy_from_slice(&dst.port.to_be_bytes());
        let mut m = wire::CTX_HS.to_vec(); m.extend_from_slice(&p[..wire::HS_SIGNED]);
        let sg = self.kp.sign(&m); p[wire::HS_SIGNED..wire::HS_LEN].copy_from_slice(sg.as_ref());
        (p, eph, xpub)
    }

    /// Accept an HSOK exactly as §13 Π3 says: ctr_echo, confirm, server signature.
    /// Is this 0x14 signed by one of the server keys, for OUR pub and xpub? Checked BEFORE the ephemeral
    /// key is consumed, so a forged 0x14 cannot burn the real handshake (F MED-2a).
    pub fn hsok_sig_ok(&self, hsok: &[u8], xpub: &[u8; 32], keys: &[[u8; 32]]) -> bool {
        if hsok.len() != wire::HSOK_LEN || hsok[0] != wire::HSOK { return false; }
        let mut sm = wire::CTX_HSOK.to_vec(); sm.extend_from_slice(&hsok[..65]); sm.extend_from_slice(&self.pub_); sm.extend_from_slice(xpub);
        keys.iter().any(|k| signature::UnparsedPublicKey::new(&signature::ED25519, &k[..]).verify(&sm, &hsok[65..129]).is_ok())
    }
    /// Accept against any of the server keys embedded in Orpheic (the current one and the next, §11.1).
    pub fn accept_keys(&mut self, hsok: &[u8], eph: agreement::EphemeralPrivateKey, xpub: [u8; 32], keys: &[[u8; 32]]) -> bool {
        if hsok.len() != wire::HSOK_LEN { return false; }
        let mut sm = wire::CTX_HSOK.to_vec(); sm.extend_from_slice(&hsok[..65]); sm.extend_from_slice(&self.pub_); sm.extend_from_slice(&xpub);
        match keys.iter().find(|k| signature::UnparsedPublicKey::new(&signature::ED25519, &k[..]).verify(&sm, &hsok[65..129]).is_ok()) {
            Some(k) => { let k = *k; self.accept(hsok, eph, xpub, &k) }
            None => false,
        }
    }
    pub fn accept(&mut self, hsok: &[u8], eph: agreement::EphemeralPrivateKey, xpub: [u8; 32], server_pub: &[u8]) -> bool {
        if hsok.len() != wire::HSOK_LEN || hsok[0] != wire::HSOK { return false; }
        let ctr_echo = u64::from_be_bytes(hsok[41..49].try_into().unwrap());
        if ctr_echo != self.ctr { return false; }
        let mut sm = wire::CTX_HSOK.to_vec(); sm.extend_from_slice(&hsok[..65]); sm.extend_from_slice(&self.pub_); sm.extend_from_slice(&xpub);
        if signature::UnparsedPublicKey::new(&signature::ED25519, &server_pub).verify(&sm, &hsok[65..129]).is_err() { return false; }
        let xs = hsok[9..41].to_vec(); let (pb, bt) = (self.pub_, self.boot);
        // A10 B3: a key the agreement refuses (all zeros, a small-order point) is a refused answer, not a panic.
        let Ok(keys) = agreement::agree_ephemeral(eph, &agreement::UnparsedPublicKey::new(&agreement::X25519, &xs),
            |sh| crypto::derive(sh, &pb, &xpub, &xs, bt)) else { return false };
        let rowid = u64::from_be_bytes(hsok[1..9].try_into().unwrap());
        let conf = crypto::mac16(&keys.conf, &[b"c", &[wire::HSOK], &rowid.to_be_bytes(), &ctr_echo.to_be_bytes()]);
        if !crypto::ct_eq(&conf, &hsok[49..65]) { return false; }
        self.rowid = rowid; self.keys = Some(keys); true
    }

    pub fn beat(&mut self, want: bool, echo: Option<u64>) -> Vec<u8> {
        self.ctr += 1;
        let flags = (want as u8) | if echo.is_some() { wire::FLAG_ECHO } else { 0 };
        let mut p = vec![0u8; if echo.is_some() { wire::BEAT_ECHO_LEN } else { wire::BEAT_LEN }];
        p[0] = wire::BEAT; p[1..9].copy_from_slice(&self.rowid.to_be_bytes()); p[9..17].copy_from_slice(&self.ctr.to_be_bytes()); p[17] = flags;
        let n = if let Some(e) = echo { p[18..26].copy_from_slice(&e.to_be_bytes()); 26 } else { 18 };
        let m = crypto::mac16(&self.keys.as_ref().unwrap().mac, &[&p[..n]]);
        p[n..n + 16].copy_from_slice(&m);
        p
    }
    /// «Send me a canary in `wait_s` seconds; my interval is now `interval_s`» (§13.4).
    pub fn probe(&mut self, wait_s: u16, interval_s: u16) -> Vec<u8> {
        self.ctr += 1;
        let mut p = vec![0u8; wire::PROBE_LEN];
        p[0] = wire::PROBE; p[1..9].copy_from_slice(&self.rowid.to_be_bytes()); p[9..17].copy_from_slice(&self.ctr.to_be_bytes());
        p[17..19].copy_from_slice(&wait_s.to_be_bytes()); p[19..21].copy_from_slice(&interval_s.to_be_bytes());
        let m = crypto::mac16(&self.keys.as_ref().unwrap().mac, &[&p[..21]]);
        p[21..37].copy_from_slice(&m);
        p
    }
    pub fn mac_ok(&self, pkt: &[u8], body: usize) -> bool {
        crypto::ct_eq(&crypto::mac16(&self.keys.as_ref().unwrap().mac, &[&pkt[..body]]), &pkt[body..body + 16])
    }
}


/// What the desktop does with each server packet (§13.1, F MED-5): verify, or drop in silence.
impl Desk {
    fn ours(&self, p: &[u8], ty: u8, len: usize) -> bool {
        p.len() == len && p[0] == ty && self.keys.is_some() && u64::from_be_bytes(p[1..9].try_into().unwrap()) == self.rowid
    }
    /// 0x13: MAC, current rowid, and a ctr_echo we really sent (the caller passes the recent ones).
    pub fn ack_ok(&self, p: &[u8], recent: &[u64]) -> bool {
        self.ours(p, wire::ACK, wire::ACK_LEN) && self.mac_ok(p, 18)
            && recent.contains(&u64::from_be_bytes(p[9..17].try_into().unwrap()))
    }
    /// 0x16: MAC + current rowid → the nonce to echo.
    pub fn move_nonce(&self, p: &[u8]) -> Option<u64> {
        (self.ours(p, wire::MOVE, wire::MOVE_LEN) && self.mac_ok(p, 17)).then(|| u64::from_be_bytes(p[9..17].try_into().unwrap()))
    }
    /// 0x18: MAC + current rowid + ctr_s strictly above the last one accepted → (ctr_s, phone ip16, port).
    pub fn punch_ok(&self, p: &[u8], last: u64) -> Option<(u64, [u8; 16], u16)> {
        if !(self.ours(p, wire::PUNCH, wire::PUNCH_LEN) && self.mac_ok(p, 35)) { return None; }
        let c = u64::from_be_bytes(p[9..17].try_into().unwrap());
        (c > last).then(|| (c, p[17..33].try_into().unwrap(), u16::from_be_bytes([p[33], p[34]])))
    }
    /// 0x1A: MAC + current rowid + the ctr of OUR probe → true.
    pub fn canary_ok(&self, p: &[u8], probe_ctr: u64) -> bool {
        self.ours(p, wire::CANARY, wire::CANARY_LEN) && self.mac_ok(p, 17)
            && u64::from_be_bytes(p[9..17].try_into().unwrap()) == probe_ctr
    }
    /// 0x17 carries no MAC: only a hint (§13 Π5) — true if it names our rowid.
    pub fn unknown_names_us(&self, p: &[u8]) -> bool { self.ours(p, wire::UNKNOWN, wire::UNKNOWN_LEN) }
}
