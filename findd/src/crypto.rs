//! MACs, key derivation, cookies and nonces (findability.md §12.1, §13 Π2/Π3/Π7).
use ring::{agreement, hkdf, hmac, rand::SystemRandom};

/// HMAC-SHA256 truncated to 16 bytes over the concatenation of `parts`.
pub fn mac16(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 16] {
    mac16_with(&hmac::Key::new(hmac::HMAC_SHA256, key), parts)
}
/// Same, with a prepared key (the server's own K_s is prepared once, C4).
pub fn mac16_with(k: &hmac::Key, parts: &[&[u8]]) -> [u8; 16] {
    let mut c = hmac::Context::with_key(k);
    for p in parts { c.update(p); }
    let t = c.sign();
    let mut o = [0u8; 16]; o.copy_from_slice(&t.as_ref()[..16]); o
}

/// Constant-time equality of two MACs/cookies.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut x = 0u8;
    for (p, q) in a.iter().zip(b) { x |= p ^ q; }
    // black_box keeps the optimiser from turning the fold into an early exit
    std::hint::black_box(x) == 0
}

pub struct SessionKeys { pub mac: [u8; 32], pub conf: [u8; 32] }

struct Len32;
impl hkdf::KeyType for Len32 { fn len(&self) -> usize { 32 } }

/// HKDF-SHA256(salt = "orpheic-hb-v1", ikm = X25519 shared) with info = label|pub|xpub|xpub_s|boot.
pub fn derive(shared: &[u8], pub_: &[u8], xpub: &[u8], xpub_s: &[u8], boot: u64) -> SessionKeys {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, crate::wire::CTX_HS).extract(shared);
    let bt = boot.to_be_bytes();
    let one = |label: &[u8]| {
        let info = [label, pub_, xpub, xpub_s, &bt];
        let mut o = [0u8; 32];
        prk.expand(&info, Len32).unwrap().fill(&mut o).unwrap();
        o
    };
    SessionKeys { mac: one(b"mac"), conf: one(b"conf") }
}

/// Server side of the X25519 exchange: fresh ephemeral key per handshake. None if the peer's
/// public value is invalid (all-zero shared secret etc. — ring rejects it).
pub fn server_agree(rng: &SystemRandom, xpub: &[u8], pub_: &[u8], boot: u64) -> Option<([u8; 32], SessionKeys)> {
    let eph = agreement::EphemeralPrivateKey::generate(&agreement::X25519, rng).ok()?;
    let xs = eph.compute_public_key().ok()?;
    let mut xpub_s = [0u8; 32]; xpub_s.copy_from_slice(xs.as_ref());
    let keys = agreement::agree_ephemeral(eph, &agreement::UnparsedPublicKey::new(&agreement::X25519, xpub),
        |sh| derive(sh, pub_, xpub, &xpub_s, boot)).ok()?;
    Some((xpub_s, keys))
}

/// Stateless cookie bound to the source (§13 Π7): HMAC(K_s, "ck"|addr16|port|t)[..16].
/// A well-known public technique, the same idea as TCP SYN cookies, the DTLS HelloVerifyRequest,
/// the IKEv2 cookie, the WireGuard cookie reply and the QUIC Retry token.
pub fn cookie(ks: &hmac::Key, ip16: &[u8; 16], port: u16, t: u64) -> [u8; 16] {
    mac16_with(ks, &[b"ck", ip16, &port.to_be_bytes(), &(t as u32).to_be_bytes()])
}
/// Stateless move nonce bound to rowid + the NEW address (§13 Π2): HMAC(K_s, "mv"|rowid|addr16|port|t)[..8].
pub fn move_nonce(ks: &hmac::Key, rowid: u64, ip16: &[u8; 16], port: u16, t: u64) -> u64 {
    let m = mac16_with(ks, &[b"mv", &rowid.to_be_bytes(), ip16, &port.to_be_bytes(), &(t as u32).to_be_bytes()]);
    u64::from_be_bytes(m[..8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ct_eq_works() {
        assert!(ct_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!ct_eq(&[1, 2, 3], &[1, 2, 4]));
        assert!(!ct_eq(&[1, 2], &[1, 2, 3]));
    }
    #[test]
    fn cookie_binds_address_and_time() {
        let k = hmac::Key::new(hmac::HMAC_SHA256, &[7u8; 32]); let a = [1u8; 16]; let mut b = a; b[15] = 2;
        assert_eq!(cookie(&k, &a, 5000, 9), cookie(&k, &a, 5000, 9));
        assert_ne!(cookie(&k, &a, 5000, 9), cookie(&k, &b, 5000, 9));
        assert_ne!(cookie(&k, &a, 5000, 9), cookie(&k, &a, 5001, 9));
        assert_ne!(cookie(&k, &a, 5000, 9), cookie(&k, &a, 5000, 10));
    }
    #[test]
    fn labels_give_distinct_keys() {
        let s = derive(&[3u8; 32], &[1u8; 32], &[2u8; 32], &[4u8; 32], 77);
        assert_ne!(s.mac, s.conf);
    }
}

/// Control-socket key parsing (moved from main.rs, T6): exactly 64 ASCII hex digits, nothing else
/// (no `+`, no multi-byte UTF-8 that would make byte slicing panic).
pub fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) { return None; }
    let b = s.as_bytes();
    let v = |c: u8| (c as char).to_digit(16).unwrap() as u8;
    let mut o = [0u8; 32];
    for i in 0..32 { o[i] = v(b[2 * i]) << 4 | v(b[2 * i + 1]); }
    Some(o)
}

#[cfg(test)]
mod hex_tests {
    #[test]
    fn hex32_is_strict() { // T6
        assert!(super::hex32(&"ab".repeat(32)).is_some());
        assert!(super::hex32(&"AB".repeat(32)).is_some());
        assert!(super::hex32(&"é".repeat(32)).is_none());
        assert!(super::hex32(&"+f".repeat(32)).is_none());
        assert!(super::hex32(&"a".repeat(63)).is_none());
        assert!(super::hex32(&"a".repeat(65)).is_none());
    }
}
