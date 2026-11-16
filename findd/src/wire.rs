//! Packet layouts of findability.md §13 Π7. All integers big-endian. Pure: no I/O, no crypto.
//! Server-side view: `parse` reads what desktops send; `put_*` writes what the server sends.

pub const HELLO: u8 = 0x10;
pub const HS: u8 = 0x11;
pub const COOKIE: u8 = 0x12;
pub const ACK: u8 = 0x13;
pub const HSOK: u8 = 0x14;
pub const BEAT: u8 = 0x15;
pub const MOVE: u8 = 0x16;
pub const UNKNOWN: u8 = 0x17;
pub const PUNCH: u8 = 0x18;
/// Router learning (findability.md §13.4): «send me a canary in T seconds» / the canary itself.
pub const PROBE: u8 = 0x19;
pub const CANARY: u8 = 0x1A;

pub const HELLO_LEN: usize = 20;
pub const COOKIE_LEN: usize = 17;
/// 0x11: … flags(1) | dst addr16+port(18) | sig(64). `dst` = the address the desktop SENT this to, inside the signature:
/// a DNS-spoofed relay at another address cannot pass the desktop's handshake on to findd (Fable, DNS audit 5/11 #2).
pub const HS_LEN: usize = 182;
pub const HS_SIGNED: usize = 118; // bytes[0..118] are signed; [118..182] = signature
pub const HSOK_LEN: usize = 129;
pub const BEAT_LEN: usize = 34;
pub const BEAT_ECHO_LEN: usize = 42;
/// §13 Π7 had ACK = 38 with uptime_s; dropped to 34 so that an ACK is never larger than the
/// shortest beat that asks for it (reply ≤ request, everywhere). A restart shows as 0x17.
pub const ACK_LEN: usize = 34;
pub const MOVE_LEN: usize = 33;
pub const UNKNOWN_LEN: usize = 9;
pub const PUNCH_LEN: usize = 51;
pub const PROBE_LEN: usize = 37;   // 0x19 | rowid 8 | ctr 8 | wait_s 2 | interval_s 2 | mac 16
pub const CANARY_LEN: usize = 33;  // 0x1A | rowid 8 | ctr_echo 8 | mac 16  (≤ PROBE_LEN)
pub const PROBE_MIN_S: u16 = 20;
pub const PROBE_MAX_S: u16 = 300;

/// Domain-separation prefixes for signatures (§12.1, §13 Π3).
pub const CTX_HS: &[u8] = b"orpheic-hb-v1";
pub const CTX_HSOK: &[u8] = b"orpheic-hb-v1/s";

pub const FLAG_WANT_REPLY: u8 = 1;
pub const FLAG_ECHO: u8 = 2;
/// Handshake flag: the desktop's door is open and verified — beats every 10′ (§11.15).
pub const HSFLAG_DOOR_OPEN: u8 = 1;

pub struct Hs<'a> {
    pub cookie: &'a [u8],       // 16
    pub pub_: [u8; 32],
    pub boot: u64,
    pub ctr: u64,
    pub xpub: &'a [u8],         // 32
    pub interval_s: u16,
    pub flags: u8,
    pub dst_ip: [u8; 16],
    pub dst_port: u16,
    pub signed: &'a [u8],       // bytes[0..118]
    pub sig: &'a [u8],          // 64
}

pub struct Beat<'a> {
    pub rowid: u64,
    pub ctr: u64,
    pub flags: u8,
    pub echo: Option<u64>,
    pub maced: &'a [u8],        // everything before the mac
    pub mac: &'a [u8],          // 16
}

pub struct Probe<'a> {
    pub rowid: u64,
    pub ctr: u64,
    pub wait_s: u16,
    pub interval_s: u16,
    pub maced: &'a [u8],
    pub mac: &'a [u8],
}

pub enum Packet<'a> {
    Hello,
    Hs(Hs<'a>),
    Beat(Beat<'a>),
    Probe(Probe<'a>),
}

fn u64_at(d: &[u8], i: usize) -> u64 { u64::from_be_bytes(d[i..i + 8].try_into().unwrap()) }

/// Exact lengths only: anything else is dropped by the caller without a reply.
pub fn parse(d: &[u8]) -> Option<Packet<'_>> {
    match (d.first()?, d.len()) {
        (&HELLO, HELLO_LEN) => Some(Packet::Hello),
        (&HS, HS_LEN) => Some(Packet::Hs(Hs {
            cookie: &d[1..17],
            pub_: d[17..49].try_into().unwrap(),
            boot: u64_at(d, 49),
            ctr: u64_at(d, 57),
            xpub: &d[65..97],
            interval_s: u16::from_be_bytes([d[97], d[98]]),
            flags: d[99],
            dst_ip: d[100..116].try_into().unwrap(),
            dst_port: u16::from_be_bytes([d[116], d[117]]),
            signed: &d[..HS_SIGNED],
            sig: &d[HS_SIGNED..HS_LEN],
        })),
        (&BEAT, BEAT_LEN) if d[17] & FLAG_ECHO == 0 => Some(Packet::Beat(Beat {
            rowid: u64_at(d, 1), ctr: u64_at(d, 9), flags: d[17], echo: None, maced: &d[..18], mac: &d[18..34],
        })),
        (&BEAT, BEAT_ECHO_LEN) if d[17] & FLAG_ECHO != 0 => Some(Packet::Beat(Beat {
            rowid: u64_at(d, 1), ctr: u64_at(d, 9), flags: d[17], echo: Some(u64_at(d, 18)), maced: &d[..26], mac: &d[26..42],
        })),
        (&PROBE, PROBE_LEN) => Some(Packet::Probe(Probe {
            rowid: u64_at(d, 1), ctr: u64_at(d, 9), wait_s: u16::from_be_bytes([d[17], d[18]]),
            interval_s: u16::from_be_bytes([d[19], d[20]]), maced: &d[..21], mac: &d[21..37],
        })),
        _ => None,
    }
}

pub fn put_cookie(o: &mut [u8], cookie: &[u8; 16]) -> usize {
    o[0] = COOKIE; o[1..17].copy_from_slice(cookie); COOKIE_LEN
}
/// Writes bytes[0..49] of an HSOK (type, rowid, xpub_s, ctr_echo); the caller adds confirm + sig.
pub fn put_hsok_head(o: &mut [u8], rowid: u64, xpub_s: &[u8], ctr_echo: u64) {
    o[0] = HSOK; o[1..9].copy_from_slice(&rowid.to_be_bytes()); o[9..41].copy_from_slice(xpub_s);
    o[41..49].copy_from_slice(&ctr_echo.to_be_bytes());
}
/// ACK head bytes[0..18]; the caller writes the mac at [18..34].
pub fn put_ack_head(o: &mut [u8], rowid: u64, ctr_echo: u64, what: u8) {
    o[0] = ACK; o[1..9].copy_from_slice(&rowid.to_be_bytes()); o[9..17].copy_from_slice(&ctr_echo.to_be_bytes()); o[17] = what;
}
/// MOVE head bytes[0..17]; mac at [17..33].
pub fn put_move_head(o: &mut [u8], rowid: u64, nonce: u64) {
    o[0] = MOVE; o[1..9].copy_from_slice(&rowid.to_be_bytes()); o[9..17].copy_from_slice(&nonce.to_be_bytes());
}
/// CANARY head bytes[0..17]; mac at [17..33].
pub fn put_canary_head(o: &mut [u8], rowid: u64, ctr_echo: u64) {
    o[0] = CANARY; o[1..9].copy_from_slice(&rowid.to_be_bytes()); o[9..17].copy_from_slice(&ctr_echo.to_be_bytes());
}
pub fn put_unknown(o: &mut [u8], rowid: u64) -> usize {
    o[0] = UNKNOWN; o[1..9].copy_from_slice(&rowid.to_be_bytes()); UNKNOWN_LEN
}
/// PUNCH head bytes[0..35]; mac at [35..51].
pub fn put_punch_head(o: &mut [u8], rowid: u64, ctr_s: u64, ip16: &[u8; 16], port: u16) {
    o[0] = PUNCH; o[1..9].copy_from_slice(&rowid.to_be_bytes()); o[9..17].copy_from_slice(&ctr_s.to_be_bytes());
    o[17..33].copy_from_slice(ip16); o[33..35].copy_from_slice(&port.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replies_never_larger_than_their_trigger() {
        assert!(COOKIE_LEN <= HELLO_LEN);
        assert!(HSOK_LEN <= HS_LEN);
        assert!(ACK_LEN <= BEAT_LEN);
        assert!(MOVE_LEN <= BEAT_LEN);
        assert!(UNKNOWN_LEN <= BEAT_LEN);
        assert!(CANARY_LEN <= PROBE_LEN);
    }
    #[test]
    fn exact_lengths_only() {
        let mut b = [0u8; 64];
        b[0] = HELLO;
        assert!(parse(&b[..HELLO_LEN]).is_some());
        assert!(parse(&b[..HELLO_LEN + 1]).is_none());
        b[0] = BEAT;
        assert!(parse(&b[..BEAT_LEN]).is_some());
        b[17] = FLAG_ECHO; // echo flag on a short beat: wrong
        assert!(parse(&b[..BEAT_LEN]).is_none());
        assert!(parse(&b[..BEAT_ECHO_LEN]).is_some());
        b[17] = 0;
        assert!(parse(&b[..BEAT_ECHO_LEN]).is_none());
        assert!(parse(&[]).is_none());
        b[0] = 0x40; // QUIC fixed bit — never ours
        assert!(parse(&b[..BEAT_LEN]).is_none());
    }
}
