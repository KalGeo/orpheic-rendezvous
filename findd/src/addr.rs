//! Addresses: every source as 16 bytes (IPv4 mapped into ::ffff:0:0/96) + port, and the
//! fairness keys of §13 Π1 (IPv4: host and /24 · IPv6: /64 and /48).

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Addr { pub ip: [u8; 16], pub port: u16 }

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fam { V4 = 0, V6 = 1 }

impl Addr {
    pub fn v4(o: [u8; 4], port: u16) -> Addr {
        let mut ip = [0u8; 16]; ip[10] = 0xff; ip[11] = 0xff; ip[12..].copy_from_slice(&o); Addr { ip, port }
    }
    pub fn fam(&self) -> Fam {
        if self.ip[..10] == [0u8; 10] && self.ip[10] == 0xff && self.ip[11] == 0xff { Fam::V4 } else { Fam::V6 }
    }
    /// The small fairness key: the IPv4 host, or the IPv6 /64.
    pub fn host_key(&self) -> u128 {
        match self.fam() {
            Fam::V4 => u128::from_be_bytes(self.ip),
            Fam::V6 => { let mut k = self.ip; k[8..].fill(0); u128::from_be_bytes(k) }
        }
    }
    /// The large fairness key: the IPv4 /24, or the IPv6 /48.
    /// Tagged so that it can never equal a host key, even in one shared table (S N4): an IPv4 /24 carries
    /// 0xEE in byte 8 (a mapped host has 0 there); an IPv6 /48 carries 1 in byte 15 (a /64 host key has 0).
    pub fn net_key(&self) -> u128 {
        let mut k = self.ip;
        match self.fam() { Fam::V4 => { k[15] = 0; k[8] = 0xEE; } Fam::V6 => { k[6..].fill(0); k[15] = 1; } }
        u128::from_be_bytes(k)
    }
    /// Addresses we never answer (§12.4): privileged source ports, unspecified, multicast,
    /// IPv4 broadcast / "this network". Loopback is allowed (tests; the kernel drops spoofed ones).
    pub fn unanswerable(&self) -> bool {
        if self.port < 1024 { return true; }
        match self.fam() {
            Fam::V4 => { let o = &self.ip[12..]; o[0] == 0 || o[0] >= 224 }
            Fam::V6 => self.ip == [0u8; 16] || self.ip[0] == 0xff,
        }
    }
    pub fn to_sockaddr(&self) -> std::net::SocketAddr {
        std::net::SocketAddr::new(std::net::Ipv6Addr::from(self.ip).to_canonical(), self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn keys_and_families() {
        let a = Addr::v4([10, 1, 2, 3], 4000);
        let b = Addr::v4([10, 1, 2, 9], 4000);
        assert_eq!(a.fam(), Fam::V4);
        assert_ne!(a.host_key(), b.host_key());
        assert_eq!(a.net_key(), b.net_key());
        assert!(Addr::v4([10, 1, 2, 3], 53).unanswerable());
        assert!(Addr::v4([239, 1, 2, 3], 5000).unanswerable());
        assert!(!a.unanswerable());
        let mut v6 = [0u8; 16]; v6[0] = 0x2a; v6[15] = 1;
        let c = Addr { ip: v6, port: 5000 };
        assert_eq!(c.fam(), Fam::V6);
        let mut v6b = v6; v6b[15] = 2; v6b[7] = 9; // same /48, other /64
        let d = Addr { ip: v6b, port: 5000 };
        assert_ne!(c.host_key(), d.host_key());
        assert_eq!(c.net_key(), d.net_key());
        assert_ne!(c.net_key(), c.host_key());
    }
    #[test]
    fn net_key_never_equals_a_host_key() { // S6'
        for last in 0..=255u8 {
            let a = Addr::v4([10, 1, 2, last], 5000);
            for b in 0..=255u8 { assert_ne!(a.net_key(), Addr::v4([10, 1, 2, b], 5000).host_key()); }
        }
    }
}
