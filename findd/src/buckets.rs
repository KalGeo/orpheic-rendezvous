//! Fixed-size token buckets (§12.4, §13 Π1/Π5): a keyed hash picks one of N slots; two keys that
//! collide share a slot (only ever stricter). Memory is fixed whatever the traffic — no map grows.
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hash};

pub struct Buckets {
    slots: Vec<(f32, u64)>, // (tokens, last refill ms)
    rate_per_ms: f32,
    burst: f32,
    hasher: RandomState,
}

impl Buckets {
    pub fn new(slots: usize, rate_per_s: f32, burst: f32) -> Buckets {
        Buckets { slots: vec![(burst, 0); slots.max(1)], rate_per_ms: rate_per_s / 1000.0, burst, hasher: RandomState::new() }
    }
    /// Spend one token for `key` at `now_ms`; false = over budget.
    pub fn allow<K: Hash>(&mut self, key: K, now_ms: u64) -> bool {
        let i = (self.hasher.hash_one(key) as usize) % self.slots.len();
        let (tok, last) = &mut self.slots[i];
        *tok = (*tok + (now_ms.saturating_sub(*last)) as f32 * self.rate_per_ms).min(self.burst);
        *last = now_ms;
        if *tok >= 1.0 { *tok -= 1.0; true } else { false }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn spends_and_refills() {
        let mut b = Buckets::new(16, 1.0, 2.0);
        assert!(b.allow(1u32, 0));
        assert!(b.allow(1u32, 0));
        assert!(!b.allow(1u32, 0));
        assert!(b.allow(1u32, 1000));
        assert!(!b.allow(1u32, 1000));
    }
}
