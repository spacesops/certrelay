use crate::{AnchorSet, TrustId};
use libveritas::compute_trust_set;
use spaces_nums::RootAnchor;
use std::collections::HashMap;

const ANCHOR_SET_SIZE: usize = 60;

pub struct AnchorSets {
    pub sets: HashMap<TrustId, AnchorSet>,
}

impl AnchorSets {
    pub fn from_anchors(raw: Vec<RootAnchor>) -> Self {
        let mut sets = HashMap::new();
        let insert = |sets: &mut HashMap<TrustId, AnchorSet>, window: &[RootAnchor]| {
            let expanded = AnchorSet::from_anchors(window.to_vec());
            let trust_set = compute_trust_set(window);
            sets.insert(TrustId::from(trust_set.id), expanded);
        };
        if raw.len() < ANCHOR_SET_SIZE {
            if !raw.is_empty() {
                insert(&mut sets, &raw);
            }
        } else {
            for window in raw.windows(ANCHOR_SET_SIZE) {
                insert(&mut sets, window);
            }
        }
        Self { sets }
    }

    pub fn get(&self, key: TrustId) -> Option<&AnchorSet> {
        self.sets.get(&key)
    }

    pub fn latest(&self) -> Option<&AnchorSet> {
        self.sets.values().max_by_key(|s| s.tip_height())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libveritas::compute_trust_set;

    // Real GET /anchors payload captured from a live relay (localhost:7779).
    // Newest-first: entries[0].height = 6480 (tip), entries[59] = 4356 (oldest).
    const REAL: &str = include_str!("testdata/anchors_newest_first.json");
    // The X-Anchor-Root header the same relay served with this body.
    const SERVED_ROOT: &str =
        "7f20135af5fea06ac6a38303ea887428a614186979a41abde64e03ea6780375e";

    #[test]
    fn tip_is_first_not_last_and_order_is_canonical() {
        let set: AnchorSet = serde_json::from_str(REAL).unwrap();
        assert_eq!(set.entries.len(), 60);
        assert_eq!(set.entries.first().unwrap().block.height, 6480);
        assert_eq!(set.entries.last().unwrap().block.height, 4356);

        // The order is load-bearing: re-hashing the entries AS SERVED must
        // reproduce the relay's X-Anchor-Root, since compute_trust_set folds
        // them in sequence. Any reordering would change the id.
        let id = hex::encode(compute_trust_set(&set.entries).id);
        assert_eq!(id, SERVED_ROOT, "served entries must be in canonical order");

        // The bug: `.last()` reported the OLDEST anchor (4356) as the tip.
        // The fix: the tip is the newest = first (6480).
        assert_eq!(set.entries.last().unwrap().block.height, 4356);
        assert_eq!(set.tip_height(), 6480);
    }

    #[test]
    fn latest_selects_window_with_newest_anchor() {
        let set: AnchorSet = serde_json::from_str(REAL).unwrap();
        let sets = AnchorSets::from_anchors(set.entries);
        assert_eq!(sets.latest().unwrap().tip_height(), 6480);
    }
}
