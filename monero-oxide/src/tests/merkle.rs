use std_shims::vec::Vec;

use rand_core::{RngCore, OsRng};

use crate::primitives::keccak256;

fn old_merkle_root(mut leafs: Vec<[u8; 32]>) -> Option<[u8; 32]> {
  match leafs.len() {
    0 => None,
    1 => Some(leafs[0]),
    2 => Some(keccak256([leafs[0], leafs[1]].concat())),
    _ => {
      // Monero preprocess this so the length is a power of 2
      let mut high_pow_2 = 4; // 4 is the lowest value this can be
      while high_pow_2 < leafs.len() {
        high_pow_2 *= 2;
      }
      let low_pow_2 = high_pow_2 / 2;

      // Merge right-most hashes until we're at the low_pow_2
      {
        let overage = leafs.len() - low_pow_2;
        let mut rightmost = leafs.drain((low_pow_2 - overage) ..);
        // This is true since we took overage from beneath and above low_pow_2, taking twice as
        // many elements as overage
        debug_assert_eq!(rightmost.len() % 2, 0);

        let mut paired_hashes = Vec::with_capacity(overage);
        while let Some(left) = rightmost.next() {
          let right = rightmost.next().expect("rightmost is of even length");
          paired_hashes.push(keccak256([left, right].concat()));
        }
        drop(rightmost);

        leafs.extend(paired_hashes);
        assert_eq!(leafs.len(), low_pow_2);
      }

      // Do a traditional pairing off
      let mut new_hashes = Vec::with_capacity(leafs.len() / 2);
      while leafs.len() > 1 {
        let mut i = 0;
        while i < leafs.len() {
          new_hashes.push(keccak256([leafs[i], leafs[i + 1]].concat()));
          i += 2;
        }

        leafs = new_hashes;
        new_hashes = Vec::with_capacity(leafs.len() / 2);
      }
      Some(leafs[0])
    }
  }
}

#[test]
fn merkle() {
  assert!(old_merkle_root(vec![]).is_none());
  assert!(crate::merkle::merkle_root(&mut []).is_none());

  for i in 1 .. 513 {
    let mut leaves = Vec::with_capacity(i);
    for _ in 0 .. i {
      let mut leaf = [0; 32];
      OsRng.fill_bytes(&mut leaf);
      leaves.push(leaf);
    }

    let old = old_merkle_root(leaves.clone()).unwrap();
    let new = crate::merkle::merkle_root(&mut leaves).unwrap();
    assert_eq!(old, new);
  }
}
