use std_shims::vec::Vec;

use crate::primitives::keccak256;

/// Calculates the Merkle root of the given tree.
///
/// Complimentary to `tree_hash` in monero-core:
/// https://github.com/monero-project/monero/blob/893916ad091a92e765ce3241b94e706ad012b62a
///   /src/crypto/tree-hash.c#L62
///
/// This function returns [`None`] if the tree is empty or has an absurd amount of leaves.
pub fn merkle_root(mut leaves: Vec<[u8; 32]>) -> Option<[u8; 32]> {
  match leaves.len() {
    0 => None,
    1 => Some(leaves[0]),
    2 => Some(keccak256([leaves[0], leaves[1]].concat())),
    _ => {
      // https://github.com/monero-project/monero/blob/b591866fcfed400bc89631686655aa769ec5f2dd
      //   /src/crypto/tree-hash.c#L55
      if leaves.len() > 0x10000000 {
        None?;
      }

      // Monero preprocess this so the length is a power of 2
      let mut high_pow_2 = 4; // 4 is the lowest value this can be
      while high_pow_2 < leaves.len() {
        high_pow_2 *= 2;
      }
      let low_pow_2 = high_pow_2 / 2;

      // Merge right-most hashes until we're at the low_pow_2
      {
        let overage = leaves.len() - low_pow_2;
        let mut rightmost = leaves.drain((low_pow_2 - overage) ..);
        // This is true since we took overage from beneath and above low_pow_2, taking twice as
        // many elements as overage
        debug_assert_eq!(rightmost.len() % 2, 0);

        let mut paired_hashes = Vec::with_capacity(overage);
        while let Some(left) = rightmost.next() {
          let right = rightmost.next().expect("rightmost is of even length");
          paired_hashes.push(keccak256([left, right].concat()));
        }
        drop(rightmost);

        leaves.extend(paired_hashes);
        assert_eq!(leaves.len(), low_pow_2);
      }

      // Do a traditional pairing off
      let mut new_hashes = Vec::with_capacity(leaves.len() / 2);
      while leaves.len() > 1 {
        let mut i = 0;
        while i < leaves.len() {
          new_hashes.push(keccak256([leaves[i], leaves[i + 1]].concat()));
          i += 2;
        }

        leaves = new_hashes;
        new_hashes = Vec::with_capacity(leaves.len() / 2);
      }
      Some(leaves[0])
    }
  }
}
