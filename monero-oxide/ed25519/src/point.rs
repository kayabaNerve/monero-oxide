use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

use crate::CompressedPoint;

/// A decompressed point on the Ed25519 elliptic curve.
#[derive(Clone, Copy, Eq, Debug, Zeroize)]
pub struct Point(curve25519_dalek::EdwardsPoint);

impl ConstantTimeEq for Point {
  fn ct_eq(&self, other: &Self) -> Choice {
    self.0.ct_eq(&other.0)
  }
}
impl PartialEq for Point {
  /// This defers to `ConstantTimeEq::ct_eq`.
  fn eq(&self, other: &Self) -> bool {
    bool::from(self.ct_eq(other))
  }
}

impl Point {
  /// Sample a biased point within the odd-prime-order subgroup of Ed25519 via a hash function.
  ///
  /// This is comparable to Monero's `hash_to_ec` function.
  ///
  /// This achieves parity with https://github.com/monero-project/monero
  ///   /blob/389e3ba1df4a6df4c8f9d116aa239d4c00f5bc78/src/crypto/crypto.cpp#L611, inlining the
  /// `ge_fromfe_frombytes_vartime` function (https://github.com/monero-project/monero
  ///   /blob/389e3ba1df4a6df4c8f9d116aa239d4c00f5bc78/src/crypto/crypto-ops.c#L2309). This
  /// implementation runs in constant time.
  ///
  /// According to the original authors
  /// (https://web.archive.org/web/20201028121818/https://cryptonote.org/whitepaper.pdf), this
  /// would implement https://arxiv.org/abs/0706.1448. Shen Noether also describes the algorithm
  /// (https://web.getmonero.org/resources/research-lab/pubs/ge_fromfe.pdf), yet without reviewing
  /// its security and in a very straight-forward fashion.
  ///
  /// In reality, this implements Elligator 2 as detailed in
  /// "Elligator: Elliptic-curve points indistinguishable from uniform random strings"
  /// (https://eprint.iacr.org/2013/325). Specifically, Section 5.5 details the application of
  /// Elligator 2 to Curve25519, after which the result is mapped to Ed25519.
  ///
  /// As this only applies Elligator 2 once, it's limited to a subset of points where a certain
  /// derivative of their `u` coordinates (in Montgomery form) are quadratic residues. It's biased
  /// accordingly. The yielded points SHOULD still have uniform relations to each other however.
  pub fn biased_hash(bytes: [u8; 32]) -> Self {
    Self(crate::hash_to_point::map(bytes))
  }

  /// Compress a point to a `CompressedPoint`.
  pub fn compress(self) -> CompressedPoint {
    CompressedPoint::from(self.0.compress().to_bytes())
  }

  /// Create a `Point` from a `curve25519_dalek::EdwardsPoint`.
  ///
  /// This is not a public function as it is not part of our API commitment.
  pub(crate) fn from(point: curve25519_dalek::EdwardsPoint) -> Self {
    Self(point)
  }

  /// Create a `curve25519_dalek::EdwardsPoint` from a `Point`.
  ///
  /// This is hidden as it is not part of our API commitment. No guarantees are made for it.
  #[doc(hidden)]
  pub fn into(self) -> curve25519_dalek::EdwardsPoint {
    self.0
  }

  /// Treat a point as a key image.
  ///
  /// This is hidden as it is not part of our API commitment. No guarantees are made for it.
  #[doc(hidden)]
  pub fn key_image(self) -> Option<curve25519_dalek::EdwardsPoint> {
    use curve25519_dalek::traits::IsIdentity;
    if self.0.is_identity() || (!self.0.is_torsion_free()) {
      None?;
    }
    Some(self.0)
  }
}
