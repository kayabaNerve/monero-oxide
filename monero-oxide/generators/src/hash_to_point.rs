use subtle::ConditionallySelectable;

use group::ff::{Field, PrimeField};
use curve25519_dalek::edwards::EdwardsPoint;
use dalek_ff_group::FieldElement;

use crate::keccak256;

/// Monero's `hash_to_ec` function.
///
/// This achieves parity with https://github.com/monero-project/monero
///   /blob/389e3ba1df4a6df4c8f9d116aa239d4c00f5bc78/src/crypto/crypto.cpp#L611, inlining the
/// `ge_fromfe_frombytes_vartime` function (https://github.com/monero-project/monero
///   /blob/389e3ba1df4a6df4c8f9d116aa239d4c00f5bc78/src/crypto/crypto-ops.c#L2309). This
/// implementation runs in constant time.
///
/// According to the original authors
/// (https://web.archive.org/web/20201028121818/https://cryptonote.org/whitepaper.pdf), this would
/// implement https://arxiv.org/abs/0706.1448. Shen Noether also describes the algorithm
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
/// accordingly.
pub fn biased_hash_to_point(bytes: [u8; 32]) -> EdwardsPoint {
  /*
    Curve25519 is a Montgomery curve with equation `v^2 = u^3 + 486662 u^2 + u`.

    A Curve25519 point `(u, v)` may be mapped to an Ed25519 point `(x, y)` with the map
    `(sqrt(-(A + 2)) u / v, (u - 1) / (u + 1))`.
  */
  #[allow(non_snake_case)]
  let A = FieldElement::from(486662u64);
  #[allow(non_snake_case)]
  let negative_A = -A;

  // Sample a FieldElement
  let r = {
    use crypto_bigint::{Encoding, U256};
    /*
      This isn't a wide reduction, implying it'd be biased, yet the bias should only be negligible
      due to the shape of the prime number. All elements within the prime field field have a
      `2 / 2^{256}` chance of being selected, except for the first 19 which have a `3 / 2^256`
      chance of being selected. In order for this 'third chance' (the bias) to be relevant, the
      hash function would have to output a number greater than or equal to:

        0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffda

      which is of negligible probability.
    */
    FieldElement::from_u256(&U256::from_le_bytes(keccak256(&bytes)))
  };

  // Per Section 5.5, take `u = 2`. This is the smallest quadratic non-residue in the field
  let ur_square = r.square().double();

  /*
    We know this is non-zero as:

    ```sage
    p = 2**255 - 19
    Mod((p - 1) * inverse_mod(2, p), p).is_square() == False
    ```
  */
  let one_plus_ur_square = FieldElement::ONE + ur_square;
  let one_plus_ur_square_inv = one_plus_ur_square
    .invert()
    .expect("unreachable modulo 2^{255} - 19 due to how `ur_square` was chosen");
  let upsilon = negative_A * one_plus_ur_square_inv;
  /*
    Quoting section 5.5,
    "then \epsilon = 1 and x = \upsilon. Otherwise \epsilon = -1, x = \upsilon u r^2"

    This differs from the map itself defined in 5.2, which sets the other candidate to
    `-1 upsilon - A`, as the IETF specification for Elligator 2 does when the curve is of the
    form `y^2 = x^3 + A x^2 + x`.
  */
  let other_candidate = upsilon * ur_square;

  /*
    Check if `upsilon` is a valid `u` coordinate by checking for a solution for the square root
    of `upsilon^3 + A upsilon^2 + upsilon`.
  */
  let epsilon = (((upsilon + A) * upsilon.square()) + upsilon).sqrt().is_some();
  let u = <FieldElement>::conditional_select(&other_candidate, &upsilon, epsilon);

  // Map from Curve25519 to Ed25519
  /*
    Elligator 2's specification in section 5.2 says to choose the negative square root as the
    `v` coordinate if `upsilon` was chosen (as signaled by `epsilon = 1`). The following
    chooses the odd `y` coordinate if `upsilon` was chosen.
  */
  let res = curve25519_dalek::MontgomeryPoint(u.to_repr())
    .to_edwards(epsilon.unwrap_u8())
    .expect("neither Elligator 2 candidate was a square");

  // Ensure this point lies within the prime-order subgroup
  res.mul_by_cofactor()
}
