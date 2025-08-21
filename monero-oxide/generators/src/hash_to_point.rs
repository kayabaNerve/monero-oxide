use subtle::{ConstantTimeEq, ConditionallySelectable};

use curve25519_dalek::edwards::EdwardsPoint;

use group::ff::{Field, PrimeField};
use dalek_ff_group::FieldElement;

use monero_io::decompress_point;

use crate::keccak256;

/// Monero's `hash_to_ec` function.
///
/// This achieves parity with https://github.com/monero-project/monero
///   /blob/389e3ba1df4a6df4c8f9d116aa239d4c00f5bc78/src/crypto/crypto.cpp#L611, inlining the
/// `ge_fromfe_frombytes_vartime` function (https://github.com/monero-project/monero
///   /blob/389e3ba1df4a6df4c8f9d116aa239d4c00f5bc78/src/crypto/crypto-ops.c#L2309). This
/// implementation runs in constant time.
///
/// According to the original authors, this would implement https://arxiv.org/abs/0706.1448, yet
/// the referenced methodology doesn't appear present. Notes by Shen Noether also describe the
/// algorithm (https://web.getmonero.org/resources/research-lab/pubs/ge_fromfe.pdf), yet without
/// reviewing its security and in a very straight-forward fashion. This function does attempt to
/// be well documented to explain the algorithm however.
pub fn hash_to_point(bytes: [u8; 32]) -> EdwardsPoint {
  // Curve25519 is a Montgomery curve with equation y^2 = x^3 + 486662 x^2 + x
  #[allow(non_snake_case)]
  let A = FieldElement::from(486662u64);

  let v = FieldElement::from_square(keccak256(&bytes)).double();
  let w = v + FieldElement::ONE;

  let w_over_x_was_square = {
    let u = w;
    let v = w.square() + (-A.square() * v);

    // Parts of sqrt_ratio_i, as documented here: https://ristretto.group/formulas/invsqrt.html
    {
      // Step 1
      #[allow(non_snake_case)]
      let r = {
        let v3 = v * v * v;
        let uv3 = u * v3;
        let v7 = v3 * v3 * v;
        let uv7 = u * v7;
        uv3 *
          uv7.pow(
            (-FieldElement::from(5u8)) *
              FieldElement::from(8u8)
                .invert()
                .expect("eight was coprime with the prime 2^{255}-19"),
          )
      };
      // Step 2
      let c = r.square() * v;

      // Step 3
      let correct_sign_sqrt = c.ct_eq(&u);
      // Step 4
      let flipped_sign_sqrt = c.ct_eq(&-u);

      // Skips steps 5-7, not updating (nor returning) `r`

      correct_sign_sqrt | flipped_sign_sqrt
    }
  };

  /*
    The following code does not calculate the full coordinates of the resulting point, solely the
    `Y` coordinate and the sign of the `X` coordinate. We then encode this, passing it to
    curve25519-dalek to decompress and yield us the instantiated point.

    This resolves the API boundary of how we cannot instantiate a `curve25519_dalek::EdwardsPoint`
    from its coordinates.
  */
  let sign = !w_over_x_was_square;

  let mut z = -A;
  z *= FieldElement::conditional_select(&v, &FieldElement::from(1u8), sign);
  #[allow(non_snake_case)]
  let Z = z + w;
  #[allow(non_snake_case)]
  let mut Y = z - w;

  /*
    If sign, `z = -486662`, else, `z = -486662 * v`
    `w = v + 1`

    We need `z + w \ne 0`, which would require `z \cong -w \mod 2^{255}-19`. This requires:
    - If `sign`, `v \mod 2^{255}-19 \ne 486661`.
    - If `!sign`, `(v + 1) \mod 2^{255}-19 \ne (v * 486662) \mod 2^{255}-19` which is equivalent to
      `(v * 486661) \mod 2^{255}-19 \ne 1`.

    In summary, if `sign`, `v` must not `486661`, and if `!sign`, `v` must not be the
    multiplicative inverse of `486661`. Since `v` is the output of a hash function, this should
    have negligible probability. Additionally, since the definition of `sign` is dependent on `v`,
    it may be truly impossible to reach.
  */
  Y *= Z.invert().expect("if sign, v was 486661. if !sign, v was 486661^{-1}");
  let mut bytes = Y.to_repr();
  bytes[31] |= sign.unwrap_u8() << 7;

  decompress_point(bytes).expect("point from hash-to-curve wasn't on-curve").mul_by_cofactor()
}
