use subtle::{ConstantTimeEq, ConditionallySelectable};

use group::ff::{Field, PrimeField};
use curve25519_dalek::edwards::EdwardsPoint;
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
/// According to the original authors
/// (https://web.archive.org/web/20201028121818/https://cryptonote.org/whitepaper.pdf), this would
/// implement https://arxiv.org/abs/0706.1448, yet the cited methodology doesn't appear present.
/// Notes by Shen Noether also describe the algorithm
/// (https://web.getmonero.org/resources/research-lab/pubs/ge_fromfe.pdf), yet without reviewing
/// its security and in a very straight-forward fashion. This function does attempt to be well
/// documented to explain the algorithm however.
pub fn hash_to_point(bytes: [u8; 32]) -> EdwardsPoint {
  /*
    Curve25519 is a Montgomery curve with equation v^2 = u^3 + 486662 u^2 + u.

    A Curve25519 point `(u, v)` may be mapped to an Ed25519 point `(x, y)` with the map
    `(sqrt(-(A+2)) u/v, (u-1) / (v+1))`.
  */
  #[allow(non_snake_case)]
  let A = FieldElement::from(486662u64);
  #[allow(non_snake_case)]
  let negative_A = -A;

  let step_1 = {
    use crypto_bigint::{Encoding, U256};
    FieldElement::from_u256(&U256::from_le_bytes(keccak256(&bytes)))
  };
  let step_1 = step_1.square();
  let step_1 = step_1.double();

  let step_2 = step_1 + FieldElement::ONE;

  // derivative_was_square = (step_2 / (step_2^2 - (A^2 * step_1))).is_square()
  let derivative_was_square = {
    // The inputs to the following inlined function, in its preferred notation
    let u = step_2;
    let v = step_2.square() - (A.square() * step_1);

    /*
      sqrt_ratio_i(u, v) primarily calculates the square root of `u / v`, at roughly half the cost
      of calculating `sqrt(u * v.invert())`. Documentation be found at the following links:
      - https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.3
      - https://ristretto.group/formulas/invsqrt.html

      The following implements parts of ristretto.group's detailing of the algorithm, in its
      notation.
    */
    let derivative_was_square = {
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
    };

    debug_assert_eq!(
      bool::from(derivative_was_square),
      Option::<FieldElement>::from((u * v.invert().unwrap()).sqrt()).is_some()
    );

    derivative_was_square
  };

  /*
    The following code does not calculate the full coordinates of the resulting point, solely the
    `Y` coordinate and the sign of the `X` coordinate. We then encode this, passing it to
    curve25519-dalek to decompress and yield us the instantiated point.

    This resolves the API boundary of how we cannot instantiate a `curve25519_dalek::EdwardsPoint`
    from its coordinates.
  */

  let step_3 =
    FieldElement::conditional_select(&(negative_A * step_1), &negative_A, !derivative_was_square);

  /*
    sign = !derivative_was_square

    If sign, `step_3 = -486662`, else, `step_3 = -486662 * step_1`
    `step_2 = step_1 + 1`

    We need `step_3 + step_2 \ne 0`, which would require `step_3 \cong -step_2 \mod 2^{255}-19`.
    This requires:
    - If `sign`, `step_1 \mod 2^{255}-19 \ne 486661`.
    - If `!sign`, `(step_1 + 1) \mod 2^{255}-19 \ne (step_1 * 486662) \mod 2^{255}-19` which is
      equivalent to `(step_1 * 486661) \mod 2^{255}-19 \ne 1`.

    In summary, if `sign`, `step_1` must not equal `486661`, and if `!sign`, `step_1` must not be
    the multiplicative inverse of `486661`. Since `step_1` is the output of a hash function, this
    should have negligible probability. Additionally, since the definition of `sign` is dependent
    on `step_1`, it may be truly impossible to reach.
  */
  #[allow(non_snake_case)]
  let Y = (step_3 - step_2) *
    (step_3 + step_2).invert().expect(&format!(
      "step_1 ({:?}) was 486661 or 486661^{{-1}} depending on was_square ({}). input: {:?}",
      step_1,
      bool::from(derivative_was_square),
      bytes
    ));

  let mut bytes = Y.to_repr();
  bytes[31] |= (!derivative_was_square).unwrap_u8() << 7;

  /*
    Ed25519 point decompression works as follows.

    d = (-121665) / 121666
    x^2 = (y^2 - 1) / ((d y^2) + 1)

    Note `(d y^2) + 1` will always be non-zero as `((2^{255} - 19) - 1) / d` doesn't have a square
    root modulo `2^{255} - 19`.

    ```sage
    p = 2**255 - 19
    d = (-121665) * inverse_mod(121666, p)
    Mod((p - 1) * inverse_mod(d, p), p).is_square() == False
    ```
  */

  decompress_point(bytes).expect("point from hash-to-curve wasn't on-curve").mul_by_cofactor()
}
