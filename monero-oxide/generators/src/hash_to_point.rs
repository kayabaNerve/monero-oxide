use subtle::{Choice, ConstantTimeEq, ConditionallySelectable};

use group::ff::{Field, PrimeField};
use curve25519_dalek::edwards::EdwardsPoint;
use dalek_ff_group::FieldElement;

use monero_io::decompress_point;

use crate::keccak256;

/*
  This function is SOLELY INTENDED for use with `hash_to_point`. It does not accept arbitrary
  `u, w, sign` values, expecting the values to rely within a certain set. It MUST NOT be used
  within any other context.
*/
fn curve25519_u_w_and_x_sign_to_ed25519_point(
  u: FieldElement,
  w: FieldElement,
  sign: Choice,
) -> EdwardsPoint {
  /*
    Map from the Curve25519 `u` coordinate to an Ed25519 `y` coordinate.

    Instead of normalizing, then mapping, the following equation optimizes to a single inversion.

    If `u / w` is actually the coordinate of a point on Curve25519, the following `unwrap` calls
    will never trigger due to the map from Curve25519 to Ed25519 being well-defined.
  */
  let y = (u - w) * (u + w).invert().expect("off-curve input");
  debug_assert_eq!(
    y,
    {
      let u = u * w.invert().expect("unreachable modulo 2^{255} - 19 due to how `w` was chosen");
      (u - FieldElement::ONE) * (u + FieldElement::ONE).invert().expect("off-curve input")
    },
    "normalize and map wasn't equivalent to normalize, then map"
  );

  /*
    Encode the `y` coordinate for us to then pass to `curve25519-dalek`, which won't let us
    construct a point directly from its `x, y` coordinates.

    This is slightly inefficient, as `curve25519-dalek` will redo all the work to perform point
    decompression. In comparison, we can also immediately calculate the `x` coordinate.
  */
  let mut bytes = y.to_repr();
  // Add the sign bit for which `x` coordinate to take.
  bytes[31] |= sign.unwrap_u8() << 7;

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

    If `u / w` is actually the coordinate of a point on Curve25519, `y` will actually be the
    coordinate of a point on Ed25519 due to the map from Curve25519 to Ed25519 being well-defined.
  */
  decompress_point(bytes).expect("point from hash-to-curve wasn't on-curve")
}

/*
  `sqrt_ratio_i(u, v)` (where `u, v` represent any elements of the field) is a frequently-defined
  function to calculate the square root of `u / v`. The benefit of such an explicit function is
  it is _much faster_ than explicitly calculating `sqrt(u * v.invert())`.

  `sqrt_ratio_i(u, v)` traditionally returns if `u / v` is square and the square root if so. For
  documentation, please see the following links:
  - https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.3
  - https://ristretto.group/formulas/invsqrt.html

  `is_square_ratio_i(u, v)` solely returns if `u / v` is square and doesn't finish the square-root
  calculation. The internal methodology is identical however, following the notation from
  ristretto.group.
*/
fn is_square_ratio_i(u: FieldElement, v: FieldElement) -> Choice {
  // Step 1
  #[allow(non_snake_case)]
  let r = {
    let v3 = v * v * v;
    let uv3 = u * v3;
    let v7 = v3 * v3 * v;
    let uv7 = u * v7;
    const NEG_5_DIV_8: FieldElement = FieldElement::from_u256({
      use crypto_bigint::U256;
      let two_255 = U256::from_u64(1).shl_vartime(255);
      let two_255_minus_19_minus_5 = two_255.wrapping_sub(&U256::from_u64(19 + 5));
      &(two_255_minus_19_minus_5.shr_vartime(3))
    });
    uv3 * uv7.pow(NEG_5_DIV_8)
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
    `(sqrt(-(A + 2)) u / v, (u - 1) / (u + 1))`.

    Note we'll use `(u, v, w)` to denote projective Curve25519 coordinates corresponding to the
    point `(u / w, v / w)`.
  */
  #[allow(non_snake_case)]
  let A = FieldElement::from(486662u64);
  #[allow(non_snake_case)]
  let A_square = FieldElement::from(236839902244u64);
  #[allow(non_snake_case)]
  let negative_A = -A;

  /*
    The paper supposedly implemented defines a solution for:
      g_1(x) = x^n + ax + b
      g_2(x) = x^n + ax^2 + bx
    where `g = g_1` or `g = g_2`.

    Curve25519's equation does match `g_2` with `n = 3`.
  */

  // Sample a FieldElement
  let sampled_field_element = {
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

  /*
    OPEN QUESTION: What is this value?

    The original implementation labelled it `v`, implying it's a Curve25519 coordinate. Here, we
    use `s` as it's a single letter and doesn't conflict with anything else.
  */
  let s = sampled_field_element.square().double();

  /*
    We know this is non-zero as:

    ```sage
    p = 2**255 - 19
    Mod((p - 1) * inverse_mod(2, p), p).is_square() == False
    ```

    This effect potentially explains `let s = sampled_field_element.square().double();`.
  */
  let w = s + FieldElement::ONE;

  /*
    The primary claim of this algorithm is as follows:

      For `w = s + 1`, if `w / (w^2 - (A^2 * s))` is square modulo 2^{255}-19, `-A * s / w` will be
      the `u`-affine-coordinate of a uniformly-sampled on-Curve25519 point. Else, `-A / w` will be.

    For any value to be the `u`-affine coordinate of an on-Curve25519 point, `u^3 + A u^2 + u`
    must be square modulo 2^{255}-19.

    The `u` coordinate is only sufficient to identify one of two points. For the corresponding
    Ed25519 `y` coordinate, the odd `x` is taken if the tested value is not square.

    The open questions are as follows:
      - Why is `(s + 1)^2 - (A^2 * s)` non-zero, and therefore well-defined to take the
        multiplicative inverse of?
      - Why is the claim true?
      - Does this uniformly sample the resulting point?

    We answer the first question here. For the value to be zero, `(s + 1)^2` must equal
    `(A^2 * s)`. Expanding, we have:
      `(s^2 + 2 s + 1) == (A^2 * s)`
      or
      `(s + 2 + (1 / s))` == A^2
    As `s` is uniform to the field, our left-hand side should be uniform to the field as well. This
    leaves negligible probability of colliding with `A^2`. This assumes `1 / s` is well-defined,
    and again, since `s` is uniform to the field, it is except with negligible probability.
  */
  #[cfg(debug_assertions)]
  let expected_result = {
    let w_inv = w.invert().expect("unreachable modulo 2^{255} - 19 due to how `w` was chosen");
    let candidate_2 = negative_A * w_inv;
    let candidate_1 = candidate_2 * s;
    let was_square = (w * (w.square() - (A_square * s)).invert().expect("negligible probability"))
      .sqrt()
      .is_some();
    let res = <_>::conditional_select(&candidate_2, &candidate_1, was_square);
    curve25519_dalek::MontgomeryPoint(res.to_repr())
      .to_edwards((!was_square).unwrap_u8())
      .expect("counterexample to second open question")
  };

  let was_square = {
    // We expand this by hand to replace one multiplication with two additions and a doubling
    let denom = ((s - A_square) * s) + s.double() + FieldElement::ONE;
    debug_assert_eq!(denom, w.square() - (A_square * s));
    is_square_ratio_i(w, denom)
  };

  /*
    This is the _Projective_ `u` coordinate for a point on Curve25519. The Affine `u` coordinate
    would be `u / w`.
  */
  let u = FieldElement::conditional_select(&(negative_A * s), &negative_A, !was_square);

  let x_coordinate_sign = !was_square;
  let res = curve25519_u_w_and_x_sign_to_ed25519_point(u, w, x_coordinate_sign);
  debug_assert_eq!(res, expected_result);

  // Ensure this point lies within the prime-order subgroup
  res.mul_by_cofactor()
}
