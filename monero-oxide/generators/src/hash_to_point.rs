use subtle::{Choice, ConstantTimeEq, ConditionallySelectable};

use group::ff::{Field, PrimeField};
use curve25519_dalek::edwards::EdwardsPoint;
use dalek_ff_group::FieldElement;

use monero_io::decompress_point;

use crate::keccak256;

/*
  This function and the following `curve25519_u_z_and_x_sign_to_ed25519_point_slow` function are
  SOLELY INTENDED for use with `hash_to_point`. They do not accept arbitrary `u, z, sign` values,
  expecting the values to rely within a certain set. They MUST NOT be used within any other
  context.
*/
fn curve25519_u_z_and_x_sign_to_ed25519_point(
  u: FieldElement,
  z: FieldElement,
  sign: Choice,
) -> EdwardsPoint {
  /*
  Map from the Curve25519 `u` coordinate to an Ed25519 `y` coordinate.

  Instead of normalizing, then mapping, the following equation optimizes to a single inversion.

  If `u / z` is actually the coordinate of a point on Curve25519, the following `unwrap` calls
  will never trigger due to the map from Curve25519 to Ed25519 being well-defined.
  */
  let y = (u - z) * (u + z).invert().unwrap();
  debug_assert_eq!(
    y,
    {
      let u = u * z.invert().expect("unreachable modulo 2^{255} - 19 due to how `z` was chosen");
      (u - FieldElement::ONE) * (u + FieldElement::ONE).invert().unwrap()
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

  If `u / z` is actually the coordinate of a point on Curve25519, `y` will actually be the
  coordinate of a point on Ed25519 due to the map from Curve25519 to Ed25519 being well-defined.
  */
  decompress_point(bytes).expect("point from hash-to-curve wasn't on-curve")
}

/*
  This slow function exists as it's much smaller and much more readable. It just also pays the cost
  of an extra inversion, which isn't cheap, so it's not worth using except as a sanity check.
*/
#[cfg(debug_assertions)]
fn curve25519_u_z_and_x_sign_to_ed25519_point_slow(
  u: FieldElement,
  z: FieldElement,
  sign: Choice,
) -> EdwardsPoint {
  curve25519_dalek::MontgomeryPoint(
    (u * z.invert().expect("unreachable modulo 2^{255} - 19 due to how `z` was chosen")).to_repr(),
  )
  .to_edwards(sign.unwrap_u8())
  .unwrap()
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
    uv3 *
      uv7.pow(
        (-FieldElement::from(5u8)) *
          FieldElement::from(8u8).invert().expect("eight was coprime with the prime 2^{255}-19"),
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

#[cfg(debug_assertions)]
fn is_square_ratio_i_slow(u: FieldElement, v: FieldElement) -> Choice {
  (u * v.invert().unwrap()).sqrt().is_some()
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
  */
  #[allow(non_snake_case)]
  let A = FieldElement::from(486662u64);
  #[allow(non_snake_case)]
  let negative_A = -A;

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

  // OPEN QUESTION: What is this value?
  let step_1 = sampled_field_element.square().double();

  /*
    `z` is used as the denominator within projective coordinates for a point on Curve25519. We know
    it's non-zero as:

    ```sage
    p = 2**255 - 19
    Mod((p - 1) * inverse_mod(2, p), p).is_square() == False
    ```

    This potentially immediately explains why `let step_1 = step_1.square().double();` occurs.
  */
  let z = step_1 + FieldElement::ONE;

  let was_square = {
    // OPEN QUESTION: Why are these the values used here?
    let num = z;
    /*
      OPEN QUESTION: Why will `denom` be non-zero? Statistically negligible probability?

      We don't actually need `denom` to be non-zero. `is_square_ratio_i` won't panic even if
      `denom` is zero, yet it won't have well-defined behavior either (due to returning if an
      undefined number is considered square) which likely complicates the following analysis.
    */
    let denom = z.square() - (A.square() * step_1);
    let was_square = is_square_ratio_i(num, denom);
    debug_assert_eq!(
      bool::from(was_square),
      bool::from(is_square_ratio_i_slow(num, denom)),
      "is_square_ratio_i implementation returned an incorrect result"
    );
    was_square
  };

  /*
    This is the _Projective_ `u` coordinate for a point on Curve25519. The Affine `u` coordinate
    would be `u / z`.
  */
  /*
    OPEN QUESTION: Why is this a coordinate of a point on Curve25519, except with negligible
    probability? Is it uniform to the set of all `u` coordinates for points on Curve25519?
  */
  let u = FieldElement::conditional_select(&(negative_A * step_1), &negative_A, !was_square);

  /*
    OPEN QUESTION: Why is `!was_square` used for the sign?

    This is probably best answered by implementing the rest of the calculations for the `x`
    coordinate in this function, which will probably show the relation.
  */
  let x_coordinate_sign = !was_square;
  let res = curve25519_u_z_and_x_sign_to_ed25519_point(u, z, x_coordinate_sign);
  debug_assert_eq!(res, curve25519_u_z_and_x_sign_to_ed25519_point_slow(u, z, x_coordinate_sign));
  res.mul_by_cofactor()
}
