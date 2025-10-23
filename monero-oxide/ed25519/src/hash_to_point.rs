use subtle::{Choice, ConstantTimeEq, ConditionallySelectable};

use sha3::{Digest, Keccak256};

use crypto_bigint::{Encoding, modular::constant_mod::*, Word, Limb, U256, impl_modulus};

const MODULUS_STR: &str = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed";
impl_modulus!(Two25519, U256, MODULUS_STR);

type Two25519Residue = Residue<Two25519, { U256::LIMBS }>;

/*
  Curve25519 is a Montgomery curve with equation `v^2 = u^3 + 486662 u^2 + u`.

  A Curve25519 point `(u, v)` may be mapped to an Ed25519 point `(x, y)` with the map
  `(sqrt(-(A + 2)) u / v, (u - 1) / (u + 1))`.
*/
const A: Two25519Residue = Two25519Residue::new(&U256::from_u64(486662));
const NEGATIVE_A: Two25519Residue = A.neg();
const D: Two25519Residue = Two25519Residue::new(&U256::from_u64(121665))
  .neg()
  .mul(&Two25519Residue::new(&U256::from_u64(121666)).invert().0);

/// Two candidates for the square root of the value when $modulus \cong 5 \mod 8$
///
/// If the value is a quadratic residue, one of these will be its square root. If the value is not
/// a quadratic residue, neither of these values will be.
///
/// This function executes in constant-time.
//
// Unfortunately, we need our own implementation due to the lack of `Residue::sqrt` being provided
// by `crypto-bigint {0.5, 0.6, 0.7}`. We are also stuck on `crypto-bigint 0.5` if we wish to
// target an MSRV of 1.69 or below.
//
// RFC-8032 provides `sqrt8k5`, which is effectively equivalent to this function except for the
// value returned.
const fn square_root_candidates(value: &Two25519Residue) -> (Two25519Residue, Two25519Residue) {
  // (p + 3) // 8
  const SQRT_EXP: U256 = Two25519::MODULUS.shr_vartime(3).wrapping_add(&U256::ONE);
  // 2^{(p - 1) // 4}
  const Z: Two25519Residue =
    Two25519Residue::ONE.add(&Two25519Residue::ONE).pow(&Two25519::MODULUS.shr_vartime(2));
  let y = value.pow(&SQRT_EXP);
  (y, y.mul(&Z))
}

fn is_quadratic_residue_8_mod_5(value: &Two25519Residue) -> Choice {
  let (a, b) = square_root_candidates(value);
  a.square().ct_eq(value) | b.square().ct_eq(value)
}

/// A `const fn` for if two `U256`s are equal.
///
/// This function executes in constant-time.
#[allow(clippy::cast_possible_truncation)]
const fn const_eq(a: &U256, b: &U256) -> u8 {
  let zero_if_eq = a.wrapping_sub(b);
  // Due to the lack of a `const fn eq`, we use any overflow for if the difference was non-zero
  let (_low_256_bits, high_bit) = U256::MAX.adc(&zero_if_eq, Limb::ZERO);
  // Negate from difference was non-zero to difference was zero
  (high_bit.0 as u8) ^ 1
}

const fn const_is_quadratic_residue_8_mod_5(value: &Two25519Residue) -> u8 {
  let (a, b) = square_root_candidates(value);
  let value = value.retrieve();
  const_eq(&a.square().retrieve(), &value) | const_eq(&b.square().retrieve(), &value)
}

/// The two candidate `u` coordinates for an input value.
const fn candidate_u_coordinates(r: &Two25519Residue) -> (Two25519Residue, Two25519Residue) {
  // Per Section 5.5, take `u = 2`. This is the smallest quadratic non-residue in the field
  let r_square = r.square();
  let ur_square = r_square.add(&r_square);

  /*
    We know this is non-zero as:

    ```sage
    p = 2**255 - 19
    Mod((p - 1) * inverse_mod(2, p), p).is_square() == False
    ```
  */
  let one_plus_ur_square = Two25519Residue::ONE.add(&ur_square);
  let (one_plus_ur_square_inv, _value_was_zero) = one_plus_ur_square.invert();
  let upsilon = NEGATIVE_A.mul(&one_plus_ur_square_inv);
  /*
    Quoting section 5.5,
    "then \epsilon = 1 and x = \upsilon. Otherwise \epsilon = -1, x = \upsilon u r^2"

    Whereas in the specification present in Section 5.2, the expansion of the `u` coordinate when
    `\epsilon = -1` is `-\upsilon - A`. Per Section 5.2, in the "Second case",
    `= -\upsilon - A = \upsilon u r^2`. These two values are equivalent, yet the negation and
    subtract outperform a multiplication.
  */
  let other_candidate = upsilon.neg().sub(&A);

  (upsilon, other_candidate)
}

const fn curve_equation(u: &Two25519Residue) -> Two25519Residue {
  u.add(&A).mul(&u.square()).add(u)
}

pub(crate) fn map(bytes: [u8; 32]) -> curve25519_dalek::EdwardsPoint {
  // Sample a uniform field element
  /*
    This isn't a wide reduction, implying it'd be biased, yet the bias should only be negligible
    due to the shape of the prime number. All elements within the prime field field have a
    `2 / 2^{256}` chance of being selected, except for the first 19 which have a `3 / 2^256`
    chance of being selected. In order for this 'third chance' (the bias) to be relevant, the
    hash function would have to output a number greater than or equal to:

      0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffda

    which is of negligible probability.
  */
  let r = Two25519Residue::new(&U256::from_le_bytes(Keccak256::digest(bytes).into()));

  let (upsilon, other_candidate) = candidate_u_coordinates(&r);

  /*
    Check if `\upsilon` is a valid `u` coordinate by checking for a solution for the square root
    of `\upsilon^3 + A \upsilon^2 + \upsilon`.
  */
  let epsilon = is_quadratic_residue_8_mod_5(&curve_equation(&upsilon));
  // Select the `u` coordinate which has a solution to the curve equation
  let u = Two25519Residue::conditional_select(&other_candidate, &upsilon, epsilon);

  // Map from Curve25519 to Ed25519
  /*
    Elligator 2's specification in section 5.2 says to choose the negative square root as the
    `v` coordinate if `\upsilon` was chosen (as signaled by `\epsilon = 1`). The following
    chooses the odd `y` coordinate if `\upsilon` was chosen, which is functionally equivalent.
  */
  let res = curve25519_dalek::MontgomeryPoint(u.retrieve().to_le_bytes())
    .to_edwards(epsilon.unwrap_u8())
    .expect("neither Elligator 2 candidate was a square");

  // Ensure this point lies within the odd-prime-order subgroup
  res.mul_by_cofactor()
}

const fn const_select(a: &Two25519Residue, b: &Two25519Residue, choice: u8) -> Two25519Residue {
  a.add(&b.sub(a).mul(&Two25519Residue::new(&U256::from_u8(choice))))
}

/// Calculate the square-root of a quadratic residue.
///
/// This returns an undefined value for non-quadratic-residues.
const fn const_sqrt(value: &Two25519Residue) -> Two25519Residue {
  let (sqrt_a, sqrt_b) = square_root_candidates(value);
  const_select(&sqrt_b, &sqrt_a, const_eq(&sqrt_a.square().retrieve(), &value.retrieve()))
}

pub(crate) const fn const_map(bytes: [u8; 32]) -> [u8; 32] {
  let (u, epsilon) = {
    let r = Two25519Residue::new(&U256::from_le_slice(
      &keccak_const::Keccak256::new().update(&bytes).finalize(),
    ));
    let (upsilon, other_candidate) = candidate_u_coordinates(&r);
    let epsilon = const_is_quadratic_residue_8_mod_5(&curve_equation(&upsilon));
    (const_select(&other_candidate, &upsilon, epsilon), epsilon)
  };

  let v = const_sqrt(&curve_equation(&u));

  // Map to Ed25519
  const SQRT_NEG_A_2: Two25519Residue =
    const_sqrt(&A.add(&Two25519Residue::ONE.add(&Two25519Residue::ONE)).neg());
  let mut x = {
    let x_candidate = SQRT_NEG_A_2.mul(&u.mul(&v.invert().0));
    // If the parity of our candidate is distinct from epsilon, negate it
    const_select(
      &x_candidate,
      &x_candidate.neg(),
      ((x_candidate.retrieve().as_limbs()[0].0 % 2) as u8) ^ epsilon,
    )
  };
  let mut y = u.sub(&Two25519Residue::ONE).mul(&u.add(&Two25519Residue::ONE).invert().0);

  // Clear the cofactor
  // https://hyperelliptic.org/EFD/g1p/auto-twisted.html presents Affine doubling formulas
  let mut i = 0;
  while i < 3 {
    let xy = x.mul(&y);
    let x_num = xy.add(&xy);
    let xyxy = xy.mul(&xy);
    let x_denom = Two25519Residue::ONE.add(&D.mul(&xyxy));

    // This is as Ed25519's curve equation's `A` is -1
    let y_num = y.square().add(&x.square());
    let y_denom = Two25519Residue::ONE.sub(&D.mul(&xyxy));

    x = x_num.mul(&x_denom.invert().0);
    y = y_num.mul(&y_denom.invert().0);

    i += 1;
  }

  // Encode the result
  let y = y.retrieve();
  // TODO: With `crypto-bigint 0.6`, adopt the provided `to_le_bytes`
  let mut res = [0; 32];
  let mut b = 0;
  #[allow(clippy::cast_possible_truncation)]
  while b < 32 {
    res[b] = (y.shr_vartime(8 * b).as_limbs()[0].0 & (u8::MAX as Word)) as u8;
    b += 1;
  }
  res[31] |= ((x.retrieve().as_limbs()[0].0 % 2) as u8) << 7;
  res
}
