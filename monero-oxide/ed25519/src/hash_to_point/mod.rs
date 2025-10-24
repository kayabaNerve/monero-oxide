use crypto_bigint::U256;

mod field25519;
use field25519::Field25519;

/*
  Curve25519 is a Montgomery curve with equation `v^2 = u^3 + 486662 u^2 + u`.

  A Curve25519 point `(u, v)` may be mapped to an Ed25519 point `(x, y)` with the map
  `(sqrt(-(A + 2)) u / v, (u - 1) / (u + 1))`.
*/
const A: Field25519 = Field25519::reduce(U256::from_u64(486662));
const NEGATIVE_A: Field25519 = A.neg();

const SQRT_NEG_A_2: Field25519 = A.add(Field25519::reduce(U256::from_u8(2))).neg().sqrt().unwrap();

/// The two candidate `u` coordinates for an input value.
const fn candidate_u_coordinates(r: Field25519) -> (Field25519, Field25519) {
  // Per Section 5.5, take `u = 2`. This is the smallest quadratic non-residue in the field
  let ur_square = r.square().double();

  /*
    We know this is non-zero as:

    ```sage
    p = 2**255 - 19
    Mod((p - 1) * inverse_mod(2, p), p).is_square() == False
    ```
  */
  let one_plus_ur_square = Field25519::ONE.add(ur_square);
  let one_plus_ur_square_inv = one_plus_ur_square.inv();
  let upsilon = NEGATIVE_A.mul(one_plus_ur_square_inv);
  /*
    Quoting section 5.5,
    "then \epsilon = 1 and x = \upsilon. Otherwise \epsilon = -1, x = \upsilon u r^2"

    Whereas in the specification present in Section 5.2, the expansion of the `u` coordinate when
    `\epsilon = -1` is `-\upsilon - A`. Per Section 5.2, in the "Second case",
    `= -\upsilon - A = \upsilon u r^2`. These two values are equivalent, yet the negation and
    subtract outperform a multiplication.
  */
  let other_candidate = upsilon.neg().sub(A);

  (upsilon, other_candidate)
}

const fn curve_equation(u: Field25519) -> Field25519 {
  u.add(A).mul(u.square()).add(u)
}

const fn const_select(a: Field25519, b: Field25519, choice: u8) -> Field25519 {
  if choice != 0 {
    b
  } else {
    a
  }
}

pub(crate) const fn const_map(bytes: [u8; 32]) -> [u8; 32] {
  let (u, v, epsilon) = {
    let r = Field25519::reduce(U256::from_le_slice(
      &keccak_const::Keccak256::new().update(&bytes).finalize(),
    ));
    let (upsilon, other_candidate) = candidate_u_coordinates(r);
    let upsilon_v = curve_equation(upsilon).sqrt();
    let epsilon = upsilon_v.is_some() as u8;
    if epsilon == 1 {
      (upsilon, upsilon_v.expect("`is_some` was `true`"), epsilon)
    } else {
      (
        other_candidate,
        curve_equation(other_candidate)
          .sqrt()
          .expect("one of these options will be a quadratic residue"),
        epsilon,
      )
    }
  };

  // Map to Ed25519
  let mut x = {
    let x_candidate = SQRT_NEG_A_2.mul(u.mul(v.inv()));
    // If the parity of our candidate is distinct from epsilon, negate it
    const_select(
      x_candidate,
      x_candidate.neg(),
      ((x_candidate.retrieve().as_limbs()[0].0 % 2) as u8) ^ epsilon,
    )
  };
  let mut y = u.sub(Field25519::ONE).mul(u.add(Field25519::ONE).inv());
  let mut z = Field25519::ONE;

  // Clear the cofactor
  // dbl-2008-hwcd, optimized for `a = -1`
  let mut i = 0;
  while i < 3 {
    let a = x.square();
    let b = y.square();
    let c = (if i == 0 { z } else { z.square() }).double();
    let d = a.neg();
    let e = x.add(y).square().sub(a).sub(b);
    let g = d.add(b);
    let f = g.sub(c);
    let h = d.sub(b);
    x = e.mul(f);
    y = g.mul(h);
    z = f.mul(g);

    i += 1;
  }

  let z = z.inv();
  let x = x.mul(z);
  let y = y.mul(z);

  // Encode the result
  let y = y.retrieve();
  let mut res = y.to_le_bytes();
  res[31] |= ((x.retrieve().as_limbs()[0].0 % 2) as u8) << 7;
  res
}
