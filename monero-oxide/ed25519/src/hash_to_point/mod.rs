#![allow(clippy::uninit_assumed_init)]

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

const fn batch_invert<const N: usize>(to_invert: [Field25519; N]) -> [Field25519; N] {
  let mut scratch = unsafe { core::mem::MaybeUninit::<[Field25519; N]>::uninit().assume_init() };
  scratch[0] = to_invert[0];
  let mut i = 1;
  while i < N {
    scratch[i] = scratch[i - 1].mul(to_invert[i]);
    i += 1;
  }
  let mut accum = scratch[N - 1].inv();

  let mut res = unsafe { core::mem::MaybeUninit::<[Field25519; N]>::uninit().assume_init() };
  let mut i = N - 1;
  while i > 0 {
    res[i] = accum.mul(scratch[i - 1]);
    accum = accum.mul(to_invert[i]);

    i -= 1;
  }
  res[0] = accum;

  res
}

const fn curve_equation(u: Field25519) -> Field25519 {
  u.add(A).mul(u.square()).add(u)
}

pub(crate) const fn const_map_batch<const N: usize>(
  preimages: [[u8; 32]; N],
) -> [crate::CompressedPoint; N] {
  let one_plus_ur_square_inv = {
    let mut one_plus_ur_square =
      unsafe { core::mem::MaybeUninit::<[Field25519; N]>::uninit().assume_init() };
    let mut i = 0;
    while i < N {
      let r = Field25519::reduce(U256::from_le_slice(
        &keccak_const::Keccak256::new().update(&preimages[i]).finalize(),
      ));
      let ur_square = r.square().double();
      one_plus_ur_square[i] = ur_square.add_one();

      i += 1;
    }

    batch_invert(one_plus_ur_square)
  };

  let mut u_epsilon =
    unsafe { core::mem::MaybeUninit::<[(Field25519, u8); N]>::uninit().assume_init() };
  let mut v = unsafe { core::mem::MaybeUninit::<[Field25519; N]>::uninit().assume_init() };
  let mut i = 0;
  while i < N {
    let upsilon = NEGATIVE_A.mul(one_plus_ur_square_inv[i]);
    let other_candidate = upsilon.add(A).neg();

    let upsilon_v = curve_equation(upsilon).sqrt();
    let (u_i, epsilon_i);
    (u_i, v[i], epsilon_i) = if let Some(upsilon_v) = upsilon_v {
      (upsilon, upsilon_v, 1)
    } else {
      (
        other_candidate,
        curve_equation(other_candidate)
          .sqrt()
          .expect("one of these options will be a quadratic residue"),
        0,
      )
    };
    u_epsilon[i] = (u_i, epsilon_i);

    i += 1;
  }

  // Map to Ed25519
  let x_denom = batch_invert(v);
  let mut y_denom = unsafe { core::mem::MaybeUninit::<[Field25519; N]>::uninit().assume_init() };
  let mut i = 0;
  while i < N {
    y_denom[i] = u_epsilon[i].0.add_one();
    i += 1;
  }
  let y_denom = batch_invert(y_denom);

  let mut xy =
    unsafe { core::mem::MaybeUninit::<[(Field25519, Field25519); N]>::uninit().assume_init() };
  let mut z = unsafe { core::mem::MaybeUninit::<[Field25519; N]>::uninit().assume_init() };
  let mut i = 0;
  while i < N {
    let (u_i, epsilon_i) = u_epsilon[i];
    let mut x_i = {
      let x_candidate = SQRT_NEG_A_2.mul(u_i.mul(x_denom[i]));
      // If the parity of our candidate is distinct from epsilon, negate it
      if ((x_candidate.retrieve().as_limbs()[0].0 % 2) as u8) != epsilon_i {
        x_candidate.neg()
      } else {
        x_candidate
      }
    };
    let mut y_i = u_i.sub_one().mul(y_denom[i]);
    let mut z_i = Field25519::ONE;

    // Clear the cofactor
    // dbl-2008-hwcd, optimized for `a = -1`
    {
      let mut i = 0;
      while i < 3 {
        let a = x_i.square();
        let b = y_i.square();
        let c = (if i == 0 { z_i } else { z_i.square() }).double();
        let d = a.neg();
        let e = x_i.add(y_i).square().sub(a).sub(b);
        let g = d.add(b);
        let f = g.sub(c);
        let h = d.sub(b);
        x_i = e.mul(f);
        y_i = g.mul(h);
        z_i = f.mul(g);

        i += 1;
      }
    }

    xy[i] = (x_i, y_i);
    z[i] = z_i;

    i += 1;
  }

  // Normalize, encode these points
  let z = batch_invert(z);
  let mut res =
    unsafe { core::mem::MaybeUninit::<[crate::CompressedPoint; N]>::uninit().assume_init() };
  let mut i = 0;
  while i < N {
    let z = z[i];
    let (x, y) = xy[i];
    let x = x.mul(z);
    let y = y.mul(z);
    // Encode the result
    let y = y.retrieve();
    let mut this = y.to_le_bytes();
    this[31] |= ((x.retrieve().as_limbs()[0].0 % 2) as u8) << 7;
    res[i] = crate::CompressedPoint(this);

    i += 1;
  }

  res
}
