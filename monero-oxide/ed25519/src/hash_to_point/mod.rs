use crypto_bigint::{Limb, U256};

mod field25519;
use field25519::Field25519;

use crate::CompressedPoint;

/*
  Curve25519 is a Montgomery curve with equation `v^2 = u^3 + 486662 u^2 + u`.

  A Curve25519 point `(u, v)` may be mapped to an Ed25519 point `(x, y)` with the map
  `(sqrt(-(A + 2)) u / v, (u - 1) / (u + 1))`.
*/
const A_LIMB: Limb = Limb(486662);
const A: Field25519 = Field25519::reduce(U256::from_u64(486662));

const SQRT_NEG_A_2: Field25519 = A.add(Field25519::reduce(U256::from_u8(2))).neg().sqrt().unwrap();

const fn batch_invert<const N: usize>(to_invert: &mut [Field25519; N], scratch: &mut [Field25519]) {
  scratch[0] = to_invert[0];
  unsafe {
    let mut scratch = &raw mut scratch[1];
    let mut to_invert = &raw mut to_invert[1];
    let mut i = 1;
    while i < N {
      *scratch = (*scratch.offset(-1)).mul(*to_invert);
      scratch = scratch.offset(1);
      to_invert = to_invert.offset(1);
      i = i.wrapping_add(1);
    }
  }
  let mut accum = scratch[N.wrapping_sub(1)].inv();

  unsafe {
    let mut i = N.wrapping_sub(1);
    let mut scratch = &raw mut scratch[i];
    let mut to_invert = &raw mut to_invert[i];
    while i > 0 {
      scratch = scratch.offset(-1);
      let res_i = accum.mul(*scratch);
      accum = accum.mul(*to_invert);
      *to_invert = res_i;
      to_invert = to_invert.offset(-1);
      i = i.wrapping_sub(1);
    }
  }
  to_invert[0] = accum;
}

const fn curve_equation(u: Field25519) -> Field25519 {
  u.add_limb(A_LIMB).mul(u.square()).add(u)
}

pub(crate) const fn const_map_batch<const N: usize, const TWO_N: usize>(
  mut preimages: [[u8; 32]; N],
) -> [CompressedPoint; N] {
  let mut scratch =
    unsafe { core::mem::MaybeUninit::<[Field25519; TWO_N]>::zeroed().assume_init() };

  let mut one_plus_ur_square_inv =
    unsafe { core::mem::MaybeUninit::<[Field25519; N]>::zeroed().assume_init() };
  {
    unsafe {
      let mut preimages = &raw const preimages[0];
      let mut one_plus_ur_square_inv = &raw mut one_plus_ur_square_inv[0];
      let mut i = 0;
      while i < N {
        let r = Field25519::reduce(U256::from_le_slice(
          &keccak_const::Keccak256::new().update(&*preimages).finalize(),
        ));
        preimages = preimages.offset(1);
        let ur_square = r.square().double();
        *one_plus_ur_square_inv = ur_square.add_one();
        one_plus_ur_square_inv = one_plus_ur_square_inv.offset(1);

        i = i.wrapping_add(1);
      }
    }

    batch_invert(&mut one_plus_ur_square_inv, &mut scratch);
  }

  let mut u_epsilon =
    unsafe { core::mem::MaybeUninit::<[(Field25519, u8); N]>::zeroed().assume_init() };
  let mut x_and_y_denom =
    unsafe { core::mem::MaybeUninit::<[Field25519; TWO_N]>::zeroed().assume_init() };
  unsafe {
    let mut one_plus_ur_square_inv = &raw mut one_plus_ur_square_inv[0];
    let mut u_epsilon = &raw mut u_epsilon[0];
    let mut x_and_y_denom = &raw mut x_and_y_denom[0];
    let mut i = 0;
    while i < N {
      let upsilon = (*one_plus_ur_square_inv).mul_limb(A_LIMB).neg();
      one_plus_ur_square_inv = one_plus_ur_square_inv.offset(1);

      let (u_i, epsilon_i);
      (u_i, *x_and_y_denom, epsilon_i) = if let Some(upsilon_v) = curve_equation(upsilon).sqrt() {
        (upsilon, upsilon_v, 1)
      } else {
        let other_candidate = upsilon.add_limb(A_LIMB).neg();
        (
          other_candidate,
          curve_equation(other_candidate)
            .sqrt()
            .expect("one of these options will be a quadratic residue"),
          0,
        )
      };
      *x_and_y_denom.add(N) = u_i.add_one();
      x_and_y_denom = x_and_y_denom.offset(1);
      *u_epsilon = (u_i, epsilon_i);
      u_epsilon = u_epsilon.offset(1);

      i = i.wrapping_add(1);
    }
  }

  // Map to Ed25519
  batch_invert(&mut x_and_y_denom, &mut scratch);
  let mut xy =
    unsafe { core::mem::MaybeUninit::<[(Field25519, Field25519); N]>::zeroed().assume_init() };
  // Re-use the scratch space from the no-longer-used `one_plus_ur_square`
  let z = &mut one_plus_ur_square_inv;
  unsafe {
    let mut z = &raw mut z[0];
    let mut u_epsilon = &raw const u_epsilon[0];
    let mut x_and_y_denom = &raw mut x_and_y_denom[0];
    let mut xy = &raw mut xy[0];
    let mut i = 0;
    while i < N {
      let (u_i, epsilon_i) = *u_epsilon;
      u_epsilon = u_epsilon.offset(1);
      let mut x_i = {
        let x_candidate = SQRT_NEG_A_2.mul(u_i.mul(*x_and_y_denom));
        // If the parity of our candidate is distinct from epsilon, negate it
        if ((x_candidate.retrieve().as_limbs()[0].0 % 2) as u8) != epsilon_i {
          x_candidate.neg()
        } else {
          x_candidate
        }
      };
      let mut y_i = u_i.sub_one().mul(*x_and_y_denom.add(N));
      x_and_y_denom = x_and_y_denom.offset(1);
      let mut z_i = Field25519::ONE;

      // Clear the cofactor
      // dbl-2008-hwcd, optimized for `a = -1`
      {
        let mut i = 0usize;
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

          i = i.wrapping_add(1);
        }
      }

      *xy = (x_i, y_i);
      xy = xy.offset(1);
      *z = z_i;
      z = z.offset(1);

      i = i.wrapping_add(1);
    }
  }

  // Normalize, encode these points
  batch_invert(z, &mut scratch);
  let mut res = unsafe { *(&raw mut preimages as *mut [CompressedPoint; N]) };
  unsafe {
    let mut z = &raw mut z[0];
    let mut xy = &raw mut xy[0];
    let mut res = &raw mut res[0];
    let mut i = 0;
    while i < N {
      let z_i = *z;
      z = z.offset(1);
      let (x, y) = *xy;
      xy = xy.offset(1);
      let x = x.mul(z_i);
      let y = y.mul(z_i);
      // Encode the result
      let y = y.retrieve();
      let mut this = y.to_le_bytes();
      this[31] |= ((x.retrieve().as_limbs()[0].0 % 2) as u8) << 7;
      *res = CompressedPoint(this);
      res = res.offset(1);

      i = i.wrapping_add(1);
    }
  }

  res
}
