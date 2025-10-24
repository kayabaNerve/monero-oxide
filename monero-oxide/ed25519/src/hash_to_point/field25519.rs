use crypto_bigint::{Limb, Word, U256};

const LAST_LIMB: usize = U256::LIMBS - 1;
const HIGH_BIT: Word = 1 << (Limb::BITS - 1);
const HIGH_TWO_BITS: Word = (1 << (Limb::BITS - 1)) | (1 << (Limb::BITS - 2));
const ALL_BUT_HIGH_BIT: Word = !HIGH_BIT;

const MODULUS: U256 =
  U256::from_be_hex("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");

const INVERTER: crypto_bigint::modular::SafeGcdInverter<
  { U256::LIMBS },
  { (U256::BITS + 64).div_ceil(62) as usize },
> = crypto_bigint::modular::SafeGcdInverter::new(
  &MODULUS.to_odd().expect("2^255 - 19 is odd"),
  &U256::ONE,
);

// (p + 3) // 8
const SQRT_EXP: U256 = MODULUS.shr_vartime(3).wrapping_add(&U256::ONE);
// 2^{(p - 1) // 4}
const Z: Field25519 = Field25519(U256::from_u8(2)).pow(MODULUS.shr_vartime(2));

#[derive(Clone, Copy)]
pub(crate) struct Field25519(U256);
impl Field25519 {
  pub(crate) const ONE: Self = Self(U256::ONE);

  const fn reduce_once(value: U256) -> Self {
    let mut reduced = value;
    let limbs = reduced.as_limbs_mut();

    if (limbs[LAST_LIMB].0 & HIGH_TWO_BITS) == 0 {
      return Self(value);
    }

    let mut i = 0;
    let mut carry = Limb(19);
    while i < U256::LIMBS {
      (limbs[i], carry) = limbs[i].adc(carry, Limb::ZERO);
      i += 1;
    }

    if (limbs[LAST_LIMB].0 & HIGH_BIT) != 0 {
      limbs[LAST_LIMB].0 &= ALL_BUT_HIGH_BIT;
      return Self(reduced);
    }
    Self(value)
  }

  pub(crate) const fn reduce(mut value: U256) -> Self {
    let limbs = value.as_limbs_mut();
    if (limbs[LAST_LIMB].0 & HIGH_BIT) != 0 {
      limbs[LAST_LIMB].0 &= ALL_BUT_HIGH_BIT;
      let mut i = 0;
      let mut carry = Limb(19);
      while i < U256::LIMBS {
        (limbs[i], carry) = limbs[i].adc(carry, Limb::ZERO);
        i += 1;
      }
    }

    Self::reduce_once(value)
  }

  const fn wide_reduce(mut lo: U256, hi: U256) -> Self {
    let lo_limbs = lo.as_limbs_mut();
    let hi = hi.as_limbs();

    let mut i = 0;
    let mut carry = Limb::ZERO;
    while i < U256::LIMBS {
      (lo_limbs[i], carry) = lo_limbs[i].mac(hi[i], Limb(38), carry);
      i += 1;
    }

    let mut result = Self::reduce(lo).0;
    let limbs = result.as_limbs_mut();
    let mut i = 0;
    let mut carry = Limb(carry.0 * 38);
    while i < U256::LIMBS {
      (limbs[i], carry) = limbs[i].adc(Limb::ZERO, carry);
      i += 1;
    }
    Self::reduce_once(result)
  }

  pub(crate) const fn add(&self, other: Self) -> Self {
    let unreduced = self.0.wrapping_add(&other.0);
    Self::reduce_once(unreduced)
  }

  pub(crate) const fn double(&self) -> Self {
    let unreduced = self.0.wrapping_shl(1);
    Self::reduce_once(unreduced)
  }

  pub(crate) const fn neg(mut self) -> Self {
    let limbs = self.0.as_limbs_mut();
    let modulus = MODULUS.as_limbs();
    let mut borrow = Limb::ZERO;
    let mut i = 0;
    while i < U256::LIMBS {
      (limbs[i], borrow) = modulus[i].sbb(limbs[i], borrow);
      i += 1;
    }
    self
  }

  pub(crate) const fn sub(mut self, other: Self) -> Self {
    let limbs = self.0.as_limbs_mut();
    let other = other.0.as_limbs();
    let mut borrow = Limb::ZERO;
    let mut i = 0;
    while i < U256::LIMBS {
      (limbs[i], borrow) = limbs[i].sbb(other[i], borrow);
      i += 1;
    }
    if borrow.0 != 0 {
      self.0 = self.0.wrapping_add(&MODULUS);
    }
    self
  }

  pub(crate) const fn mul(&self, other: Self) -> Self {
    let (lo, hi) = self.0.split_mul(&other.0);
    Self::wide_reduce(lo, hi)
  }
  pub(crate) const fn square(&self) -> Self {
    let (lo, hi) = self.0.square_wide();
    Self::wide_reduce(lo, hi)
  }

  pub(crate) const fn inv(&self) -> Self {
    Self(INVERTER.inv_vartime(&self.0).expect("requested inverse of number without inverse"))
  }

  const fn pow(&self, exp: U256) -> Self {
    let mut result = Self::ONE;
    let mut i = 255;
    while i > 0 {
      if !result.eq(Self::ONE) {
        result = result.square();
      }
      if exp.bit_vartime(i) {
        result = result.mul(*self);
      }
      i -= 1;
    }
    result = result.square();
    if exp.bit_vartime(i) {
      result = result.mul(*self);
    }
    result
  }

  pub(crate) const fn sqrt(&self) -> Option<Self> {
    let y = self.pow(SQRT_EXP);
    if y.mul(y).eq(*self) {
      return Some(y);
    }
    let other = y.mul(Z);
    if other.mul(other).eq(*self) {
      return Some(other);
    }
    None
  }

  pub(crate) const fn eq(&self, other: Self) -> bool {
    let mut eq = true;
    let mut i = 0;
    let limbs = self.0.as_limbs();
    let other = other.0.as_limbs();
    while i < U256::LIMBS {
      eq &= limbs[i].0 == other[i].0;
      i += 1;
    }
    eq
  }

  pub(crate) const fn retrieve(self) -> U256 {
    self.0
  }
}
