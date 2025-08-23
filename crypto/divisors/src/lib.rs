#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
#![allow(non_snake_case)]

use barycentric::Interpolator;
use divisor::{Divisor, SmallDivisor};
use inversion::BatchInverse;
use std_shims::{vec, vec::Vec};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, CtOption};
use zeroize::{Zeroize, ZeroizeOnDrop};
mod barycentric;
mod divisor;
mod ec;
mod inversion;
mod sizes;

pub use ec::{Curve, Projective, XyPoint};
use group::{
  ff::{Field, PrimeField, PrimeFieldBits},
  Group,
};

mod poly;
pub use poly::Poly;

#[cfg(test)]
mod tests;

/// A curve usable with this library.
pub trait DivisorCurve: Group + ConstantTimeEq + ConditionallySelectable + Zeroize {
  /// An element of the field this curve is defined over.
  type FieldElement: Zeroize + PrimeField + ConditionallySelectable;
  /// Alternative point representation for models where `DivisorCurve::to_xy` is expensive.
  /// In most cases, `Self` will be enough. Most of the rest can use `ec::Projective`.
  type XyPoint: XyPoint<Self::FieldElement>;

  /// The A in the curve equation y^2 = x^3 + A x + B.
  fn a() -> Self::FieldElement;
  /// The B in the curve equation y^2 = x^3 + A x + B.
  fn b() -> Self::FieldElement;

  /// Precomputes necessary values for optimal interpolation.
  #[allow(non_snake_case)]
  fn PRECOMPUTE() -> Precomp<Self::FieldElement>;

  /// Provides the curve params, same as calling `Self::a` and `Self::b`.
  fn curve() -> Curve<Self::FieldElement> {
    Curve { a: Self::a(), b: Self::b() }
  }

  /// y^2 - x^3 - A x - B
  ///
  /// Section 2 of the security proofs define this modulus.
  ///
  /// This MUST NOT be overriden.
  // TODO: Move to an extension trait
  fn divisor_modulus() -> Poly<Self::FieldElement> {
    Poly {
      // 0 y**1, 1 y*2
      y_coefficients: vec![Self::FieldElement::ZERO, Self::FieldElement::ONE],
      yx_coefficients: vec![],
      x_coefficients: vec![
        // - A x
        -Self::a(),
        // 0 x^2
        Self::FieldElement::ZERO,
        // - x^3
        -Self::FieldElement::ONE,
      ],
      // - B
      zero_coefficient: -Self::b(),
    }
  }

  /// Convert a point to its x and y coordinates.
  ///
  /// Returns None if passed the point at infinity.
  ///
  /// This function may run in time variable to if the point is the identity.
  fn to_xy(point: Self) -> Option<(Self::FieldElement, Self::FieldElement)>;
  /// Like `to_xy`, but it may assume no point is the identity, which
  /// must be ensured by the caller.
  fn to_xy_batched(points: &[Self]) -> Vec<[Self::FieldElement; 2]> {
    points.iter().cloned().map(Self::to_xy).map(Option::unwrap).map(|(x, y)| [x, y]).collect()
  }
}

/// Calculate the slope and intercept between two points.
///
/// This function panics when `a @ infinity`, `b @ infinity`, `a == b`, or when `a == -b`.
#[allow(dead_code)]
pub(crate) fn slope_intercept<C: DivisorCurve>(a: C, b: C) -> (C::FieldElement, C::FieldElement) {
  let (ax, ay) = C::to_xy(a).unwrap();
  debug_assert_eq!(C::divisor_modulus().eval(ax, ay), C::FieldElement::ZERO);
  let (bx, by) = C::to_xy(b).unwrap();
  debug_assert_eq!(C::divisor_modulus().eval(bx, by), C::FieldElement::ZERO);
  let slope = (by - ay) *
    Option::<C::FieldElement>::from((bx - ax).invert())
      .expect("trying to get slope/intercept of points sharing an x coordinate");
  let intercept = by - (slope * bx);
  debug_assert!(bool::from((ay - (slope * ax) - intercept).is_zero()));
  debug_assert!(bool::from((by - (slope * bx) - intercept).is_zero()));
  (slope, intercept)
}

type Xy<C> = (<C as DivisorCurve>::FieldElement, <C as DivisorCurve>::FieldElement);

/// The x of 2 points, to build (x - a.x)(x - a.x)
struct Denom<C: DivisorCurve> {
  ax: CtOption<C::FieldElement>,
  bx: CtOption<C::FieldElement>,
}

/// Computes all (slope, intercept) pairs, batching inverses.
/// Returns a.x and b.x too needed to build denominators laters.
fn slopes_and_denoms<C: DivisorCurve>(
  a: Vec<Xy<C>>,
  b: Vec<C::XyPoint>,
) -> Vec<[C::FieldElement; 2]> {
  assert_eq!(a.len(), b.len());
  let b: Vec<Xy<C>> = C::XyPoint::to_xy_batched(b);
  let mut diffs: Vec<C::FieldElement> = a
    .iter()
    .zip(b.iter())
    .map(|(a, b)| {
      let (ax, bx) = (a.0, b.0);
      bx - ax
    })
    .collect();

  BatchInverse::invert_slice(diffs.as_mut_slice());

  a.into_iter()
    .zip(b)
    .zip(diffs)
    .map(|((a, b), diff)| {
      let (ax, ay) = a;
      let (bx, by) = b;

      let slope = (by - ay) * diff;
      let intercept = by - (slope * bx);
      debug_assert!(bool::from((ay - (slope * ax) - intercept).is_zero()));
      debug_assert!(bool::from((by - (slope * bx) - intercept).is_zero()));
      [slope, intercept]
    })
    .collect()
}

/// Data required to compute lines and which can be computed optimally
/// without batching, which is up to slope computation.
/// Consists of `a` and `b` to computed the slope, and a few `Choice` to
/// build the correct line.
struct LineArgs<C: DivisorCurve> {
  // a is the same value as the input, no need to return it.
  // a: C,
  b: C::XyPoint,
  /// This line is always the same, only the Choice is needed.
  both_are_identity: Choice,
  /// the choice corrsponding to the case, and the constant coefficient
  /// which is the only variable value of the line. As x and y are 0 and 1.
  identity_or_inverse: (Choice, C::FieldElement),
}

/// First half of `line`, receives a.x to avoid computing to_xy().
/// Computes up to before the call to `slope_intercept`.
/// Relevant differences are commented,`line` is left as main documentation,
/// as the general computation is the same, just batching friendly.
fn line_args<C: DivisorCurve>(
  a: C::XyPoint,
  b: C::XyPoint,
  a_x: C::FieldElement,
  b_x: C::FieldElement,
  gen: &C::XyPoint,
  curve: &Curve<C::FieldElement>,
) -> LineArgs<C> {
  let a_is_identity = a.is_identity();
  let b_is_identity = b.is_identity();

  // This line is a constant that can be computed later
  let both_are_identity = a_is_identity & b_is_identity;

  let one_is_identity = a_is_identity | b_is_identity;

  let additive_inverses = a.ct_eq(&-b);
  let one_is_identity_or_additive_inverses = one_is_identity | additive_inverses;
  let if_one_is_identity_or_additive_inverses = {
    let a = <_>::conditional_select(&a, gen, both_are_identity);
    let x = <_>::conditional_select(&a_x, &b_x, a.is_identity());
    // only this is needed to construct the line later.
    -x
  };

  let a = <_>::conditional_select(&a, gen, a_is_identity);
  let b = <_>::conditional_select(&b, gen, b_is_identity);
  let b = <_>::conditional_select(&b, &a.double(curve), additive_inverses);
  let b = <_>::conditional_select(&b, &-a.double(curve), a.ct_eq(&b));

  let identity_or_inverse =
    (one_is_identity_or_additive_inverses, if_one_is_identity_or_additive_inverses);
  LineArgs { b, both_are_identity, identity_or_inverse }
}

/// Finish line from (slope, intercept) choices for the
/// particular type of line.
fn finish_line<F: PrimeField>(
  slope: F,
  intercept: F,
  both_are_identity: Choice,
  identity_or_inverse: (Choice, F),
) -> SmallDivisor<F> {
  // for case of different, non indentity points.
  let mut res = SmallDivisor::new((-slope, -intercept), F::ONE);

  let (one_is_identity_or_additive_inverses, constant_term) = identity_or_inverse;
  // for the constant line case.
  let if_one_is_identity_or_additive_inverses = SmallDivisor::new((F::ONE, constant_term), F::ZERO);

  res = <_>::conditional_select(
    &res,
    &if_one_is_identity_or_additive_inverses,
    one_is_identity_or_additive_inverses,
  );

  // for the 0 + 0 case.
  let if_both_are_identity = SmallDivisor::new((F::ZERO, F::ONE), F::ZERO);

  <_>::conditional_select(&res, &if_both_are_identity, both_are_identity)
}

/// Computes all lines, batching expensive operations.
fn lines_and_denoms<C: DivisorCurve>(
  points: &[C::XyPoint],
  curve: &Curve<C::FieldElement>,
) -> Vec<(SmallDivisor<C::FieldElement>, Denom<C>)> {
  // all the pairs of points from which lines will be created.
  let pairs: Vec<[C::XyPoint; 2]> = {
    let mut pairs: Vec<[C::XyPoint; 2]> = Vec::new();
    let mut divs: Vec<C::XyPoint> = Vec::new();

    let mut iter = points.iter().copied();
    while let Some(a) = iter.next() {
      let b = iter.next();
      pairs.push([a, b.unwrap_or(-a)]);
      let div = match b {
        Some(b) => C::XyPoint::add(a, b, curve),
        None => a,
      };
      divs.push(div);
    }

    while divs.len() > 1 {
      let mut next_divs = Vec::with_capacity(divs.len() / 2 + 1);
      // If there's an odd amount of divisors, carry the odd one out to the next iteration
      if (divs.len() % 2) == 1 {
        next_divs.push(divs.pop().unwrap());
      }

      while let Some(a) = divs.pop() {
        let b = divs.pop().unwrap();
        pairs.push([a, b]);
        next_divs.push(C::XyPoint::add(a, b, curve));
      }
      divs = next_divs;
    }
    pairs
  };

  let gen = C::generator();
  let gen = C::to_xy(gen).unwrap();
  let gen = C::XyPoint::from_affine(gen.0, gen.1);
  let a: Vec<C::XyPoint> = pairs
    .iter()
    .map(|[a, _]| {
      let is_identity = a.is_identity();
      <_>::conditional_select(a, &gen, is_identity)
    })
    .collect();
  let b: Vec<C::XyPoint> = pairs
    .iter()
    .map(|[_, b]| {
      let is_identity = b.is_identity();
      <_>::conditional_select(b, &gen, is_identity)
    })
    .collect();

  type Xy<C> = (<C as DivisorCurve>::FieldElement, <C as DivisorCurve>::FieldElement);

  // `slopes_and_denoms` expects the "a" and "b" from `line_args`,
  // but a remains the same as this. As such, it can be reused
  // and doesn't need to be in the output of `line_args`
  let a_xy: Vec<Xy<C>> = C::XyPoint::to_xy_batched(a.clone());
  // This one may change, and as such it is only used as an input for
  // `line_args`.
  let b_xy: Vec<Xy<C>> = C::XyPoint::to_xy_batched(b);

  let (line_args_and_denom, b): (Vec<_>, Vec<C::XyPoint>) = pairs
    .into_iter()
    .zip(&a_xy)
    .zip(b_xy)
    .map(|((pair, a_xy), b_xy)| {
      let (a_x, _) = a_xy;
      let ax = CtOption::new(*a_x, !pair[0].is_identity());
      let (b_x, _) = b_xy;
      let bx = CtOption::new(b_x, !pair[1].is_identity());
      let denom = Denom { ax, bx };
      let [a, b] = pair;
      let args: LineArgs<C> = line_args(a, b, *a_x, b_x, &gen, curve);
      // a is the same we have, this one can be discarded.
      let LineArgs { b, both_are_identity, identity_or_inverse } = args;
      let args = (both_are_identity, identity_or_inverse);
      ((args, denom), b)
    })
    .unzip();

  let slopes = slopes_and_denoms::<C>(a_xy, b);

  line_args_and_denom
    .into_iter()
    .zip(slopes)
    .map(|((args, denom), slope)| {
      let [slope, intercept] = slope;
      let (both_are_identity, identity_or_inverse) = args;
      let line = finish_line(slope, intercept, both_are_identity, identity_or_inverse);
      (line, denom)
    })
    .collect()
}

/// Create a divisor interpolating the following points.
///
/// Returns None if:
///   - No points were passed in
///   - The points don't sum to the point at infinity
///   - A passed in point was the point at infinity
///
/// If the arguments were valid, this function executes in an amount of time constant to the amount
/// of points.
#[allow(clippy::new_ret_no_self)]
pub fn new_divisor<C: DivisorCurve>(
  points: &[C::XyPoint],
  interpolaror: &Interpolator<C::FieldElement>,
  curve: &Curve<C::FieldElement>,
) -> Option<Poly<C::FieldElement>> {
  // No points were passed in, this is the point at infinity, or the single point isn't infinity
  // and accordingly doesn't sum to infinity. All three cause us to return None
  // Checks a bit other than the first bit is set, meaning this is >= 2
  let mut invalid_args = (points.len() & (!1)).ct_eq(&0);
  // The points don't sum to the point at infinity
  let sum = points.iter().cloned().reduce(|a, b| C::XyPoint::add(a, b, curve)).unwrap();
  assert!(bool::from(sum.is_identity()));
  invalid_args |= !sum.is_identity();
  // A point was the point at identity
  for point in points {
    invalid_args |= point.is_identity();
  }
  if bool::from(invalid_args) {
    None?;
  }

  let mut all_lines = lines_and_denoms::<C>(points, curve).into_iter();
  let points_len = points.len();

  let modulus = Divisor::compute_modulus(C::a(), C::b(), EVALS);
  // Create the initial set of divisors
  let mut divs = vec![];

  for _ in 0 .. (points_len / 2 + points_len % 2) {
    let line = all_lines.next().unwrap().0;
    let line: Divisor<C::FieldElement> = Divisor::from_small(line, modulus.clone());
    divs.push(line);
  }

  // Our Poly algorithm is leaky and will create an excessive amount of y x**j and x**j
  // coefficients which are zero, yet as our implementation is constant time, still come with
  // an immense performance cost. This code truncates the coefficients we know are zero.
  let trim = |divisor: &mut Poly<_>, points_len: usize| {
    // We should only be trimming divisors reduced by the modulus
    debug_assert!(divisor.yx_coefficients.len() <= 1);
    if divisor.yx_coefficients.len() == 1 {
      let truncate_to = ((points_len + 1) / 2).saturating_sub(2);
      #[cfg(debug_assertions)]
      for p in truncate_to .. divisor.yx_coefficients[0].len() {
        debug_assert_eq!(divisor.yx_coefficients[0][p], <C::FieldElement as Field>::ZERO);
      }
      divisor.yx_coefficients[0].truncate(truncate_to);
    }
    {
      let truncate_to = points_len / 2;
      #[cfg(debug_assertions)]
      for p in truncate_to .. divisor.x_coefficients.len() {
        debug_assert_eq!(divisor.x_coefficients[p], <C::FieldElement as Field>::ZERO);
      }
      divisor.x_coefficients.truncate(truncate_to);
    }
  };

  // Pair them off until only one remains
  while divs.len() > 1 {
    let mut next_divs = vec![];
    // If there's an odd amount of divisors, carry the odd one out to the next iteration
    if (divs.len() % 2) == 1 {
      next_divs.push(divs.pop().unwrap());
    }

    while let Some(a_div) = divs.pop() {
      let b_div = divs.pop().unwrap();

      // Merge the two divisors
      // line connecting both divisors
      let (line, denom) = all_lines.next().unwrap();
      let Denom { ax, bx } = denom;
      let denom = (ax, bx);
      let merged = Divisor::merge([a_div, b_div], line, denom);
      next_divs.push(merged);
    }

    divs = next_divs;
  }

  // Return the unified divisor
  let divisor = divs.remove(0);
  let mut divisor = divisor_to_poly::<C>(divisor, interpolaror);
  trim(&mut divisor, points_len);
  Some(divisor)
}

/// N necessary values for optimal interpolation which should be ideal for most curves
pub const EVALS: usize = 130;

/// Convert divisor from univariate to bivariate representation.
pub fn divisor_to_poly<C: DivisorCurve>(
  divisor: Divisor<C::FieldElement>,
  interpolator: &Interpolator<C::FieldElement>,
) -> Poly<C::FieldElement> {
  let [mut a, mut b] = divisor.interpolate(interpolator);
  let zero_coefficient = a[0];
  a.remove(0);
  let x_coefficients = a;
  let y_coefficients = vec![b[0]];
  b.remove(0);
  let yx_coefficients = vec![b];

  Poly { y_coefficients, yx_coefficients, x_coefficients, zero_coefficient }
}

/// Necessary values for optimal interpolation.
pub type Precomp<F> = Interpolator<F>;

/// The decomposition of a scalar.
///
/// The decomposition ($d$) of a scalar ($s$) has the following two properties:
///
/// - $\sum^{\mathsf{NUM_BITS} - 1}_{i=0} d_i * 2^i = s$
/// - $\sum^{\mathsf{NUM_BITS} - 1}_{i=0} d_i = \mathsf{NUM_BITS}$
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ScalarDecomposition<F: Zeroize + PrimeFieldBits> {
  scalar: F,
  decomposition: Vec<u64>,
}

impl<F: Zeroize + PrimeFieldBits> ScalarDecomposition<F> {
  /// Decompose a non-zero scalar.
  ///
  /// Returns `None` if the scalar is zero.
  ///
  /// This function is constant time if the scalar is non-zero.
  pub fn new(scalar: F) -> Option<Self> {
    if bool::from(scalar.is_zero()) {
      None?;
    }

    /*
      We need the sum of the coefficients to equal F::NUM_BITS. The scalar's bits will be less than
      F::NUM_BITS. Accordingly, we need to increment the sum of the coefficients without
      incrementing the scalar represented. We do this by finding the highest non-0 coefficient,
      decrementing it, and increasing the immediately less significant coefficient by 2. This
      increases the sum of the coefficients by 1 (-1+2=1).
    */

    let num_bits = u64::from(F::NUM_BITS);

    // Obtain the bits of the scalar
    let num_bits_usize = usize::try_from(num_bits).unwrap();
    let mut decomposition = vec![0; num_bits_usize];
    for (i, bit) in scalar.to_le_bits().into_iter().take(num_bits_usize).enumerate() {
      let bit = u64::from(u8::from(bit));
      decomposition[i] = bit;
    }

    // The following algorithm only works if the value of the scalar exceeds num_bits
    // If it isn't, we increase it by the modulus such that it does exceed num_bits
    {
      let mut less_than_num_bits = Choice::from(0);
      for i in 0 .. num_bits {
        less_than_num_bits |= scalar.ct_eq(&F::from(i));
      }
      let mut decomposition_of_modulus = vec![0; num_bits_usize];
      // Decompose negative one
      for (i, bit) in (-F::ONE).to_le_bits().into_iter().take(num_bits_usize).enumerate() {
        let bit = u64::from(u8::from(bit));
        decomposition_of_modulus[i] = bit;
      }
      // Increment it by one
      decomposition_of_modulus[0] += 1;

      // Add the decomposition onto the decomposition of the modulus
      for i in 0 .. num_bits_usize {
        let new_decomposition = <_>::conditional_select(
          &decomposition[i],
          &(decomposition[i] + decomposition_of_modulus[i]),
          less_than_num_bits,
        );
        decomposition[i] = new_decomposition;
      }
    }

    // Calculcate the sum of the coefficients
    let mut sum_of_coefficients: u64 = 0;
    for decomposition in &decomposition {
      sum_of_coefficients += *decomposition;
    }

    /*
      Now, because we added a log2(k)-bit number to a k-bit number, we may have our sum of
      coefficients be *too high*. We attempt to reduce the sum of the coefficients accordingly.

      This algorithm is guaranteed to complete as expected. Take the sequence `222`. `222` becomes
      `032` becomes `013`. Even if the next coefficient in the sequence is `2`, the third
      coefficient will be reduced once and the next coefficient (`2`, increased to `3`) will only
      be eligible for reduction once. This demonstrates, even for a worst case of log2(k) `2`s
      followed by `1`s (as possible if the modulus is a Mersenne prime), the log2(k) `2`s can be
      reduced as necessary so long as there is a single coefficient after (requiring the entire
      sequence be at least of length log2(k) + 1). For a 2-bit number, log2(k) + 1 == 2, so this
      holds for any odd prime field.

      To fully type out the demonstration for the Mersenne prime 3, with scalar to encode 1 (the
      highest value less than the number of bits):

      10 - Little-endian bits of 1
      21 - Little-endian bits of 1, plus the modulus
      02 - After one reduction, where the sum of the coefficients does in fact equal 2 (the target)
    */
    {
      let mut log2_num_bits = 0;
      while (1 << log2_num_bits) < num_bits {
        log2_num_bits += 1;
      }

      for _ in 0 .. log2_num_bits {
        // If the sum of coefficients is the amount of bits, we're done
        let mut done = sum_of_coefficients.ct_eq(&num_bits);

        for i in 0 .. (num_bits_usize - 1) {
          let should_act = (!done) & decomposition[i].ct_gt(&1);
          // Subtract 2 from this coefficient
          let amount_to_sub = <_>::conditional_select(&0, &2, should_act);
          decomposition[i] -= amount_to_sub;
          // Add 1 to the next coefficient
          let amount_to_add = <_>::conditional_select(&0, &1, should_act);
          decomposition[i + 1] += amount_to_add;

          // Also update the sum of coefficients
          sum_of_coefficients -= <_>::conditional_select(&0, &1, should_act);

          // If we updated the coefficients this loop iter, we're done for this loop iter
          done |= should_act;
        }
      }
    }

    for _ in 0 .. num_bits {
      // If the sum of coefficients is the amount of bits, we're done
      let mut done = sum_of_coefficients.ct_eq(&num_bits);

      // Find the highest coefficient currently non-zero
      for i in (1 .. decomposition.len()).rev() {
        // If this is non-zero, we should decrement this coefficient if we haven't already
        // decremented a coefficient this round
        let is_non_zero = !(0.ct_eq(&decomposition[i]));
        let should_act = (!done) & is_non_zero;

        // Update this coefficient and the prior coefficient
        let amount_to_sub = <_>::conditional_select(&0, &1, should_act);
        decomposition[i] -= amount_to_sub;

        let amount_to_add = <_>::conditional_select(&0, &2, should_act);
        // i must be at least 1, so i - 1 will be at least 0 (meaning it's safe to index with)
        decomposition[i - 1] += amount_to_add;

        // Also update the sum of coefficients
        sum_of_coefficients += <_>::conditional_select(&0, &1, should_act);

        // If we updated the coefficients this loop iter, we're done for this loop iter
        done |= should_act;
      }
    }
    debug_assert!(bool::from(decomposition.iter().sum::<u64>().ct_eq(&num_bits)));

    Some(ScalarDecomposition { scalar, decomposition })
  }

  /// The scalar.
  pub fn scalar(&self) -> &F {
    &self.scalar
  }

  /// The decomposition of the scalar.
  pub fn decomposition(&self) -> &[u64] {
    &self.decomposition
  }

  /// Convert to (x,y) and then into the second representation to later avoid
  /// calling the potentially expensive `C::to_xy` many times.
  fn to_xy<C>(p: C) -> C::XyPoint
  where
    C: DivisorCurve<Scalar = F>,
  {
    let (x, y) = C::to_xy(p).unwrap();
    C::XyPoint::from_affine(x, y)
  }

  /// A divisor to prove a scalar multiplication.
  ///
  /// The divisor will interpolate $-(s \cdot G)$ with $d_i$ instances of $2^i \cdot G$.
  ///
  /// This function executes in constant time with regards to the scalar.
  ///
  /// This function MAY panic if the generator is the point at infinity.
  pub fn scalar_mul_divisor<C: Zeroize + DivisorCurve<Scalar = F>>(
    &self,
    generator: C,
  ) -> Poly<C::FieldElement> {
    // 1 is used for the resulting point, NUM_BITS is used for the decomposition, and then we store
    // one additional index in a usize for the points we shouldn't write at all (hence the +2)
    let _ = usize::try_from(<C::Scalar as PrimeField>::NUM_BITS + 2)
      .expect("NUM_BITS + 2 didn't fit in usize");
    // let identity = Self::to_xy(C::identity());
    let identity = C::XyPoint::IDENTITY;
    let mut divisor_points = vec![identity; (<C::Scalar as PrimeField>::NUM_BITS + 1) as usize];

    // Write the inverse of the resulting point
    divisor_points[0] = Self::to_xy(-generator * self.scalar);
    let mut generator = Self::to_xy(generator);

    let curve = Curve { a: C::a(), b: C::b() };

    // Write the decomposition
    let mut write_above: u64 = 0;
    for coefficient in &self.decomposition {
      // Write the generator to every slot except the slots we have already written to.
      for i in 1 ..= (<C::Scalar as PrimeField>::NUM_BITS as u64) {
        divisor_points[i as usize].conditional_assign(&generator, i.ct_gt(&write_above));
      }

      // Increase the next write start by the coefficient.
      write_above += coefficient;
      generator = generator.double(&curve);
    }

    // Here we may want to construct one based on the number of points.
    // Currently set tot `EVALS` which should be ideal for most curves and
    // scalars.
    let interpolator = C::PRECOMPUTE();

    // Create a divisor out of the points
    let res = new_divisor::<C>(&divisor_points, &interpolator, &curve).unwrap();
    divisor_points.zeroize();
    res
  }
}

#[cfg(any(test, feature = "pasta"))]
mod pasta {
  use crate::DivisorCurve;
  use crate::Projective;
  use crate::{Precomp, Interpolator, EVALS};
  use group::{ff::Field, Curve};
  use pasta_curves::{
    arithmetic::{Coordinates, CurveAffine},
    Ep, Eq, Fp, Fq,
  };
  use std_shims::sync::OnceLock;

  static FP_PRECOMPUTE_CELL: OnceLock<Precomp<Fp>> = OnceLock::new();
  static FQ_PRECOMPUTE_CELL: OnceLock<Precomp<Fq>> = OnceLock::new();

  impl DivisorCurve for Ep {
    type FieldElement = Fp;
    // TODO: using Self may be better
    type XyPoint = Projective<Fp>;

    fn a() -> Self::FieldElement {
      Self::FieldElement::ZERO
    }
    fn b() -> Self::FieldElement {
      Self::FieldElement::from(5u64)
    }

    fn PRECOMPUTE() -> Precomp<Self::FieldElement> {
      FP_PRECOMPUTE_CELL.get_or_init(|| Interpolator::new(EVALS - 1)).clone()
    }

    fn to_xy(point: Self) -> Option<(Self::FieldElement, Self::FieldElement)> {
      Option::<Coordinates<_>>::from(point.to_affine().coordinates())
        .map(|coords| (*coords.x(), *coords.y()))
    }
  }

  impl DivisorCurve for Eq {
    type FieldElement = Fq;
    // TODO: using Self may be better
    type XyPoint = Projective<Fq>;

    fn a() -> Self::FieldElement {
      Self::FieldElement::ZERO
    }
    fn b() -> Self::FieldElement {
      Self::FieldElement::from(5u64)
    }

    fn PRECOMPUTE() -> Precomp<Self::FieldElement> {
      FQ_PRECOMPUTE_CELL.get_or_init(|| Interpolator::new(EVALS - 1)).clone()
    }

    fn to_xy(point: Self) -> Option<(Self::FieldElement, Self::FieldElement)> {
      Option::<Coordinates<_>>::from(point.to_affine().coordinates())
        .map(|coords| (*coords.x(), *coords.y()))
    }
  }
}

mod ed25519 {
  use crate::{Projective, Precomp, Interpolator, EVALS};
  use dalek_ff_group::{EdwardsPoint, FieldElement};
  use group::{
    ff::{Field, PrimeField},
    Group, GroupEncoding,
  };
  use subtle::{Choice, ConditionallySelectable};
  use std_shims::sync::OnceLock;

  static PRECOMPUTE_CELL: OnceLock<Precomp<FieldElement>> = OnceLock::new();

  impl crate::DivisorCurve for EdwardsPoint {
    type FieldElement = FieldElement;
    type XyPoint = Projective<FieldElement>;

    // Wei25519 a/b
    // https://www.ietf.org/archive/id/draft-ietf-lwig-curve-representations-02.pdf E.3
    fn a() -> Self::FieldElement {
      let mut be_bytes =
        hex::decode("2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa984914a144").unwrap();
      be_bytes.reverse();
      let le_bytes = be_bytes;
      Self::FieldElement::from_repr(le_bytes.try_into().unwrap()).unwrap()
    }
    fn b() -> Self::FieldElement {
      let mut be_bytes =
        hex::decode("7b425ed097b425ed097b425ed097b425ed097b425ed097b4260b5e9c7710c864").unwrap();
      be_bytes.reverse();
      let le_bytes = be_bytes;

      Self::FieldElement::from_repr(le_bytes.try_into().unwrap()).unwrap()
    }

    fn PRECOMPUTE() -> Precomp<Self::FieldElement> {
      PRECOMPUTE_CELL.get_or_init(|| Interpolator::new(EVALS - 1)).clone()
    }

    // https://www.ietf.org/archive/id/draft-ietf-lwig-curve-representations-02.pdf E.2
    fn to_xy(point: Self) -> Option<(Self::FieldElement, Self::FieldElement)> {
      if bool::from(point.is_identity()) {
        None?;
      }

      // Extract the y coordinate from the compressed point
      let mut edwards_y = point.to_bytes();
      let x_is_odd = edwards_y[31] >> 7;
      edwards_y[31] &= (1 << 7) - 1;
      let edwards_y = Self::FieldElement::from_repr(edwards_y).unwrap();

      // Recover the x coordinate
      let edwards_y_sq = edwards_y * edwards_y;
      let D = -Self::FieldElement::from(121665u64) *
        Self::FieldElement::from(121666u64).invert().unwrap();
      let mut edwards_x = ((edwards_y_sq - Self::FieldElement::ONE) *
        ((D * edwards_y_sq) + Self::FieldElement::ONE).invert().unwrap())
      .sqrt()
      .unwrap();

      // Negate the x coordinate if the sign doesn't match
      edwards_x = <_>::conditional_select(
        &edwards_x,
        &-edwards_x,
        edwards_x.is_odd() ^ Choice::from(x_is_odd),
      );

      // Calculate the x and y coordinates for Wei25519
      let edwards_y_plus_one = Self::FieldElement::ONE + edwards_y;
      let one_minus_edwards_y = Self::FieldElement::ONE - edwards_y;
      let wei_x = (edwards_y_plus_one * one_minus_edwards_y.invert().unwrap()) +
        (Self::FieldElement::from(486662u64) * Self::FieldElement::from(3u64).invert().unwrap());
      let c =
        (-(Self::FieldElement::from(486662u64) + Self::FieldElement::from(2u64))).sqrt().unwrap();
      let wei_y = c * edwards_y_plus_one * (one_minus_edwards_y * edwards_x).invert().unwrap();
      Some((wei_x, wei_y))
    }
  }
}
