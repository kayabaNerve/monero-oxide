use core::{
  ops::{AddAssign, Mul},
  iter::successors,
};
use std_shims::{vec, vec::Vec};

use ff::{Field, PrimeField, BatchInvert};

#[cfg_attr(test, derive(Debug, PartialEq))]
#[derive(Clone)]
struct UnivariatePoly<F>(Vec<F>);

impl<F: Field> AddAssign<&Self> for UnivariatePoly<F> {
  /// Panics if the polynomials are of different lengths.
  fn add_assign(&mut self, rhs: &Self) {
    assert_eq!(self.0.len(), rhs.0.len());
    for i in 0 .. self.0.len() {
      self.0[i] += rhs.0[i];
    }
  }
}

impl<F: Field> Mul<F> for UnivariatePoly<F> {
  type Output = Self;
  fn mul(mut self, scalar: F) -> Self {
    for coeff in &mut self.0 {
      *coeff *= scalar;
    }
    self
  }
}

impl<F: Field> UnivariatePoly<F> {
  #[cfg(test)]
  fn eval(&self, x: F) -> F {
    self.0.iter().rev().fold(F::ZERO, |acc, coeff| (acc * x) + coeff)
  }

  // Mul by `x + c`.
  fn mul_x_c(&mut self, c: F) {
    let coeffs = &mut self.0;
    coeffs.insert(0, F::ZERO);
    for i in 0 .. (coeffs.len() - 1) {
      let q = coeffs[i + 1];
      coeffs[i] += q * c;
    }
  }

  /// Divide the polynomial by `x + c` for given `c`.
  ///
  /// Executes in time variable to the length of the polynomial.
  fn div_x_c(mut self, c: F) -> (Self, F) {
    let coeffs = &mut self.0;
    let len = coeffs.len();
    let Some(mut new_coeff) = coeffs.pop() else {
      return (Self(vec![]), F::ZERO);
    };
    for i in 1 .. len {
      let coeff = coeffs[len - 1 - i];
      coeffs[len - 1 - i] = new_coeff;
      new_coeff = coeff - (new_coeff * c);
    }
    let remainder = new_coeff;
    (self, remainder)
  }
}

struct Weights<F: Field> {
  inverted_weights: Vec<F>,
  l: UnivariatePoly<F>,
}

impl<F: PrimeField> Weights<F> {
  /// P(x) = (x-0)(x-1)(x-2)...(x-domain_size - 1)
  fn l(domain_size: usize) -> UnivariatePoly<F> {
    assert_ne!(domain_size, 0);

    let mut poly = UnivariatePoly(vec![F::ONE]);
    for i in 0 .. domain_size {
      let i: F = F::from(u64::try_from(i).unwrap());
      poly.mul_x_c(-i);
    }
    poly
  }

  fn new(domain_size: usize) -> Self {
    assert_ne!(domain_size, 0);

    let start = Some(-F::ONE);
    let diffs = successors(start, |prev| Some(*prev - F::ONE));
    let diff_products = diffs.scan(F::ONE, |product, diff| {
      *product *= diff;
      Some(*product)
    });
    let mut diff_products: Vec<F> = diff_products.take(domain_size - 1).collect();
    diff_products.reverse();
    diff_products.push(F::ONE);
    let diff_products_right = diff_products.into_iter();

    let diffs = successors(Some(F::ONE), |prev| Some(*prev + F::ONE));
    let diff_products_left = diffs.scan(F::ONE, |product, diff| {
      *product *= diff;
      Some(*product)
    });
    let diff_products_left = [F::ONE].into_iter().chain(diff_products_left);

    let weights: Vec<F> =
      diff_products_left.zip(diff_products_right).map(|(left, right)| left * right).collect();

    let mut inverted_weights = weights.clone();
    (&mut inverted_weights).batch_invert();
    Weights { inverted_weights, l: Self::l(domain_size) }
  }

  fn li(&self, i: usize) -> UnivariatePoly<F> {
    ({
      let i = -F::from(u64::try_from(i).unwrap());
      let (li, rem) = self.l.clone().div_x_c(i);
      // The `l` polynomial is the product of `x - i`, ensuring we can divide out `x - i`
      debug_assert_eq!(rem, F::ZERO);
      li
    }) * self.inverted_weights[i]
  }
}

/// A precomputed box which can perform Lagrange interpolation.
///
/// This box is able to interpolate evaluations of a polynomial to recover the original polynomial.
/// Notably, when this box is constructed, the degree of the output polynomial must be specified,
/// and the amount of evaluations provided MUST exceed the degree of the output polynomial.
#[derive(Clone)]
pub struct Interpolator<F: Field> {
  lagrange_polys: Vec<UnivariatePoly<F>>,
}

impl<F: PrimeField> Interpolator<F> {
  /// Create a new box eligible for Lagrange interpolation.
  ///
  /// This may panic if the degree is `usize::MAX`.
  pub fn new(degree: usize) -> Self {
    let domain_size = degree + 1;
    let weights = Weights::new(domain_size);
    let mut lagrange_polys = Vec::with_capacity(domain_size);
    for i in 0 .. domain_size {
      let li = weights.li(i);
      lagrange_polys.push(li);
    }
    Self { lagrange_polys }
  }

  pub(crate) fn required_evaluations(&self) -> usize {
    self.lagrange_polys.len()
  }

  /// Attempt to reconstruct the original polynomial via interpolation.
  ///
  /// Returns `None` if not enough evaluations were provided to attempt interpolation.
  pub(crate) fn interpolate(&self, evals: &[F]) -> Option<Vec<F>> {
    if evals.len() < self.lagrange_polys.len() {
      None?;
    }

    let poly = vec![F::ZERO; evals.len()];
    let mut poly = UnivariatePoly(poly);
    for (eval, li) in evals.iter().zip(&self.lagrange_polys) {
      for (res, li) in poly.0.iter_mut().zip(&li.0) {
        *res += *li * *eval;
      }
    }

    Some(poly.0)
  }
}

#[test]
fn test_div_x_c() {
  use rand_core::OsRng;
  use dalek_ff_group::Scalar;
  use crate::Poly;

  {
    assert_eq!(
      UnivariatePoly(vec![]).div_x_c(Scalar::random(&mut OsRng)),
      (UnivariatePoly(vec![]), Scalar::ZERO)
    );
  }
  {
    let c0 = Scalar::random(&mut OsRng);
    assert_eq!(
      UnivariatePoly(vec![c0]).div_x_c(Scalar::random(&mut OsRng)),
      (UnivariatePoly(vec![]), c0)
    );
  }
  for i in 2 .. 256 {
    let mut coeffs = UnivariatePoly(vec![Scalar::ZERO; i]);
    for coeff in &mut coeffs.0 {
      *coeff = Scalar::random(&mut OsRng);
    }
    let poly = Poly::<Scalar> {
      zero_coefficient: coeffs.0[0],
      x_coefficients: coeffs.0[1 ..].to_vec(),
      yx_coefficients: vec![],
      y_coefficients: vec![],
    };
    let denom = Scalar::random(&mut OsRng);
    let (coeffs_div, coeffs_rem) = coeffs.div_x_c(denom);
    let (mut poly_div, poly_rem) = poly.div_rem(&Poly {
      zero_coefficient: denom,
      x_coefficients: vec![Scalar::ONE],
      yx_coefficients: vec![],
      y_coefficients: vec![],
    });
    assert_eq!(coeffs_div.0[0], poly_div.zero_coefficient);
    assert_eq!(poly_div.x_coefficients.pop(), Some(Scalar::ZERO));
    assert_eq!(&coeffs_div.0[1 ..], &poly_div.x_coefficients);
    assert!(poly_div.yx_coefficients.is_empty());
    assert!(poly_div.y_coefficients.is_empty());
    assert_eq!(coeffs_rem, poly_rem.zero_coefficient);
    assert!(poly_rem.x_coefficients.is_empty());
    assert!(poly_rem.yx_coefficients.is_empty());
    assert!(poly_rem.y_coefficients.is_empty());
  }
}

#[test]
fn interpolation() {
  use rand_core::OsRng;
  use dalek_ff_group::Scalar;

  for i in 2 .. 256 {
    let mut evals = vec![Scalar::ZERO; i];
    for eval in &mut evals {
      *eval = Scalar::random(&mut OsRng);
    }

    let coeffs = UnivariatePoly(Interpolator::new(i - 1).interpolate(&evals).unwrap());
    for (i, eval) in evals.into_iter().enumerate() {
      assert_eq!(coeffs.eval(Scalar::from(u64::try_from(i).unwrap())), eval);
    }
  }
}
