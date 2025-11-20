use core::ops::{Add, Sub, Mul};
use std_shims::{vec, vec::Vec, collections::BTreeMap};

use zeroize::Zeroize;

use ciphersuite::group::ff::PrimeField;

use crate::ScalarVector;

/// A reference to a variable usable within linear combinations.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[allow(non_camel_case_types)]
pub enum Variable {
  /// A variable within the left vector of vectors multiplied against each other.
  aL(usize),
  /// A variable within the right vector of vectors multiplied against each other.
  aR(usize),
  /// A variable within the output vector of the left vector multiplied by the right vector.
  aO(usize),
  /// A variable within a Pedersen vector commitment, committed to with a generator from `g` (bold).
  CG {
    /// The commitment being indexed.
    commitment: usize,
    /// The index of the variable.
    index: usize,
  },
  /// A variable within a Pedersen commitment.
  V(usize),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
enum Tag {
  WL,
  WR,
  WO,
  WV,
}

/// A linear combination.
///
/// Specifically, `WL aL + WR aR + WO aO + WCG C_G + WV V + c`.
#[derive(Clone, PartialEq, Eq, Debug)]
#[must_use]
pub struct LinComb<F: PrimeField> {
  /// The highest index within `aL`, `aR`, or `aO` which is used.
  highest_a_index: Option<usize>,
  /// The highest index for a Pedersen vector commitment.
  highest_c_index: Option<usize>,
  /// The highest index for a Pedersen commitment.
  highest_v_index: Option<usize>,

  // Sparse representation of WL/WR/WO/WV
  WLROV: Vec<(Tag, (usize, F))>,
  /// A sparse representation of the vector commitments and the weights for the variables within
  /// them.
  WCG: BTreeMap<usize, Vec<(usize, F)>>,
  c: F,
}

impl<F: Zeroize + PrimeField> Zeroize for LinComb<F> {
  fn zeroize(&mut self) {
    self.highest_a_index.zeroize();
    self.highest_c_index.zeroize();
    self.highest_v_index.zeroize();
    self.WLROV.zeroize();
    for WCG in self.WCG.values_mut() {
      WCG.zeroize();
    }
    self.c.zeroize();
  }
}

impl<F: PrimeField> LinComb<F> {
  /// Create an empty linear combination.
  pub fn empty() -> Self {
    Self {
      highest_a_index: None,
      highest_c_index: None,
      highest_v_index: None,
      WLROV: vec![],
      WCG: BTreeMap::new(),
      c: F::ZERO,
    }
  }
}

impl<F: PrimeField> From<Variable> for LinComb<F> {
  fn from(constrainable: Variable) -> LinComb<F> {
    LinComb::empty().term(F::ONE, constrainable)
  }
}

impl<F: PrimeField> LinComb<F> {
  /// Reconcile two linear combinations, making them interoperable and able to be merged.
  fn reconcile_for_merging(&mut self, other: &Self) {
    self.highest_a_index = self.highest_a_index.max(other.highest_a_index);
    self.highest_c_index = self.highest_c_index.max(other.highest_c_index);
    self.highest_v_index = self.highest_v_index.max(other.highest_v_index);
  }
}

impl<F: PrimeField> Add<&LinComb<F>> for LinComb<F> {
  type Output = Self;

  fn add(mut self, constraint: &Self) -> Self {
    self.reconcile_for_merging(constraint);

    self.WLROV.extend(constraint.WLROV.iter());
    for (i, sparse_vec) in &constraint.WCG {
      if let Some(existing) = self.WCG.get_mut(i) {
        existing.extend(sparse_vec);
      } else {
        self.WCG.insert(*i, sparse_vec.clone());
      }
    }
    self.c += constraint.c;
    self
  }
}

impl<F: PrimeField> Sub<&LinComb<F>> for LinComb<F> {
  type Output = Self;

  fn sub(mut self, constraint: &Self) -> Self {
    self.reconcile_for_merging(constraint);

    self.WLROV.extend(constraint.WLROV.iter().map(|(tag, (i, weight))| (*tag, (*i, -*weight))));
    for (i, sparse_vec) in &constraint.WCG {
      let sparse_vec = sparse_vec.iter().copied().map(|(j, value)| (j, -value));
      if let Some(existing) = self.WCG.get_mut(i) {
        existing.extend(sparse_vec);
      } else {
        self.WCG.insert(*i, sparse_vec.collect());
      }
    }
    self.c -= constraint.c;
    self
  }
}

impl<F: PrimeField> Mul<F> for LinComb<F> {
  type Output = Self;

  fn mul(mut self, scalar: F) -> Self {
    for (_, (_, weight)) in &mut self.WLROV {
      *weight *= scalar;
    }
    for WC in self.WCG.values_mut() {
      for (_, weight) in WC {
        *weight *= scalar;
      }
    }
    self.c *= scalar;
    self
  }
}

impl<F: PrimeField> LinComb<F> {
  /// Add a new instance of a term to this linear combination.
  pub fn term(mut self, scalar: F, constrainable: Variable) -> Self {
    match constrainable {
      Variable::aL(i) => {
        self.highest_a_index = self.highest_a_index.max(Some(i));
        self.WLROV.push((Tag::WL, (i, scalar)))
      }
      Variable::aR(i) => {
        self.highest_a_index = self.highest_a_index.max(Some(i));
        self.WLROV.push((Tag::WR, (i, scalar)))
      }
      Variable::aO(i) => {
        self.highest_a_index = self.highest_a_index.max(Some(i));
        self.WLROV.push((Tag::WO, (i, scalar)))
      }
      Variable::CG { commitment: i, index: j } => {
        self.highest_c_index = self.highest_c_index.max(Some(i));
        /*
          We use `highest_a_index` to track the highest index within the IPA, hence why it tracks
          indexes to `aL`, `aR`, and `aO`. The variables within a vector commitment are _also_
          dependent on the size of the IPA, hence why these _also_ update `highest_a_index`.
        */
        self.highest_a_index = self.highest_a_index.max(Some(j));
        if let Some(values) = self.WCG.get_mut(&i) {
          values.push((j, scalar));
        } else {
          self.WCG.insert(i, vec![(j, scalar)]);
        }
      }
      Variable::V(i) => {
        self.highest_v_index = self.highest_v_index.max(Some(i));
        self.WLROV.push((Tag::WV, (i, scalar)));
      }
    };
    self
  }

  /// Add to the constant `c`.
  pub fn constant(mut self, scalar: F) -> Self {
    self.c += scalar;
    self
  }

  pub(crate) fn highest_a_index(&self) -> Option<usize> {
    self.highest_a_index
  }

  pub(crate) fn highest_c_index(&self) -> Option<usize> {
    self.highest_c_index
  }

  pub(crate) fn highest_v_index(&self) -> Option<usize> {
    self.highest_v_index
  }

  /// View the current weights for `aL`.
  pub fn WL(&self) -> impl Iterator<Item = &(usize, F)> {
    self.WLROV.iter().filter_map(|(tag, value)| matches!(tag, Tag::WL).then_some(value))
  }

  /// View the current weights for `aR`.
  pub fn WR(&self) -> impl Iterator<Item = &(usize, F)> {
    self.WLROV.iter().filter_map(|(tag, value)| matches!(tag, Tag::WR).then_some(value))
  }

  /// View the current weights for `aO`.
  pub fn WO(&self) -> impl Iterator<Item = &(usize, F)> {
    self.WLROV.iter().filter_map(|(tag, value)| matches!(tag, Tag::WO).then_some(value))
  }

  /// View the current weights for `CG`.
  pub fn WCG(&self) -> &BTreeMap<usize, Vec<(usize, F)>> {
    &self.WCG
  }

  /// View the current weights for `V`.
  pub fn WV(&self) -> impl Iterator<Item = &(usize, F)> {
    self.WLROV.iter().filter_map(|(tag, value)| matches!(tag, Tag::WV).then_some(value))
  }

  /// View the current constant `c`.
  pub fn c(&self) -> &F {
    &self.c
  }
}

/// Accumulate a sparse vector into an accumulator with a multiplicative weight applied.
///
/// This is equivalent to `accumulator += values * weight`, if `values` was a normal vector.
///
/// Returns the highest index written to during accumulation.
pub(crate) fn accumulate_vector<'value, F: PrimeField>(
  accumulator: &mut ScalarVector<F>,
  values: impl Iterator<Item = &'value (usize, F)>,
  weight: F,
) -> usize {
  let mut hi = 0;
  for (i, coeff) in values {
    accumulator[*i] += *coeff * weight;
    hi = hi.max(*i);
  }
  hi
}
