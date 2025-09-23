//! A non-allocating alternative to `Vec`, used to track the state of an EPEE decoder.
//!
//! This is only possible due to bounding the depth of objects we decode, which we are able to do
//! with complete correctness due to EPEE defining a maximum depth of just `100`. This limit is
//! also sufficiently small as to make this not only feasible yet performant, with the stack taking
//! less than a kibibyte (even on 64-bit platforms).
//!
//! This code is internal to `monero-epee` yet is still written not to panic in any case.

/*
  Introducing `NonZero` bumped us from a MSRV of Rust 1.60 to Rust 1.79. We have no incentive to
  support Rust 1.60 here, yet it would be trivial to expand the supported versions of Rust.
*/
use core::num::NonZero;

use crate::{EpeeError, Type, TypeOrEntry};

// https://github.com/monero-project/monero/blob/8d4c625713e3419573dfcc7119c8848f47cabbaa/
//   contrib/epee/include/storages/portable_storage_from_bin.h#L42
const EPEE_LIB_MAX_OBJECT_DEPTH: usize = 100;
/*
  Explicitly set a larger depth in case we have slight differences in counting the current depth.

  The goal of this library is to decode at _least_ the set of objects EPEE itself will handle.
  While we may be slightly more tolerant, this is accepted over incompatibility given the lack of a
  strict specification for EPEE.

  Additionally, decoding a larget set of objects will not be considered an incompatibility so long
  as encodings (unsupported at the time of writing this comment) will always be handled by EPEE,
  ensuring _mutual_ compatibility.
*/
const MAX_OBJECT_DEPTH: usize = EPEE_LIB_MAX_OBJECT_DEPTH + 2;

/*
  `TypeOrEntry` is a branching `enum`, yet has less than 256 possible instantiations. Accordingly
  it is representable with just a `u8`. This checks Rust is smart enough to realize this and that
  we don't have to define our own `u8` encoder to achieve this small of a representation.
*/
#[cfg(test)]
const _ASSERT_SINGLE_BYTE_TYPE_OR_ENTRY: [(); 1 - core::mem::size_of::<TypeOrEntry>()] =
  [(); 1 - core::mem::size_of::<TypeOrEntry>()];

/// A non-allocating `Vec`.
///
/// This has a maximum depth premised on the bound for an EPEE's object depth.
struct Stack {
  /*
    We represent items to decode as `(TypeOrEntry, u64)` so that if told to decode a vector with
    one billion entries, we don't have to allocate
    `vec![TypeOrEntry::Entry(Type::*), 1_000_000_000]` to keep track of the state. Instead, the
    size of the state is solely a function of depth, not width.

    The following two arrays are separate as Rust would pad `(TypeOrEntry, u64)` to 16 bytes, when
    it only requires 9 bytes to represent.
  */
  /// The type of the item being read.
  types: [TypeOrEntry; MAX_OBJECT_DEPTH],
  /// The amount remaining for the item being read.
  amounts: [NonZero<u64>; MAX_OBJECT_DEPTH],

  /// The current depth of the stack.
  ///
  /// This is analogous to the length of a `Vec`, yet we use the term `depth` to distinguish how it
  /// tracks the depth of an object, not the amount of items present (which would be a function of
  /// depth and width, as noted above).
  depth: u8,
}

/*
  Because every time we decode an object, we allocate this fixed-size item on the stack (avoiding
  requiring dynamic allocation on the heap), ensure it's tiny and not an issue to allocate.
*/
#[cfg(test)]
const _ASSERT_KIBIBYTE_STACK: [(); 1024 - core::mem::size_of::<Stack>()] =
  [(); 1024 - core::mem::size_of::<Stack>()];

impl Stack {
  fn new(initial_item: (TypeOrEntry, u64)) -> Self {
    /*
      Zero-initialize the arrays.

      Because `TypeOrEntry` does not have a 'zero' defined, we simply use `TypeOrEntry::Entry` to
      avoid `unsafe` code here for a minor performance benefit. Because we require `amounts` to be
      non-zero, we use `NonZero::MIN`.
    */
    let mut types = [TypeOrEntry::Entry; MAX_OBJECT_DEPTH];
    let mut amounts = [NonZero::<u64>::MIN; MAX_OBJECT_DEPTH];

    // Set the initial item
    let (kind, amount) = initial_item;
    types[0] = kind;

    let depth = if let Some(amount) = NonZero::new(amount) {
      amounts[0] = amount;
      1
    } else {
      // If we aren't actually supposed to decode anything, return an empty stack
      0
    };

    Self { types, amounts, depth }
  }

  /// The current stack depth.
  #[inline(always)]
  fn depth(&self) -> usize {
    usize::from(self.depth)
  }

  /// Peek the current item on the stack.
  fn peek(&self) -> Option<(TypeOrEntry, NonZero<u64>)> {
    let i = self.depth().checked_sub(1)?;
    Some((self.types[i], self.amounts[i]))
  }

  /// Peek the next item from the stack if it has at least the specified depth.
  fn peek_with_minimum_depth(&self, depth: u8) -> Option<(TypeOrEntry, NonZero<u64>)> {
    if self.depth < depth {
      None?;
    }
    self.peek()
  }

  /// Pop the next item from the stack.
  fn pop(&mut self) -> Option<TypeOrEntry> {
    let i = self.depth().checked_sub(1)?;

    let kind = self.types[i];

    // This will not panic as `amount` is unsigned and non-zero.
    let amount = self.amounts[i].get() - 1;
    if let Some(amount) = NonZero::new(amount) {
      self.amounts[i] = amount;
    } else {
      // This will not panic as we know depth can have `1` subtracted.
      self.depth -= 1;
    }

    Some(kind)
  }

  /// Pop the next item from the stack if it has at least the specified depth.
  fn pop_with_minimum_depth(&mut self, depth: u8) -> Option<TypeOrEntry> {
    if self.depth < depth {
      None?;
    }
    self.pop()
  }

  /// Push an item onto the stack.
  fn push(&mut self, kind: TypeOrEntry, amount: u64) -> Result<(), EpeeError> {
    // Assert the maximum depth for an object
    if self.depth() == MAX_OBJECT_DEPTH {
      Err(EpeeError::DepthLimitExceeded)?;
    }

    let Some(amount) = NonZero::new(amount) else {
      // If we have nothing to decode, immediately return
      return Ok(());
    };

    // These will not panic due to our depth check at the start of the function
    self.types[self.depth()] = kind;
    self.amounts[self.depth()] = amount;
    self.depth += 1;

    Ok(())
  }

  /// Create a snapshot of the current stack.
  fn snapshot(&self) -> Snapshot {
    Snapshot {
      tail: self.peek().unwrap_or((TypeOrEntry::Entry, NonZero::<u64>::MIN)),
      depth: self.depth,
    }
  }
}

/// A snapshot of a stack.
///
/// A snapshot preserves the tail of the stack at the time of its creation. This allows quickly
/// reverting a stack to its snapshot so long as no elements before the tail have been mutated.
#[derive(Clone, Copy)]
struct Snapshot {
  tail: (TypeOrEntry, NonZero<u64>),
  depth: u8,
}

/// A stack which has had a snapshot taken.
pub(crate) struct SnapshottedStack<'a> {
  stack: &'a mut Stack,
  snapshot: Snapshot,
}

impl<'a> SnapshottedStack<'a> {
  /// Associate a stack with a snapshot.
  ///
  /// The caller is responsible for ensuring these are related and that no elements before the tail
  /// as of when the snapshot was taken have been mutated. The methods on this struct help to
  /// ensure that.
  fn associate(stack: &'a mut Stack, snapshot: Snapshot) -> Self {
    Self { stack, snapshot }
  }

  /// The depth of the stack.
  pub(crate) fn depth(&self) -> usize {
    usize::from(self.stack.depth)
  }

  /// Push an element onto the stack.
  pub(crate) fn push(&mut self, kind: TypeOrEntry, amount: u64) -> Result<(), EpeeError> {
    self.stack.push(kind, amount)
  }

  /// Peek the next item on the stack.
  ///
  /// This will return `None` if `pop` would return `None`.
  pub(crate) fn peek(&self) -> Option<(TypeOrEntry, NonZero<u64>)> {
    self.stack.peek_with_minimum_depth(self.snapshot.depth)
  }

  /// Pop the next item from the stack.
  ///
  /// This will return `None` if the stack is empty or if this would mutate an element preceding
  /// the snapshot.
  pub(crate) fn pop(&mut self) -> Option<TypeOrEntry> {
    self.stack.pop_with_minimum_depth(self.snapshot.depth)
  }
}

/// An index into an EPEE object.
///
/// Due to how this library implements a lazy decoding strategy, to find a field is to advance to
/// the field, preventing reading two fields within the same object _unless_ they're read in order
/// (when EPEE is an unordered encoding). We solve this by taking snapshots of the stack before
/// each index, allowing us to reset the stack after each index operation.
///
/// The index uses a single stack across all operations to ensure a fixed amount of memory is
/// consumed.
pub(crate) struct Index<'a> {
  stack: Stack,
  encoding: &'a [u8],
  snapshot_types: [TypeOrEntry; MAX_OBJECT_DEPTH],
  snapshot_amounts: [NonZero<u64>; MAX_OBJECT_DEPTH],
  snapshot_depths: [u8; MAX_OBJECT_DEPTH],
  snapshot_encoding_locations: [usize; MAX_OBJECT_DEPTH],
  depth: u8,
}

#[cfg(test)]
const _ASSERT_THREE_KIBIBYTE_INDEX: [(); (3 * 1024) - core::mem::size_of::<Index>()] =
  [(); (3 * 1024) - core::mem::size_of::<Index>()];

impl<'a> Index<'a> {
  /// Create a new index for a root-level object.
  pub(crate) fn root_object(encoding: &'a [u8]) -> Self {
    let stack = Stack::new((TypeOrEntry::Type(Type::Object), 1));

    let snapshot = stack.snapshot();
    Self {
      stack,
      encoding,
      snapshot_types: [snapshot.tail.0; MAX_OBJECT_DEPTH],
      snapshot_amounts: [snapshot.tail.1; MAX_OBJECT_DEPTH],
      snapshot_depths: [snapshot.depth; MAX_OBJECT_DEPTH],
      snapshot_encoding_locations: [0; MAX_OBJECT_DEPTH],
      depth: 1,
    }
  }

  /// Advance the index.
  ///
  /// This SHOULD be done with distinct containers as the amount of snapshots is limited by the
  /// maximum depth of an object. Accordingly, creating multiple snapshots at the same depth will
  /// lead to exhaustion before the actual depth limit is reached.
  pub(crate) fn advance<'b>(
    &'b mut self,
    current_encoding_len: usize,
  ) -> Result<SnapshottedStack<'b>, EpeeError> {
    let snapshot = self.stack.snapshot();
    let depth = usize::from(self.depth);
    if depth == MAX_OBJECT_DEPTH {
      Err(EpeeError::DepthLimitExceeded)?;
    }
    self.snapshot_types[depth] = snapshot.tail.0;
    self.snapshot_amounts[depth] = snapshot.tail.1;
    self.snapshot_depths[depth] = snapshot.depth;
    self.snapshot_encoding_locations[depth] =
      self.encoding.len().saturating_sub(current_encoding_len);
    self.depth += 1;
    Ok(SnapshottedStack::associate(&mut self.stack, snapshot))
  }

  /// Revert the index.
  ///
  /// Returns the encoding claimed to be the current state when the index was advanced.
  ///
  /// Has undefined, yet memory-safe/panic-free, behavior if no snapshot is present.
  pub(crate) fn revert(&mut self) -> &'a [u8] {
    // Decrement the snapshot depth
    self.depth = self.depth.saturating_sub(1);
    let depth = usize::from(self.depth);

    // Revert the stack
    let stack_depth = self.snapshot_depths[depth];
    self.stack.depth = stack_depth;
    let stack_depth = usize::from(stack_depth);
    self.stack.types[stack_depth - 1] = self.snapshot_types[depth];
    self.stack.amounts[stack_depth - 1] = self.snapshot_amounts[depth];

    // Return the prior encoding
    &self.encoding[self.snapshot_encoding_locations[depth] ..]
  }
}
