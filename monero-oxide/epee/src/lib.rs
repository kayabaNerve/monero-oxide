#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![no_std]

mod io;
mod stack;
mod parser;

pub(crate) use io::*;
pub(crate) use stack::*;
pub use parser::*;

/// An error incurred when decoding.
#[derive(Clone, Copy, Debug)]
pub enum EpeeError {
  /// The blob did not have the expected header.
  InvalidHeader,
  /// The blob did not have the expected version.
  ///
  /// For `EpeeError::InvalidVersion(version)`, `version` is the version read from the blob.
  InvalidVersion(Option<u8>),
  /// The blob was short, as discovered when trying to read `{0}` bytes.
  Short(usize),
  /// Unrecognized type specified.
  UnrecognizedType,
  /// An object defined a key of `""`.
  EmptyKey,
  /// The depth limit was exceeded.
  DepthLimitExceeded,
  /// An operation expected one type yet the actual type was distinct.
  TypeError,
}

/// The EPEE header.
// https://github.com/monero-project/monero/blob/8d4c625713e3419573dfcc7119c8848f47cabbaa
//  /contrib/epee/include/storages/portable_storage_base.h#L37-L38
pub const HEADER: [u8; 8] = *b"\x01\x11\x01\x01\x01\x01\x02\x01";
/// The supported version of the EPEE protocol.
// https://github.com/monero-project/monero/blob/8d4c625713e3419573dfcc7119c8848f47cabbaa
//  /contrib/epee/include/storages/portable_storage_base.h#L39
pub const VERSION: u8 = 1;

/// A decoder for an EPEE-encoded object.
pub struct Epee<'encoding> {
  original_encoding: &'encoding [u8],
  current_encoding_state: &'encoding [u8],
  stack: Stack,
  error: Option<EpeeError>,
}

/// An item with an EPEE-encoded object.
pub struct EpeeEntry<'encoding, 'parent> {
  root: Option<&'parent mut Epee<'encoding>>,
  kind: Type,
  len: u64,
}

// When this entry is dropped, advance the decoder past it
impl<'encoding, 'parent> Drop for EpeeEntry<'encoding, 'parent> {
  #[inline(always)]
  fn drop(&mut self) {
    if let Some(root) = self.root.take() {
      root.error = root.error.or_else(|| root.stack.step(&mut root.current_encoding_state).err());
    }
  }
}

/// An iterator over fields.
pub struct FieldIterator<'encoding, 'parent> {
  root: &'parent mut Epee<'encoding>,
  len: u64,
}

// When this object is dropped, advance the decoder past the unread items
impl<'encoding, 'parent> Drop for FieldIterator<'encoding, 'parent> {
  #[inline(always)]
  fn drop(&mut self) {
    for _ in 0 .. self.len {
      self.root.error = self
        .root
        .error
        .or_else(|| self.root.stack.step(&mut self.root.current_encoding_state).err());
    }
  }
}

impl<'encoding, 'parent> FieldIterator<'encoding, 'parent> {
  /// The next entry (key, value) within the object.
  ///
  /// This is approximate to `Iterator::next` yet each item maintains a mutable reference to the
  /// iterator. Accordingly, we cannot use `Iterator::next` which requires items not borrow from
  /// the iterator.
  #[allow(clippy::should_implement_trait)]
  pub fn next(&mut self) -> Option<Result<(&'encoding [u8], EpeeEntry<'encoding, '_>), EpeeError>> {
    self.len = self.len.checked_sub(1)?;
    let (key, kind, len) = match self.root.stack.single_step(&mut self.root.current_encoding_state)
    {
      Ok(Some((key, kind, len))) => (key, kind, len),
      // This should be unreachable as the stack shouldn't be empty if our iterator has a non-zero
      // length
      Ok(None) => None?,
      Err(e) => return Some(Err(e)),
    };

    Some(Ok((key, EpeeEntry { root: Some(self.root), kind, len })))
  }
}

impl<'encoding> Epee<'encoding> {
  /// Create a new view of an encoding.
  pub fn new(mut encoding: &'encoding [u8]) -> Result<Self, EpeeError> {
    // Check the header
    if read_bytes(&mut encoding, HEADER.len()).ok() != Some(HEADER.as_slice()) {
      Err(EpeeError::InvalidHeader)?;
    }

    // Check the version
    {
      let version = read_byte(&mut encoding).ok();
      if version != Some(VERSION) {
        Err(EpeeError::InvalidVersion(version))?;
      }
    }

    Ok(Epee {
      original_encoding: encoding,
      current_encoding_state: encoding,
      stack: Stack::root_object(),
      error: None,
    })
  }

  /// Iterate over the fields within this object.
  ///
  /// This takes a mutable reference as `Epee` may only be iterated over once at any time.
  /// Future calls to `fields` will be safe and behave identically however.
  pub fn fields<'this>(&'this mut self) -> Result<FieldIterator<'encoding, 'this>, EpeeError> {
    // Reset the current state.
    self.current_encoding_state = self.original_encoding;
    self.stack.reset();
    self.error = None;

    let len = read_varint(&mut &*self.current_encoding_state)?;
    // Read past the `Type::Object` this was constructed with into `[Type::Entry; n]`
    self.stack.single_step(&mut self.current_encoding_state)?;
    Ok(FieldIterator { root: self, len })
  }
}

/// An iterator over an array.
pub struct ArrayIterator<'encoding, 'parent> {
  root: &'parent mut Epee<'encoding>,
  kind: Type,
  len: u64,
}

// When this array is dropped, advance the decoder past the unread items
impl<'encoding, 'parent> Drop for ArrayIterator<'encoding, 'parent> {
  #[inline(always)]
  fn drop(&mut self) {
    for _ in 0 .. self.len {
      self.root.error = self
        .root
        .error
        .or_else(|| self.root.stack.step(&mut self.root.current_encoding_state).err());
    }
  }
}

impl<'encoding, 'parent> ArrayIterator<'encoding, 'parent> {
  /// The next item within the array.
  ///
  /// This is approximate to `Iterator::next` yet each item maintains a mutable reference to the
  /// iterator. Accordingly, we cannot use `Iterator::next` which requires items not borrow from
  /// the iterator.
  #[allow(clippy::should_implement_trait)]
  pub fn next(&mut self) -> Option<Result<EpeeEntry<'encoding, '_>, EpeeError>> {
    if let Some(err) = self.root.error {
      return Some(Err(err));
    }

    self.len = self.len.checked_sub(1)?;
    Some(Ok(EpeeEntry { root: Some(self.root), kind: self.kind, len: 1 }))
  }
}

impl<'encoding, 'parent> EpeeEntry<'encoding, 'parent> {
  /// The type of object this entry represents.
  #[inline(always)]
  pub fn kind(&self) -> Type {
    self.kind
  }

  /// The amount of items present within this entry.
  #[allow(clippy::len_without_is_empty)]
  #[inline(always)]
  pub fn len(&self) -> u64 {
    self.len
  }

  /// Iterate over the fields within this object.
  pub fn fields(mut self) -> Result<FieldIterator<'encoding, 'parent>, EpeeError> {
    let root =
      self.root.take().expect("root was None despite only taking in methods which consume `self`");

    if let Some(err) = root.error {
      Err(err)?;
    }

    if (self.kind != Type::Object) || (self.len != 1) {
      Err(EpeeError::TypeError)?;
    }

    let len = read_varint(&mut &*root.current_encoding_state)?;
    // Read past the `Type::Object` this was constructed with into `[Type::Entry; n]`
    root.stack.single_step(&mut root.current_encoding_state)?;
    Ok(FieldIterator { root, len })
  }

  /// Get an iterator of all items within this container.
  ///
  /// If you want to index a specific item, you may use `.iterate()?.nth(i)?`. An `index` method
  /// isn't provided as each index operation is of O(n) complexity and single indexes SHOULD NOT be
  /// used. Only exposing `iterate` attempts to make this clear to the user.
  pub fn iterate(mut self) -> Result<ArrayIterator<'encoding, 'parent>, EpeeError> {
    let root =
      self.root.take().expect("root was None despite only taking in methods which consume `self`");

    if let Some(err) = root.error {
      Err(err)?;
    }

    Ok(ArrayIterator { root, kind: self.kind, len: self.len })
  }

  #[inline(always)]
  fn as_primitive<T>(&self, kind: Type) -> Result<&[u8], EpeeError> {
    if (self.kind != kind) || (self.len != 1) {
      Err(EpeeError::TypeError)?;
    }

    let root = self
      .root
      .as_ref()
      .expect("root was None despite only taking in methods which consume `self`");
    read_bytes(&mut &*root.current_encoding_state, core::mem::size_of::<T>())
  }

  /// Get the current item as an `i64`.
  #[inline(always)]
  pub fn as_i64(&self) -> Result<i64, EpeeError> {
    Ok(i64::from_le_bytes(self.as_primitive::<i64>(Type::Int64)?.try_into().unwrap()))
  }

  /// Get the current item as an `i32`.
  #[inline(always)]
  pub fn as_i32(&self) -> Result<i32, EpeeError> {
    Ok(i32::from_le_bytes(self.as_primitive::<i32>(Type::Int32)?.try_into().unwrap()))
  }

  /// Get the current item as an `i16`.
  #[inline(always)]
  pub fn as_i16(&self) -> Result<i16, EpeeError> {
    Ok(i16::from_le_bytes(self.as_primitive::<i16>(Type::Int16)?.try_into().unwrap()))
  }

  /// Get the current item as an `i8`.
  #[inline(always)]
  pub fn as_i8(&self) -> Result<i8, EpeeError> {
    Ok(i8::from_le_bytes(self.as_primitive::<i8>(Type::Int8)?.try_into().unwrap()))
  }

  /// Get the current item as a `u64`.
  #[inline(always)]
  pub fn as_u64(&self) -> Result<u64, EpeeError> {
    Ok(u64::from_le_bytes(self.as_primitive::<u64>(Type::Uint64)?.try_into().unwrap()))
  }

  /// Get the current item as a `u32`.
  #[inline(always)]
  pub fn as_u32(&self) -> Result<u32, EpeeError> {
    Ok(u32::from_le_bytes(self.as_primitive::<u32>(Type::Uint32)?.try_into().unwrap()))
  }

  /// Get the current item as a `u16`.
  #[inline(always)]
  pub fn as_u16(&self) -> Result<u16, EpeeError> {
    Ok(u16::from_le_bytes(self.as_primitive::<u16>(Type::Uint16)?.try_into().unwrap()))
  }

  /// Get the current item as a `u8`.
  #[inline(always)]
  pub fn as_u8(&self) -> Result<u8, EpeeError> {
    Ok(self.as_primitive::<u8>(Type::Uint8)?[0])
  }

  /// Get the current item as an `f64`.
  #[inline(always)]
  pub fn as_f64(&self) -> Result<f64, EpeeError> {
    Ok(f64::from_le_bytes(self.as_primitive::<f64>(Type::Double)?.try_into().unwrap()))
  }

  /// Get the current item as a 'string' (represented as a `&[u8]`).
  #[inline(always)]
  pub fn as_str(&self) -> Result<&[u8], EpeeError> {
    if (self.kind != Type::String) || (self.len != 1) {
      Err(EpeeError::TypeError)?;
    }

    let root = self
      .root
      .as_ref()
      .expect("root was None despite only taking in methods which consume `self`");
    read_str(&mut &*root.current_encoding_state)
  }

  /// Get the current item as a 'string' (represented as a `&[u8]`) of a specific length.
  ///
  /// This will error if the result is not actually the expected length.
  #[inline(always)]
  pub fn as_fixed_len_str(&self, len: usize) -> Result<&[u8], EpeeError> {
    let str = self.as_str()?;
    if str.len() != len {
      Err(EpeeError::TypeError)?;
    }
    Ok(str)
  }

  /// Get the current item as a `bool`.
  #[inline(always)]
  pub fn as_bool(&self) -> Result<bool, EpeeError> {
    Ok(self.as_primitive::<bool>(Type::Bool)?[0] != 0)
  }
}
