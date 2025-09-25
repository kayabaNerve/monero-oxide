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
pub struct Epee<'a> {
  current_encoding_state: &'a [u8],
  stack: Stack,
  error: Option<EpeeError>,
}

/// An item with an EPEE-encoded object.
pub struct EpeeEntry<'a> {
  root: &'a mut Epee<'a>,
  kind: Type,
  len: u64,
}

// When this entry is dropped, advance the decoder past it
impl<'a> Drop for EpeeEntry<'a> {
  #[inline(always)]
  fn drop(&mut self) {
    self.root.error =
      self.root.error.or_else(|| self.root.stack.step(&mut self.root.current_encoding_state).err());
  }
}

/// An iterator over fields.
pub struct FieldIterator<'a> {
  root: &'a mut Epee<'a>,
  len: u64,
  advance: bool,
}

// When this object is dropped, advance the decoder past it
impl<'a> Drop for FieldIterator<'a> {
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

impl<'a> FieldIterator<'a> {
  /// The next entry (key, value) within the object.
  ///
  /// This is approximate to `Iterator::next` yet each item maintains a mutable reference to the
  /// iterator. Accordingly, we cannot use `Iterator::next` which requires items not borrow from
  /// the iterator.
  #[allow(clippy::should_implement_trait)]
  pub fn next(&'a mut self) -> Option<Result<(&'a [u8], EpeeEntry<'a>), EpeeError>> {
    // If we've prior iterated, advance the decoder past the prior yielded item
    if self.advance {
      match self.root.stack.step(&mut self.root.current_encoding_state) {
        Ok(_) => {}
        Err(e) => return Some(Err(e)),
      }
    }

    self.len = self.len.checked_sub(1)?;
    let (key, kind, len) = match self.root.stack.single_step(&mut self.root.current_encoding_state)
    {
      Ok(Some((key, kind, len))) => (key, kind, len),
      // This should be unreachable as the stack shouldn't be empty if our iterator has a non-zero
      // length
      Ok(None) => None?,
      Err(e) => return Some(Err(e)),
    };

    Some(Ok((key, EpeeEntry { root: self.root, kind, len })))
  }
}

impl<'a> Epee<'a> {
  /// Create a new view of an encoding.
  pub fn new(mut encoding: &'a [u8]) -> Result<Self, EpeeError> {
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

    Ok(Epee { current_encoding_state: encoding, stack: Stack::root_object(), error: None })
  }

  /// Iterate over the fields within this object.
  ///
  /// This takes a mutable reference to `self` _but_ `self` will be functionally identical once the
  /// returned object is dropped. The mutable reference to `self` is solely taken to reuse its
  /// stack for the duration of the indexing.
  pub fn fields(&'a mut self) -> Result<FieldIterator<'a>, EpeeError> {
    let len = read_varint(&mut &*self.current_encoding_state)?;
    // Read past the `Type::Object` this was constructed with into `[Type::Entry; n]`
    self.stack.single_step(&mut self.current_encoding_state)?;
    Ok(FieldIterator { root: self, len, advance: false })
  }
}

/// An iterator over an array.
pub struct ArrayIterator<'a> {
  root: &'a mut Epee<'a>,
  kind: Type,
  len: u64,
  advance: bool,
}

// When this array is dropped, advance the decoder past it
impl<'a> Drop for ArrayIterator<'a> {
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

impl<'a> ArrayIterator<'a> {
  /// The next item within the array.
  ///
  /// This is approximate to `Iterator::next` yet each item maintains a mutable reference to the
  /// iterator. Accordingly, we cannot use `Iterator::next` which requires items not borrow from
  /// the iterator.
  #[allow(clippy::should_implement_trait)]
  pub fn next(&'a mut self) -> Option<Result<EpeeEntry<'a>, EpeeError>> {
    if let Some(err) = self.root.error {
      return Some(Err(err));
    }

    // If we've prior iterated, advance the decoder past the prior yielded item
    if self.advance {
      match self.root.stack.step(&mut self.root.current_encoding_state) {
        Ok(_) => {}
        Err(e) => return Some(Err(e)),
      }
    }

    let res = EpeeEntry { root: self.root, kind: self.kind, len: 1 };
    self.len = self.len.checked_sub(1)?;
    self.advance = true;
    Some(Ok(res))
  }
}

impl<'a> EpeeEntry<'a> {
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
  ///
  /// This takes a mutable reference to `self` _but_ `self` will be functionally identical once the
  /// returned object is dropped. The mutable reference to `self` is solely taken to reuse its
  /// stack for the duration of the indexing.
  pub fn fields(&'a mut self) -> Result<FieldIterator<'a>, EpeeError> {
    if let Some(err) = self.root.error {
      Err(err)?;
    }

    if (self.kind != Type::Object) || (self.len != 1) {
      Err(EpeeError::TypeError)?;
    }

    let len = read_varint(&mut &*self.root.current_encoding_state)?;
    // Read past the `Type::Object` this was constructed with into `[Type::Entry; n]`
    self.root.stack.single_step(&mut self.root.current_encoding_state)?;
    Ok(FieldIterator { root: self.root, len, advance: false })
  }

  /// Get an iterator of all items within this container.
  ///
  /// If you want to index a specific item, you may use `.iterate()?.nth(i)?`. An `index` method
  /// isn't provided as each index operation is of O(n) complexity and single indexes SHOULD NOT be
  /// used. Only exposing `iterate` attempts to make this clear to the user.
  pub fn iterate(&'a mut self) -> Result<ArrayIterator<'a>, EpeeError> {
    if let Some(err) = self.root.error {
      Err(err)?;
    }

    Ok(ArrayIterator { root: self.root, kind: self.kind, len: self.len, advance: false })
  }

  #[inline(always)]
  fn as_primitive<T>(&self, kind: Type) -> Result<&[u8], EpeeError> {
    if (self.kind != kind) || (self.len != 1) {
      Err(EpeeError::TypeError)?;
    }
    read_bytes(&mut &*self.root.current_encoding_state, core::mem::size_of::<T>())
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
    read_str(&mut &*self.root.current_encoding_state)
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
