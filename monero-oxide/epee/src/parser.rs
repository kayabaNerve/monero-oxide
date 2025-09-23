use crate::{EpeeError, SnapshottedStack, read_byte, read_bytes, read_varint, read_str};

/// The EPEE-defined type of the field being read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Type {
  /// An `i64`.
  Int64 = 1,
  /// An `i32`.
  Int32 = 2,
  /// An `i16`.
  Int16 = 3,
  /// An `i8`.
  Int8 = 4,
  /// A `u64`.
  Uint64 = 5,
  /// A `u32`.
  Uint32 = 6,
  /// A `u16`.
  Uint16 = 7,
  /// A `u8`.
  Uint8 = 8,
  /// A `f64`.
  Double = 9,
  /// A length-prefixed collection of bytes.
  String = 10,
  /// A `bool`.
  Bool = 11,
  /// An object.
  Object = 12,
  // Array = 13, // Unused and unsupported
}

/// A bitflag for if the field is actually an array.
#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum Array {
  /// A unit type.
  Unit = 0,
  /// An array.
  Array = 1 << 7,
}

/*
  An internal marker used to distinguish if we're reading an EPEE-defined field OR if we're reading
  an entry within an section (object). This lets us collapse the definition of a section to an
  array of entries, simplifying decoding.
*/
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum TypeOrEntry {
  // An epee-defined type
  Type(Type),
  // An entry (name, type, value)
  Entry,
}

impl Type {
  /// Read a type specification, including its length.
  pub fn read(reader: &mut &[u8]) -> Result<(Self, u64), EpeeError> {
    let kind = read_byte(reader)?;

    // Check if the array bit is set
    let array = kind & (Array::Array as u8);
    // Clear the array bit
    let kind = kind & (!(Array::Array as u8));

    let kind = match kind {
      1 => Type::Int64,
      2 => Type::Int32,
      3 => Type::Int16,
      4 => Type::Int8,
      5 => Type::Uint64,
      6 => Type::Uint32,
      7 => Type::Uint16,
      8 => Type::Uint8,
      9 => Type::Double,
      10 => Type::String,
      11 => Type::Bool,
      12 => Type::Object,
      _ => Err(EpeeError::UnrecognizedType)?,
    };

    // Flatten non-array values to an array of length one
    /*
      TODO: Will `epee` proper return an error if an array of length one is specified for a unit
      type? This wouldn't break out definition of compatibility yet should be revisited.
    */
    let len = if array != 0 { read_varint(reader)? } else { 1 };

    Ok((kind, len))
  }
}

/// Read a entry's key.
// https://github.com/monero-project/monero/blob/8d4c625713e3419573dfcc7119c8848f47cabbaa
//   /contrib/epee/include/storages/portable_storage_from_bin.h#143-L152
fn read_key<'a>(reader: &mut &'a [u8]) -> Result<&'a [u8], EpeeError> {
  let len = usize::from(read_byte(reader)?);
  if len == 0 {
    Err(EpeeError::EmptyKey)?;
  }
  if reader.len() < len {
    Err(EpeeError::Short(len))?;
  }
  let res = &reader[.. len];
  *reader = &reader[len ..];
  Ok(res)
}

impl<'a> SnapshottedStack<'a> {
  /// Execute a single step of the decoding algorithm.
  ///
  /// Returns `Some((kind, len))` if an entry was read, or `None` otherwise. This also returns
  /// `None` if the stack is empty.
  pub(crate) fn single_step(
    &mut self,
    encoding: &mut &[u8],
  ) -> Result<Option<(Type, u64)>, EpeeError> {
    let Some(kind) = self.pop() else {
      return Ok(None);
    };
    match kind {
      TypeOrEntry::Type(Type::Int64) => {
        read_bytes(encoding, core::mem::size_of::<i64>())?;
      }
      TypeOrEntry::Type(Type::Int32) => {
        read_bytes(encoding, core::mem::size_of::<i32>())?;
      }
      TypeOrEntry::Type(Type::Int16) => {
        read_bytes(encoding, core::mem::size_of::<i16>())?;
      }
      TypeOrEntry::Type(Type::Int8) => {
        read_bytes(encoding, core::mem::size_of::<i8>())?;
      }
      TypeOrEntry::Type(Type::Uint64) => {
        read_bytes(encoding, core::mem::size_of::<u64>())?;
      }
      TypeOrEntry::Type(Type::Uint32) => {
        read_bytes(encoding, core::mem::size_of::<u32>())?;
      }
      TypeOrEntry::Type(Type::Uint16) => {
        read_bytes(encoding, core::mem::size_of::<u16>())?;
      }
      TypeOrEntry::Type(Type::Uint8) => {
        read_bytes(encoding, core::mem::size_of::<u8>())?;
      }
      TypeOrEntry::Type(Type::Double) => {
        read_bytes(encoding, core::mem::size_of::<f64>())?;
      }
      TypeOrEntry::Type(Type::String) => {
        read_str(encoding)?;
      }
      TypeOrEntry::Type(Type::Bool) => {
        read_bytes(encoding, core::mem::size_of::<bool>())?;
      }
      TypeOrEntry::Type(Type::Object) => {
        let amount_of_entries = read_varint(encoding)?;
        self.push(TypeOrEntry::Entry, amount_of_entries)?;
      }
      TypeOrEntry::Entry => {
        let _entry_key = read_key(encoding)?;
        let (kind, len) = Type::read(encoding)?;
        self.push(TypeOrEntry::Type(kind), len)?;
        return Ok(Some((kind, len)));
      }
    }
    Ok(None)
  }

  /// Step through the entirety of the next item.
  ///
  /// Returns `None` if the stack is empty.
  pub(crate) fn step(&mut self, encoding: &mut &[u8]) -> Result<Option<()>, EpeeError> {
    let Some((kind, len)) = self.peek() else { return Ok(None) };
    let current_stack_depth = self.depth();
    /*
      We stop at the next item at the same depth, unless this is the last object in an
      object/array, in which case the same depth of the stack is used for _both_ the item's
      definition _and_ its innards (due to popping the item's definition, then pushing the
      innards).
    */
    let stop_at_stack_depth = if ((kind, len.get()) == (TypeOrEntry::Entry, 1)) ||
      (kind, len.get()) == (TypeOrEntry::Type(Type::Object), 1)
    {
      // We could peek at an item on the stack, therefore it has an item
      current_stack_depth - 1
    } else {
      current_stack_depth
    };

    while {
      self.single_step(encoding)?;
      self.depth() != stop_at_stack_depth
    } {}

    Ok(Some(()))
  }

  pub(crate) fn entry(
    &mut self,
    encoding: &mut &[u8],
    key: &str,
  ) -> Result<Option<(Type, u64)>, EpeeError> {
    let Some((kind, len)) = self.peek() else { return Ok(None) };
    if kind != TypeOrEntry::Entry {
      Err(EpeeError::TypeError)?;
    }

    // Iterate through the entries for one with a matching key
    for _ in 0 .. len.get() {
      /*
        NOTE: EPEE would check no duplicate keys are present here, while we simply follow the first
        instance.
      */
      if read_key(&mut *encoding).ok() == Some(key.as_bytes()) {
        break;
      }
      self.step(encoding)?;
    }

    self.single_step(encoding)
  }
}
