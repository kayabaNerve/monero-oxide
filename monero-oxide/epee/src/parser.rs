use core::convert::TryFrom;

use crate::{EpeeError, Stack, read_byte, read_bytes, read_varint};

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
#[derive(Clone, Copy)]
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

/// An iterator which seeks to all values of desired `(type, name)`.
pub(crate) struct Seek<'a> {
  pub(crate) reader: &'a [u8],
  pub(crate) kind: Type,
  pub(crate) array: Array,
  pub(crate) field_name: &'static str,
  pub(crate) stack: Stack,
}
#[cfg(test)]
const _ASSERT_KIBIBYTE_SEEK: [(); 1024 - core::mem::size_of::<Seek>()] =
  [(); 1024 - core::mem::size_of::<Seek>()];

impl<'a> Iterator for Seek<'a> {
  type Item = Result<(u64, &'a [u8]), EpeeError>;
  fn next(&mut self) -> Option<Self::Item> {
    (|| -> Result<_, EpeeError> {
      let mut result = None;

      while let Some(kind) = self.stack.pop() {
        match kind {
          TypeOrEntry::Type(Type::Int64) => {
            read_bytes::<{ core::mem::size_of::<i64>() }>(&mut self.reader)?;
          }
          TypeOrEntry::Type(Type::Int32) => {
            read_bytes::<{ core::mem::size_of::<i32>() }>(&mut self.reader)?;
          }
          TypeOrEntry::Type(Type::Int16) => {
            read_bytes::<{ core::mem::size_of::<i16>() }>(&mut self.reader)?;
          }
          TypeOrEntry::Type(Type::Int8) => {
            read_bytes::<{ core::mem::size_of::<i8>() }>(&mut self.reader)?;
          }
          TypeOrEntry::Type(Type::Uint64) => {
            read_bytes::<{ core::mem::size_of::<u64>() }>(&mut self.reader)?;
          }
          TypeOrEntry::Type(Type::Uint32) => {
            read_bytes::<{ core::mem::size_of::<u32>() }>(&mut self.reader)?;
          }
          TypeOrEntry::Type(Type::Uint16) => {
            read_bytes::<{ core::mem::size_of::<u16>() }>(&mut self.reader)?;
          }
          TypeOrEntry::Type(Type::Uint8) => {
            read_bytes::<{ core::mem::size_of::<u8>() }>(&mut self.reader)?;
          }
          TypeOrEntry::Type(Type::Double) => {
            read_bytes::<{ core::mem::size_of::<f64>() }>(&mut self.reader)?;
          }
          TypeOrEntry::Type(Type::String) => {
            let len = usize::try_from(read_varint(&mut self.reader)?)
              .map_err(|_| EpeeError::Short(usize::MAX))?;
            if self.reader.len() < len {
              Err(EpeeError::Short(len))?;
            }
            self.reader = &self.reader[len ..];
          }
          TypeOrEntry::Type(Type::Bool) => {
            read_bytes::<{ core::mem::size_of::<bool>() }>(&mut self.reader)?;
          }
          TypeOrEntry::Type(Type::Object) => {
            let amount_of_entries = read_varint(&mut self.reader)?;
            self.stack.push(TypeOrEntry::Entry, amount_of_entries)?;
          }
          TypeOrEntry::Entry => {
            let key = read_key(&mut self.reader)?;
            let (kind, len) = Type::read(&mut self.reader)?;
            let result_stack_depth = self.stack.depth();
            self.stack.push(TypeOrEntry::Type(kind), len)?;
            // If this is the requested `(name, type)`, yield it
            if (key == self.field_name.as_bytes()) && (kind == self.kind) {
              // Check if this was unexpectedly an array
              // Note this is imperfect in that an array of length 1 will be accepted as a unit
              if matches!(self.array, Array::Unit) && (len != 1) {
                Err(EpeeError::ArrayWhenUnit)?;
              }
              result = Some(((len, self.reader), result_stack_depth));
            }
          }
        }

        if let Some(((epee_len, bytes), stack_depth)) = result {
          if stack_depth == self.stack.depth() {
            let remaining_bytes = self.reader.len();
            let bytes_used_by_field = bytes.len() - remaining_bytes;
            return Ok(Some((epee_len, &bytes[.. bytes_used_by_field])));
          }
        }
      }

      if !self.reader.is_empty() {
        Err(EpeeError::TrailingBytes(self.reader.len()))?;
      }

      Ok(None)
    })()
    .transpose()
  }
}
