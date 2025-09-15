//! (Mostly) `epee`-compliant utilities for working with `epee`-encoded data.

/*
  `epee` is a bespoke serialization format, without any official documentation. The best
  specification is avilable here:

  https://github.com/jeffro256/serde_epee
    /tree/cbebe75475fb2c6073f7b2e058c88ceb2531de17PORTABLE_STORAGE.md

  monero-oxide originally used the `epee` encoder made available by monero-rs
  (https://github.com/monero-rs/monero-epee-bin-serde), yet stopped using it due to its panics and
  incompatibilities.

  monero-oxide than embedded a handrolled `epee` encoder, as needed to satisfy a single method only
  available via Monero's binary RPC. Today, we have an extended version of that handrolled encoder
  which is insufficient as an `epee` library yet sufficient for our needs.

  This file contains all the code which is expected to exactly follow the `epee` specification,
  with the following exceptions:
  - We don't support the `Array` type (type 13) as it's unused and lacking documentation
  - We may accept a _wider_ class of inputs than the `epee` library itself

  We do not support:
  - Encoding objects, instead hand-rolling the few requests we have to make manually
  - Decoding objects

  Instead, we support iterating through `epee` encoded values and finding all field definitions.
  This lets the caller jump to the binary blob representing an encoded value, and decode it
  themselves, without us actually deserializing the entire object. If we were to do that, we'd
  presumably require something akin to `serde_json::Value` or a proc macro. This is sufficient for
  our needs, much simpler, and should be trivial to verify it won't panic/face various exhaustion
  attacks.

  ---

  This module is usable on `core`, without `alloc`.
*/

#[derive(Debug)]
#[allow(dead_code)]
pub(super) enum EpeeError {
  /// The `epee`-encoded blob did not have the expected header.
  InvalidHeader,
  /// The `epee`-encoded blob was short, as discovered when trying to read `{0}` bytes.
  Short(usize),
  /// Unrecognized type specified.
  UnrecognizedType,
  /// Array found when a unit was expected.
  ArrayWhenUnit,
  /// The `epee`-encoded blob had {0} trailing bytes.
  TrailingBytes(usize),
  /// The depth limit was exceeded.
  DepthLimitExceeded,
}

// epee header, an 8-byte magic and a version
pub(crate) const HEADER: &[u8] = b"\x01\x11\x01\x01\x01\x01\x02\x01\x01";

// The type of the field being read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub(crate) enum Type {
  Int64 = 1,
  Int32 = 2,
  Int16 = 3,
  Int8 = 4,
  Uint64 = 5,
  Uint32 = 6,
  Uint16 = 7,
  Uint8 = 8,
  Double = 9,
  String = 10,
  Bool = 11,
  Object = 12,
  // Array = 13, // Unused and unsupported
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub(crate) enum Array {
  Unit = 0,
  Array = 1 << 7,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TypeOrEntry {
  // An epee-defined type
  Type(Type),
  // An entry (name, type, value)
  Entry,
}

impl TypeOrEntry {
  fn to_u8(self) -> u8 {
    match self {
      TypeOrEntry::Type(kind) => kind as u8,
      TypeOrEntry::Entry => u8::MAX,
    }
  }

  // Panics if not called with a valid serialization for a `TypeOrEntry`.
  fn from_u8(kind: u8) -> Self {
    match kind {
      0xff => TypeOrEntry::Entry,
      _ => TypeOrEntry::Type(
        Type::read(&mut [kind].as_slice())
          .expect("Type we converted to u8 could not be converted back")
          .0,
      ),
    }
  }
}

fn read_byte(reader: &mut &[u8]) -> Result<u8, EpeeError> {
  #[allow(clippy::len_zero)]
  if reader.len() < 1 {
    Err(EpeeError::Short(1))?;
  }
  let byte = reader[0];
  *reader = &reader[1 ..];
  Ok(byte)
}

pub(super) fn read_bool(reader: &mut &[u8]) -> Result<bool, EpeeError> {
  read_byte(reader).map(|byte| byte != 0)
}

fn read_bytes<'a, const N: usize>(reader: &mut &'a [u8]) -> Result<&'a [u8], EpeeError> {
  if reader.len() < N {
    Err(EpeeError::Short(N))?;
  }
  let res = &reader[.. N];
  *reader = &reader[N ..];
  Ok(res)
}

// Read a VarInt
pub(super) fn read_varint(reader: &mut &[u8]) -> Result<u64, EpeeError> {
  let vi_start = read_byte(reader)?;
  let len = match vi_start & 0b11 {
    0 => 1,
    1 => 2,
    2 => 4,
    3 => 8,
    _ => unreachable!(),
  };
  let mut vi = u64::from(vi_start >> 2);
  for i in 1 .. len {
    vi |= u64::from(read_byte(reader)?) << (((i - 1) * 8) + 6);
  }
  Ok(vi)
}

impl Type {
  // Read a type specification, including its length
  fn read(reader: &mut &[u8]) -> Result<(Self, u64), EpeeError> {
    let kind = read_byte(reader)?;
    let array = kind & (Array::Array as u8);
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

    let len = if array != 0 { read_varint(reader)? } else { 1 };

    Ok((kind, len))
  }
}

// Read a entry's key
fn read_key<'a>(reader: &mut &'a [u8]) -> Result<&'a [u8], EpeeError> {
  let len = usize::from(read_byte(reader)?);
  if reader.len() < len {
    Err(EpeeError::Short(len))?;
  }
  let res = &reader[.. len];
  *reader = &reader[len ..];
  Ok(res)
}

// https://github.com/monero-project/monero/blob/8d4c625713e3419573dfcc7119c8848f47cabbaa/
//   contrib/epee/include/storages/portable_storage_from_bin.h#L42
const EPEE_LIB_MAX_OBJECT_DEPTH: usize = 100;
// Explicitly set a larger depth in case we have slight differences in counting, so we can likely
// handle at least the set of objects Monero's `epee` library would handle
const MAX_OBJECT_DEPTH: usize = EPEE_LIB_MAX_OBJECT_DEPTH + 3;

#[repr(Rust, packed)]
struct PackedTypes([u8; MAX_OBJECT_DEPTH]);

/*
  epee allows nested objects, when we don't want to write a recursive function. The following
  `Seek::next` only reads a single item per iteration of its loop, using this stack to keep track
  of its depth.

  In order to not represent an array of 100 items as `Type::*; 100]`, which would enable a DoS by
  simply claiming there's 100 items when there isn't, we associate each item with its length as
  `(Type::*, 100)`. This causes our stack to grow only with depth, not width.
*/
struct Stack {
  remaining: [u64; MAX_OBJECT_DEPTH],
  types: PackedTypes,
  len: usize,
}
const _ASSERT_KILOBYTE_STACK: [(); 1024 - core::mem::size_of::<Stack>()] = [(); _];

impl Stack {
  fn new(initial_item: (TypeOrEntry, u64)) -> Self {
    let (kind, amount) = initial_item;
    Self {
      types: PackedTypes([kind.to_u8(); MAX_OBJECT_DEPTH]),
      remaining: [amount; MAX_OBJECT_DEPTH],
      len: 1,
    }
  }

  fn len(&self) -> usize {
    self.len
  }

  /// Panics if the stack is empty, if range checks are on.
  fn last(&mut self) -> (TypeOrEntry, &mut u64) {
    let i = self.len - 1;
    let kind = TypeOrEntry::from_u8(self.types.0[i]);
    let amount = &mut self.remaining[i];
    (kind, amount)
  }

  fn push(&mut self, kind: TypeOrEntry, amount: u64) -> Result<(), EpeeError> {
    if self.len == MAX_OBJECT_DEPTH {
      Err(EpeeError::DepthLimitExceeded)?;
    }
    self.types.0[self.len] = kind.to_u8();
    self.remaining[self.len] = amount;
    self.len += 1;
    Ok(())
  }

  /// Panics if the stack is empty, if range checks are on.
  fn pop(&mut self) {
    self.len -= 1;
  }
}

/// An iterator which seeks to all values of desired `(type, name)`.
struct Seek<'a> {
  reader: &'a [u8],
  kind: Type,
  array: Array,
  field_name: &'static str,
  stack: Stack,
}
const _ASSERT_KILOBYTE_SEEK: [(); 1024 - core::mem::size_of::<Seek>()] = [(); _];

impl<'a> Seek<'a> {
  fn new(
    mut reader: &'a [u8],
    kind: Type,
    array: Array,
    field_name: &'static str,
  ) -> Result<Self, EpeeError> {
    if read_bytes::<{ HEADER.len() }>(&mut reader).ok() != Some(HEADER) {
      Err(EpeeError::InvalidHeader)?;
    }
    let stack = Stack::new((TypeOrEntry::Type(Type::Object), 1u64));
    Ok(Seek { reader, kind, array, field_name, stack })
  }
}

impl<'a> Iterator for Seek<'a> {
  type Item = Result<(u64, &'a [u8]), EpeeError>;
  fn next(&mut self) -> Option<Self::Item> {
    (|| -> Result<_, EpeeError> {
      let mut result = None;

      while self.stack.len() > 0 {
        let (kind, remaining) = self.stack.last();

        // Decrement the amount remaining by one
        *remaining -= 1;
        if *remaining == 0 {
          self.stack.pop();
        }

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
            let result_stack_depth = self.stack.len();
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
          if stack_depth == self.stack.len() {
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

/// Seek all instances of a field with the desired `(type, name)`.
///
/// This yields the length of the item _as an `epee` value_ and a slice for the bytes of the
/// `epee`-encoded item. This will validate the resulting item is complete to the claimed length.
pub(super) fn seek_all<'a>(
  reader: &'a [u8],
  kind: Type,
  array: Array,
  field_name: &'static str,
) -> Result<impl Iterator<Item = Result<(u64, &'a [u8]), EpeeError>>, EpeeError> {
  Seek::new(reader, kind, array, field_name)
}
