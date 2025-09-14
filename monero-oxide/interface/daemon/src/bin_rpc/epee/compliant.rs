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

  This fille contains all the code which is expected to exactly follow the `epee` specification,
  with the following exceptions:
  - We don't support the `Array` type (type 13) as it's unused and lacking documentation

  We do not support:
  - Encoding objects, instead hand-rolling the few requests we have to make manually
  - Decoding objects

  Instead, we support iterating through `epee` encoded values and finding all field definitions.
  This lets the caller jump to the binary blob representing an encoded value, and decode it
  themselves, without us actually deserializing the entire object. If we were to do that, we'd
  presumably require something akin to `serde_json::Value` or a proc macro. This is sufficient for
  our needs, much simpler, and should be trivial to verify it won't panic/face various exhaustion
  attacks.
*/

#[allow(unused_imports)]
use std_shims::prelude::*;
use std_shims::io;

use monero_oxide::io::{read_byte, read_bytes, read_raw_vec};

// epee header, an 8-byte magic and a version
pub(crate) const HEADER: &[u8] = b"\x01\x11\x01\x01\x01\x01\x02\x01\x01";

// The type of the field being read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
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
enum TypeOrEntry {
  // An epee-defined types
  Type(Type),
  // An entry (name, type, value)
  Entry,
}

pub(crate) const ARRAY_FLAG: u8 = 1 << 7;

// Read a VarInt
pub(crate) fn read_vi<R: io::Read>(reader: &mut R) -> io::Result<u64> {
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
  pub(crate) fn read<R: io::Read>(reader: &mut R) -> io::Result<(Self, u64)> {
    let kind = read_byte(reader)?;
    let array = kind & ARRAY_FLAG;
    let kind = kind & (!ARRAY_FLAG);

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
      _ => Err(io::Error::other("unrecognized epee type"))?,
    };

    let len = if array != 0 { read_vi(reader)? } else { 1 };

    Ok((kind, len))
  }
}

// Read a entry's key
pub(crate) fn read_key<'a>(reader: &mut &'a [u8]) -> io::Result<&'a [u8]> {
  let len = usize::from(read_byte(reader)?);
  if reader.len() < len {
    Err(io::Error::new(io::ErrorKind::UnexpectedEof, "epee object ended while reading key"))?;
  }
  let res = &reader[.. len];
  *reader = &reader[len ..];
  Ok(res)
}

/// An iterator which seeks to all values of desired `(type, name)`.
struct Seek<'a> {
  reader: &'a [u8],
  expected_type: Type,
  field_name: &'static str,
  /*
    epee allows nested objects, when we don't want to write a recursive function. The following
    function only reads a single item per iteration of its loop, using a heap-allocated vector
    to keep track of its depth.

    In order to not represent an array of 100 items as `vec![Type::*; 100]`, which would enable a
    DoS by claiming there's 100 items when there isn't, we associate each item with its length
    as `(Type::*, 100)`. This causes our stack to grow only with depth, not width.
  */
  stack: Vec<(TypeOrEntry, u64)>,
}

impl<'a> Iterator for Seek<'a> {
  type Item = io::Result<(u64, &'a [u8])>;
  fn next(&mut self) -> Option<Self::Item> {
    (|| {
      while let Some((kind, remaining)) = self.stack.last_mut() {
        let kind = *kind;

        // Decrement the amount remaining by one
        *remaining = (*remaining)
          .checked_sub(1)
          .ok_or_else(|| io::Error::other("stack contained an exhausted item"))?;
        if *remaining == 0 {
          self.stack.pop();
        }

        match kind {
          TypeOrEntry::Type(Type::Int64) => {
            read_bytes::<_, { core::mem::size_of::<i64>() }>(&mut self.reader)?;
          }
          TypeOrEntry::Type(Type::Int32) => {
            read_bytes::<_, { core::mem::size_of::<i32>() }>(&mut self.reader)?;
          }
          TypeOrEntry::Type(Type::Int16) => {
            read_bytes::<_, { core::mem::size_of::<i16>() }>(&mut self.reader)?;
          }
          TypeOrEntry::Type(Type::Int8) => {
            read_bytes::<_, { core::mem::size_of::<i8>() }>(&mut self.reader)?;
          }
          TypeOrEntry::Type(Type::Uint64) => {
            read_bytes::<_, { core::mem::size_of::<u64>() }>(&mut self.reader)?;
          }
          TypeOrEntry::Type(Type::Uint32) => {
            read_bytes::<_, { core::mem::size_of::<u32>() }>(&mut self.reader)?;
          }
          TypeOrEntry::Type(Type::Uint16) => {
            read_bytes::<_, { core::mem::size_of::<u16>() }>(&mut self.reader)?;
          }
          TypeOrEntry::Type(Type::Uint8) => {
            read_bytes::<_, { core::mem::size_of::<u8>() }>(&mut self.reader)?;
          }
          TypeOrEntry::Type(Type::Double) => {
            read_bytes::<_, { core::mem::size_of::<f64>() }>(&mut self.reader)?;
          }
          TypeOrEntry::Type(Type::String) => {
            let len = read_vi(&mut self.reader)?;
            read_raw_vec(
              read_byte,
              len
                .try_into()
                .map_err(|_| io::Error::other("length of epee string exceed usize::MAX"))?,
              &mut self.reader,
            )?;
          }
          TypeOrEntry::Type(Type::Bool) => {
            read_bytes::<_, { core::mem::size_of::<bool>() }>(&mut self.reader)?;
          }
          TypeOrEntry::Type(Type::Object) => {
            self.stack.push((TypeOrEntry::Entry, read_vi(&mut self.reader)?));
          }
          TypeOrEntry::Entry => {
            let key = read_key(&mut self.reader)?;
            let (kind, len) = Type::read(&mut self.reader)?;
            self.stack.push((TypeOrEntry::Type(kind), len));
            // If this is the requested `(name, type)`, yield it
            if (key == self.field_name.as_bytes()) && (kind == self.expected_type) {
              return Ok(Some((len, self.reader)));
            }
          }
        }
      }
      Ok(None)
    })()
    .transpose()
  }
}

/// Seek all instances of a field with the desired `(type, name)`.
///
/// This yields the length of the item _as an epee value_ and a slice which starts with the
/// epee-encoded value. The slice will not be bounded by the end of the epee-encoded value.
pub(crate) fn seek_all<'a>(
  mut reader: &'a [u8],
  expected_type: Type,
  field_name: &'static str,
) -> io::Result<impl Iterator<Item = io::Result<(u64, &'a [u8])>>> {
  if read_bytes::<_, { HEADER.len() }>(&mut reader)? != HEADER {
    Err(io::Error::other("missing EPEE header"))?;
  }
  let stack = vec![(TypeOrEntry::Type(Type::Object), 1u64)];
  Ok(Seek { reader, expected_type, field_name, stack })
}

/// Seek the _only_ instance of a field with the desired `(type, name)`.
///
/// This yields the length of the item _as an epee value_ and a slice which starts with the
/// epee-encoded value. The slice will not be bounded by the end of the epee-encoded value.
pub(crate) fn seek(
  reader: &mut &[u8],
  expected_type: Type,
  field_name: &'static str,
) -> io::Result<Option<u64>> {
  if read_bytes::<_, { HEADER.len() }>(reader)? != HEADER {
    Err(io::Error::other("missing EPEE header"))?;
  }
  let len = {
    let stack = vec![(TypeOrEntry::Type(Type::Object), 1u64)];
    let mut iter = Seek { reader, expected_type, field_name, stack };
    let len_and_seeked = iter.next().transpose()?;
    *reader = iter.reader;
    if iter.next().is_some() {
      Err(io::Error::other("field was present multiple times within epee"))?;
    }
    len_and_seeked.map(|(len, _seeked)| len)
  };
  Ok(len)
}
