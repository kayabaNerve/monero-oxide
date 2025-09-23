#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![no_std]

mod stack;
mod parser;

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
  /// Array found when a unit was expected.
  ArrayWhenUnit,
  /// The blob had {0} trailing bytes.
  TrailingBytes(usize),
  /// The depth limit was exceeded.
  DepthLimitExceeded,
}

/// The EPEE header.
// https://github.com/monero-project/monero/blob/8d4c625713e3419573dfcc7119c8848f47cabbaa
//  /contrib/epee/include/storages/portable_storage_base.h#L37-L38
pub const HEADER: [u8; 8] = *b"\x01\x11\x01\x01\x01\x01\x02\x01";
/// The supported version of the EPEE protocol.
// https://github.com/monero-project/monero/blob/8d4c625713e3419573dfcc7119c8848f47cabbaa
//  /contrib/epee/include/storages/portable_storage_base.h#L39
pub const VERSION: u8 = 1;

fn read_byte(reader: &mut &[u8]) -> Result<u8, EpeeError> {
  #[allow(clippy::len_zero)]
  if reader.len() < 1 {
    Err(EpeeError::Short(1))?;
  }
  let byte = reader[0];
  *reader = &reader[1 ..];
  Ok(byte)
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
fn read_varint(reader: &mut &[u8]) -> Result<u64, EpeeError> {
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

impl<'a> Seek<'a> {
  fn new(
    mut reader: &'a [u8],
    kind: Type,
    array: Array,
    field_name: &'static str,
  ) -> Result<Self, EpeeError> {
    if read_bytes::<{ HEADER.len() }>(&mut reader).ok() != Some(HEADER.as_slice()) {
      Err(EpeeError::InvalidHeader)?;
    }
    {
      let version = read_byte(&mut reader).ok();
      if version != Some(VERSION) {
        Err(EpeeError::InvalidVersion(version))?;
      }
    }
    let stack = Stack::new((TypeOrEntry::Type(Type::Object), 1u64));
    Ok(Seek { reader, kind, array, field_name, stack })
  }
}

/// Seek all instances of a field with the desired `(type, name)`.
///
/// This yields the length of the item _as an EPEE value_ and a slice for the bytes of the
/// EPEE-encoded item. This will validate the resulting item is complete to the claimed length.
pub fn seek_all<'a>(
  reader: &'a [u8],
  kind: Type,
  array: Array,
  field_name: &'static str,
) -> Result<impl Iterator<Item = Result<(u64, &'a [u8]), EpeeError>>, EpeeError> {
  Seek::new(reader, kind, array, field_name)
}
