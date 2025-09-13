// https://github.com/jeffro256/serde_epee
//  /tree/cbebe75475fb2c6073f7b2e058c88ceb2531de17PORTABLE_STORAGE.md
// for the best documentation on the epee specification.

#[allow(unused_imports)]
use std_shims::prelude::*;
use std_shims::io;

use monero_oxide::io::{CompressedPoint, read_byte, read_u64, read_bytes, read_raw_vec};

use crate::{InterfaceError, RingCtOutputInformation};

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

  // An internal (non-epee) type to flag we have to read an entry (key, type, and value)
  InternalEntry,
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

pub(crate) fn read_key<'a>(reader: &mut &'a [u8]) -> io::Result<&'a [u8]> {
  let len = usize::from(read_byte(reader)?);
  if reader.len() < len {
    Err(io::Error::new(io::ErrorKind::UnexpectedEof, "epee object ended while reading key"))?;
  }
  let res = &reader[.. len];
  *reader = &reader[len ..];
  Ok(res)
}

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
  stack: Vec<(Type, u64)>,
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
          Type::Int64 => {
            read_bytes::<_, { core::mem::size_of::<i64>() }>(&mut self.reader)?;
          }
          Type::Int32 => {
            read_bytes::<_, { core::mem::size_of::<i32>() }>(&mut self.reader)?;
          }
          Type::Int16 => {
            read_bytes::<_, { core::mem::size_of::<i16>() }>(&mut self.reader)?;
          }
          Type::Int8 => {
            read_bytes::<_, { core::mem::size_of::<i8>() }>(&mut self.reader)?;
          }
          Type::Uint64 => {
            read_bytes::<_, { core::mem::size_of::<u64>() }>(&mut self.reader)?;
          }
          Type::Uint32 => {
            read_bytes::<_, { core::mem::size_of::<u32>() }>(&mut self.reader)?;
          }
          Type::Uint16 => {
            read_bytes::<_, { core::mem::size_of::<u16>() }>(&mut self.reader)?;
          }
          Type::Uint8 => {
            read_bytes::<_, { core::mem::size_of::<u8>() }>(&mut self.reader)?;
          }
          Type::Double => {
            read_bytes::<_, { core::mem::size_of::<f64>() }>(&mut self.reader)?;
          }
          Type::String => {
            let len = read_vi(&mut self.reader)?;
            read_raw_vec(
              read_byte,
              len
                .try_into()
                .map_err(|_| io::Error::other("length of epee string exceed usize::MAX"))?,
              &mut self.reader,
            )?;
          }
          Type::Bool => {
            read_bytes::<_, { core::mem::size_of::<bool>() }>(&mut self.reader)?;
          }
          Type::Object => {
            self.stack.push((Type::InternalEntry, read_vi(&mut self.reader)?));
          }
          Type::InternalEntry => {
            let key = read_key(&mut self.reader)?;
            let (kind, len) = Type::read(&mut self.reader)?;
            self.stack.push((kind, len));
            if key == self.field_name.as_bytes() {
              if kind != self.expected_type {
                Err(io::Error::other(format!(
                  "seeked epee field `{}` was type {kind:?}, expected {:?}",
                  self.field_name, self.expected_type,
                )))?;
              }
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

pub(crate) fn seek_all<'a>(
  mut reader: &'a [u8],
  expected_type: Type,
  field_name: &'static str,
) -> io::Result<impl Iterator<Item = io::Result<(u64, &'a [u8])>>> {
  if read_bytes::<_, { HEADER.len() }>(&mut reader)? != HEADER {
    Err(io::Error::other("missing EPEE header"))?;
  }
  let stack = vec![(Type::Object, 1u64)];
  Ok(Seek { reader, expected_type, field_name, stack })
}

pub(crate) fn seek(
  reader: &mut &[u8],
  expected_type: Type,
  field_name: &'static str,
) -> io::Result<Option<u64>> {
  if read_bytes::<_, { HEADER.len() }>(reader)? != HEADER {
    Err(io::Error::other("missing EPEE header"))?;
  }
  let len = {
    let stack = vec![(Type::Object, 1u64)];
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

pub(crate) fn check_status(mut epee: &[u8]) -> Result<(), InterfaceError> {
  if seek(&mut epee, Type::String, "status")
    .map_err(|e| InterfaceError::InvalidInterface(format!("couldn't seek `status`: {e:?}")))? !=
    Some(1)
  {
    Err(InterfaceError::InvalidInterface("`status` was an array".to_string()))?;
  }
  if (epee.len() < 3) || (epee[0] != (2u8 << 2)) || (&epee[1 .. 3] != "OK".as_bytes()) {
    Err(InterfaceError::InvalidInterface("epee `status` wasn't \"OK\"".to_string()))?;
  }
  Ok(())
}

pub(crate) fn extract_start_height(mut distributions: &[u8]) -> Result<usize, InterfaceError> {
  if seek(&mut distributions, Type::Uint64, "start_height").map_err(|e| {
    let err_msg = format!("couldn't seek `start_height`: {e:?}");
    InterfaceError::InvalidInterface(err_msg)
  })? !=
    Some(1)
  {
    Err(InterfaceError::InvalidInterface(
      "distribution response was missing `start_height`".to_string(),
    ))?;
  }
  let start_height = read_u64(&mut distributions).map_err(|e| {
    InterfaceError::InvalidInterface(format!("`start_height` was incorrectly encoded: {e:?}"))
  })?;
  usize::try_from(start_height).map_err(|_| {
    InterfaceError::InvalidInterface("`start_height` did not fit within a `usize`".to_string())
  })
}

pub(crate) fn extract_distribution(mut distributions: &[u8]) -> Result<Vec<u64>, InterfaceError> {
  let outer_len = seek(&mut distributions, Type::String, "distribution").map_err(|e| {
    InterfaceError::InvalidInterface(format!("couldn't seek `distribution`: {e:?}"))
  })?;
  #[allow(clippy::map_unwrap_or)]
  let len = outer_len
    .map(|outer_len| {
      if outer_len != 1 {
        return Err(InterfaceError::InvalidInterface("outer `distribution` was array".to_string()));
      }
      read_vi(&mut distributions).map(|byte_len| byte_len / 8).map_err(|e| {
        InterfaceError::InvalidInterface(format!(
          "`distribution` wasn't a correctly encoded string: {e:?}"
        ))
      })
    })
    .unwrap_or(Ok(0))?;
  let mut distribution = vec![];
  for _ in 0 .. len {
    distribution.push(read_u64(&mut distributions).map_err(|e| {
      InterfaceError::InvalidInterface(format!("incomplete `distribution`: {e:?}"))
    })?);
  }
  Ok(distribution)
}

pub(crate) fn accumulate_outs(
  outs: &[u8],
  amount: usize,
  res: &mut Vec<RingCtOutputInformation>,
) -> io::Result<()> {
  let start = res.len();

  let mut block_numbers = seek_all(outs, Type::Uint64, "height")?;
  let mut keys = seek_all(outs, Type::String, "key")?;
  let mut commitments = seek_all(outs, Type::String, "mask")?;
  let mut transactions = seek_all(outs, Type::String, "txid")?;
  let mut unlocked = seek_all(outs, Type::Bool, "unlocked")?;

  for ((((block_number, key), commitment), transaction), unlocked) in (&mut block_numbers)
    .zip(&mut keys)
    .zip(&mut commitments)
    .zip(&mut transactions)
    .zip(&mut unlocked)
    .take(amount)
  {
    let block_number = usize::try_from(read_u64(&mut block_number?.1)?)
      .map_err(|_| io::Error::other("`height` wasn't representable within a `usize`"))?;

    let mut key = key?.1;
    let _ = read_vi(&mut key)?;
    let key = CompressedPoint(read_bytes::<_, 32>(&mut key)?);

    let mut commitment = commitment?.1;
    let _ = read_vi(&mut commitment)?;
    let commitment = CompressedPoint(read_bytes::<_, 32>(&mut commitment)?)
      .decompress()
      .ok_or_else(|| io::Error::other("`get_outs` commitment was invalid"))?;

    let mut transaction = transaction?.1;
    let _ = read_vi(&mut transaction)?;
    let transaction = read_bytes::<_, 32>(&mut transaction)?;

    let unlocked = read_byte(&mut unlocked?.1)? != 0;

    res.push(RingCtOutputInformation { block_number, key, commitment, transaction, unlocked });
  }

  if res.len() != (start + amount) {
    Err(io::Error::other("`get_outs` had less outs than expected"))?;
  }

  if block_numbers.next().is_some() ||
    keys.next().is_some() ||
    commitments.next().is_some() ||
    transactions.next().is_some() ||
    unlocked.next().is_some()
  {
    Err(io::Error::other("`get_outs` unexpectedly had more outs"))?;
  }

  Ok(())
}
