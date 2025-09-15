use core::fmt::Display;

#[allow(unused_imports)]
use std_shims::prelude::*;

use monero_oxide::{
  io::{CompressedPoint, read_u64},
  transaction::{Pruned, Transaction},
  block::Block,
};

use crate::{InterfaceError, PrunedTransactionWithPrunableHash, RingCtOutputInformation};

mod compliant;
use compliant::{EpeeError, read_varint, seek_all};
pub(crate) use compliant::{HEADER, Type, Array};

impl From<EpeeError> for InterfaceError {
  fn from(err: EpeeError) -> InterfaceError {
    InterfaceError::InvalidInterface(format!("EpeeError::{err:?}"))
  }
}

/// Seek the _only_ instance of a field with the desired `(type, name)`.
///
/// This yields the length of the item _as an `epee` value_ and a slice for the bytes of the
/// `epee`-encoded item, or `None` if no instances were found. This will validate the resulting
/// item is complete to the claimed length.
///
/// Errors if multiple instances of the field are found.
fn seek_once<'a>(
  reader: &'a [u8],
  kind: Type,
  array: Array,
  field_name: &'static str,
) -> Result<Option<(u64, &'a [u8])>, InterfaceError> {
  let mut iter = seek_all(reader, kind, array, field_name)?;
  let result = iter.next().transpose()?;
  // Check no other instances exist
  if iter.next().is_some() {
    Err(InterfaceError::InvalidInterface(
      "field was present multiple times within `epee`-encoded value".to_string(),
    ))?;
  }
  Ok(result)
}

/// A helper to access the data within an `epee` string.
///
/// If `expected_len = Some(_)`, the length of the string is checked to align.
fn decapsulate_string(
  mut string: &[u8],
  expected_len: Option<usize>,
) -> Result<&[u8], InterfaceError> {
  let declared_len = read_varint(&mut string)?;
  if declared_len != u64::try_from(string.len()).expect("byte buffer had length exceeding 2**64?") {
    Err(InterfaceError::InvalidInterface(format!(
      "string with declared length of {declared_len} had {} bytes",
      string.len()
    )))?;
  }
  if let Some(expected_len) = expected_len {
    if string.len() != expected_len {
      Err(InterfaceError::InvalidInterface(format!(
        "string had length {} when {expected_len} was expected",
        string.len()
      )))?;
    }
  }
  Ok(string)
}

fn decapsulate_thirty_two_byte_array_from_string(
  string: &[u8],
) -> Result<[u8; 32], InterfaceError> {
  Ok(
    decapsulate_string(string, Some(32))?
      .try_into()
      .expect("32-byte string couldn't be converted to 32-byte array"),
  )
}

/// Read a `Vec<u64>` from a `epee`-encoded buffer.
///
/// This assumes the claimed length is actually present within the byte buffer. This will be the
/// case for an array yielded by `Seek::next` or buffers from `decapsulate_string(_, Some(_))`.
fn read_u64_array_from_epee<L: Copy + TryInto<usize> + Display>(
  len: L,
  mut epee: &[u8],
) -> Result<Vec<u64>, InterfaceError> {
  let len: usize = len.try_into().map_err(|_| {
    InterfaceError::InvalidInterface(format!("array's length exceeded `usize::MAX`: {len}"))
  })?;
  // This is safe to pre-allocate due to the byte buffer being prior-checked to have this many items
  let mut res = Vec::with_capacity(len);
  for _ in 0 .. len {
    res.push(read_u64(&mut epee).map_err(|_| {
      InterfaceError::InternalError(
        "incomplete array despite precondition the array is complete".to_string(),
      )
    })?);
  }
  Ok(res)
}

/// Check the `status` field within an `epee`-encoded object.
pub(crate) fn check_status(epee: &[u8]) -> Result<(), InterfaceError> {
  if seek_once(epee, Type::String, Array::Unit, "status")? != Some((1, &[2 << 2, b'O', b'K'])) {
    Err(InterfaceError::InvalidInterface("epee `status` wasn't \"OK\"".to_string()))?;
  }
  Ok(())
}

/// Extract the `start_height` field from the response to `get_output_distribution.bin`.
pub(crate) fn extract_start_height(distributions: &[u8]) -> Result<usize, InterfaceError> {
  let Some((_epee_len, mut distributions)) =
    seek_once(distributions, Type::Uint64, Array::Unit, "start_height")?
  else {
    Err(InterfaceError::InvalidInterface(
      "distribution response was missing `start_height`".to_string(),
    ))?
  };
  let start_height = read_u64(&mut distributions).map_err(|e| {
    InterfaceError::InvalidInterface(format!("`start_height` was incorrectly encoded: {e:?}"))
  })?;
  usize::try_from(start_height).map_err(|_| {
    InterfaceError::InvalidInterface("`start_height` did not fit within a `usize`".to_string())
  })
}

/// Extract the `distribution` field from the response to `get_output_distribution.bin`.
///
/// This assumes only a single distribution was requested by the user.
pub(crate) fn extract_distribution(
  epee: &[u8],
  expected_len: usize,
) -> Result<Vec<u64>, InterfaceError> {
  let Some((_epee_len, epee)) = seek_once(epee, Type::String, Array::Unit, "distribution")? else {
    return Ok(vec![]);
  };

  let Some(expected_byte_len) = expected_len.checked_mul(8) else {
    Err(InterfaceError::InternalError(
      "requested a longer distribution than whose byte-length is representable".to_string(),
    ))?
  };
  let epee = decapsulate_string(epee, Some(expected_byte_len))?;
  read_u64_array_from_epee(expected_len, epee)
}

/// Accumulate a set of outs from `get_outs.bin`.
pub(crate) fn accumulate_outs(
  outs: &[u8],
  amount: usize,
  res: &mut Vec<RingCtOutputInformation>,
) -> Result<(), InterfaceError> {
  let start = res.len();

  // Create iterators for each of the fields within each out's struct
  let mut block_numbers = seek_all(outs, Type::Uint64, Array::Unit, "height")?;
  let mut keys = seek_all(outs, Type::String, Array::Unit, "key")?;
  let mut commitments = seek_all(outs, Type::String, Array::Unit, "mask")?;
  let mut transactions = seek_all(outs, Type::String, Array::Unit, "txid")?;
  let mut unlocked = seek_all(outs, Type::Bool, Array::Unit, "unlocked")?;

  for ((((block_number, key), commitment), transaction), unlocked) in (&mut block_numbers)
    .zip(&mut keys)
    .zip(&mut commitments)
    .zip(&mut transactions)
    .zip(&mut unlocked)
    .take(amount)
  {
    let block_number = read_u64(&mut block_number?.1).map_err(|e| {
      InterfaceError::InvalidInterface(format!(
        "`epee` yielded `Uint64` yet couldn't read `Uint64` from it: {e:?}"
      ))
    })?;
    let block_number = usize::try_from(block_number).map_err(|_| {
      InterfaceError::InvalidInterface(
        "out `height` wasn't representable within a `usize`".to_string(),
      )
    })?;

    let key = CompressedPoint(decapsulate_thirty_two_byte_array_from_string(key?.1)?);
    let commitment = CompressedPoint(decapsulate_thirty_two_byte_array_from_string(commitment?.1)?)
      .decompress()
      .ok_or_else(|| {
        InterfaceError::InvalidInterface("`get_outs` returned an invalid commitment".to_string())
      })?;
    let transaction = decapsulate_thirty_two_byte_array_from_string(transaction?.1)?;
    let unlocked = compliant::read_bool(&mut unlocked?.1)?;

    res.push(RingCtOutputInformation { block_number, key, commitment, transaction, unlocked });
  }

  if res.len() != (start + amount) {
    Err(InterfaceError::InvalidInterface("`get_outs` had less outs than expected".to_string()))?;
  }

  if block_numbers.next().is_some() ||
    keys.next().is_some() ||
    commitments.next().is_some() ||
    transactions.next().is_some() ||
    unlocked.next().is_some()
  {
    Err(InterfaceError::InvalidInterface("`get_outs` unexpectedly had more outs".to_string()))?;
  }

  Ok(())
}

pub(crate) fn extract_blocks_from_blocks_bin(
  blocks_bin: &[u8],
) -> Result<impl use<'_> + Iterator<Item = Result<Block, InterfaceError>>, InterfaceError> {
  let blocks = seek_all(blocks_bin, Type::String, Array::Unit, "block")?;

  Ok(blocks.map(|block| {
    Block::read(&mut decapsulate_string(block?.1, None)?)
      .map_err(|_| InterfaceError::InvalidInterface("invalid block".to_string()))
  }))
}

pub(crate) fn extract_txs_from_blocks_bin(
  blocks_bin: &[u8],
) -> Result<
  impl use<'_> + Iterator<Item = Result<PrunedTransactionWithPrunableHash, InterfaceError>>,
  InterfaceError,
> {
  let mut txs = seek_all(blocks_bin, Type::String, Array::Unit, "blob")?;
  let mut prunable_hashes = seek_all(blocks_bin, Type::String, Array::Unit, "prunable_hash")?;

  Ok(core::iter::from_fn(move || {
    let tx = txs.next();
    let prunable_hash = prunable_hashes.next();

    let (tx, prunable_hash) = match (tx, prunable_hash) {
      (Some(tx), Some(prunable_hash)) => {
        (tx.map_err(InterfaceError::from), prunable_hash.map_err(InterfaceError::from))
      }
      (None, None) => None?,
      _ => {
        return Some(Err(InterfaceError::InvalidInterface(
          "node had unbalanced amount of transactions, prunable hashes".to_string(),
        )))
      }
    };

    Some(tx.and_then(|(_epee_len, tx)| {
      prunable_hash.and_then(|(_epee_len, prunable_hash)| {
        let tx = Transaction::<Pruned>::read(&mut decapsulate_string(tx, None)?).map_err(|e| {
          InterfaceError::InvalidInterface(format!(
            "blocks.bin contains invalid pruned transaction: {e:?}"
          ))
        })?;
        let prunable_hash = decapsulate_thirty_two_byte_array_from_string(prunable_hash)?;

        Ok(if matches!(tx, Transaction::V1 { .. }) {
          PrunedTransactionWithPrunableHash::new(tx, None)
            .expect("v1 transaction expected prunable hash")
        } else {
          PrunedTransactionWithPrunableHash::new(tx, Some(prunable_hash))
            .expect("non-v1 transaction expected no prunable hash")
        })
      })
    }))
  }))
}

pub(crate) fn extract_first_output_indexes_from_block_bin(
  block_bin: &[u8],
) -> Result<impl use<'_> + Iterator<Item = Result<Option<u64>, InterfaceError>>, InterfaceError> {
  let output_indexes_per_transaction = seek_all(block_bin, Type::Uint64, Array::Array, "indices")?;
  Ok(output_indexes_per_transaction.map(|epee| {
    let (epee_len, mut epee) = epee?;
    Ok(if epee_len > 0 {
      Some(read_u64(&mut epee).map_err(|e| {
        InterfaceError::InvalidInterface(format!(
          "couldn't read `u64` from `epee` array with at least one: {e:?}"
        ))
      })?)
    } else {
      None
    })
  }))
}

pub(crate) fn extract_output_indexes(epee: &[u8]) -> Result<Vec<u64>, InterfaceError> {
  let Some((len, epee)) = seek_once(epee, Type::Uint64, Array::Array, "o_indexes")? else {
    return Ok(vec![]);
  };
  read_u64_array_from_epee(len, epee)
}
