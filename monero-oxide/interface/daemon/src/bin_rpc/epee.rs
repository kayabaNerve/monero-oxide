#[allow(unused_imports)]
use std_shims::prelude::*;

use monero_oxide::{
  io::{CompressedPoint, read_u64},
  transaction::Transaction,
  block::Block,
};

use monero_epee::{EpeeError as OriginalEpeeError, EpeeEntry, Epee};
pub(crate) use monero_epee::{HEADER, Type, Array};

use crate::{InterfaceError, RingCtOutputInformation};

pub(crate) const VERSION: u8 = 1;

struct EpeeError(OriginalEpeeError);
impl From<EpeeError> for InterfaceError {
  fn from(err: EpeeError) -> InterfaceError {
    InterfaceError::InvalidInterface(format!("EpeeError::{:?}", err.0))
  }
}

/// Read a `Vec<u64>` from a `epee`-encoded buffer.
///
/// This assumes the claimed length is actually present within the byte buffer. This will be the
/// case for an array encoded within a length-checked string
fn read_u64_array_from_epee(len: usize, mut epee: &[u8]) -> Result<Vec<u64>, InterfaceError> {
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

/*
  `EpeeEntry` must live for less time than its iterator, yet this makes it very tricky to work
  with. If we wrote a function which takes an iterator, then returns an entry, the entry's
  lifetime _must_ outlive the function (because it's returned from the function). At the same time,
  this prevents the iterator from being iterated within the function's body over because it's
  mutably borrowed for a lifetime exceeding the function.

  The solution, however ugly, is to handle the field _inside_ the iteration over the fields. We use
  the following macro to generate the code for this.
*/
macro_rules! optional_field {
  ($fields: ident, $field: literal, $body: expr) => {
    loop {
      let Some(entry) = $fields.next() else { break Ok::<_, EpeeError>(None) };
      let entry = match entry {
        Ok(entry) => entry,
        Err(e) => Err(EpeeError(e))?,
      };
      if entry.0 == $field.as_bytes() {
        break Ok(Some($body(entry.1).map_err(EpeeError)?));
      }
    }
  };
}
macro_rules! field {
  ($fields: ident, $field: literal, $body: expr) => {
    optional_field!($fields, $field, $body)?.ok_or_else(|| {
      InterfaceError::InvalidInterface(format!("expected field {} but it wasn't present", $field))
    })
  };
}

/// A wrapper to call `to_fixed_len_str` via, since `field` assumes the body only takes a single
/// argument.
// Unfortunately, callers cannot simply use a lambda due to needing to define these lifetimes.
struct FixedLenStr(usize);
impl FixedLenStr {
  #[allow(clippy::wrong_self_convention)]
  fn to_fixed_len_str<'encoding, 'parent>(
    self,
    entry: EpeeEntry<'encoding, 'parent, &'encoding [u8]>,
  ) -> Result<&'encoding [u8], monero_epee::EpeeError> {
    entry.to_fixed_len_str(self.0)
  }
}

/// Check the `status` field within an `epee`-encoded object.
pub(crate) fn check_status(epee: &[u8]) -> Result<(), InterfaceError> {
  let mut epee = Epee::new(epee).map_err(EpeeError)?;
  let mut epee = epee.fields().map_err(EpeeError)?;
  let status = field!(epee, "status", EpeeEntry::to_str)?;
  if status != b"OK" {
    return Err(InterfaceError::InvalidInterface("epee `status` wasn't \"OK\"".to_string()));
  }
  Ok(())
}

/// Extract the `start_height` field from the response to `get_output_distribution.bin`.
///
/// This assumes only a single distribution was requested by the caller.
pub(crate) fn extract_start_height(epee: &[u8]) -> Result<usize, InterfaceError> {
  let mut epee = Epee::new(epee).map_err(EpeeError)?;
  let mut epee = epee.fields().map_err(EpeeError)?;
  /*
    `distributions` is technically an array, but we assume only one distribution was requested,
    which allows us to treat it as a unit value and immediately access its fields.
  */
  let mut distributions = field!(epee, "distributions", EpeeEntry::fields)?;
  let start_height = field!(distributions, "start_height", EpeeEntry::to_u64)?;
  usize::try_from(start_height).map_err(|_| {
    InterfaceError::InvalidInterface("`start_height` did not fit within a `usize`".to_string())
  })
}

/// Extract the `distribution` field from the response to `get_output_distribution.bin`.
///
/// This assumes only a single distribution was requested by the caller.
pub(crate) fn extract_distribution(
  epee: &[u8],
  expected_len: usize,
) -> Result<Vec<u64>, InterfaceError> {
  let mut epee = Epee::new(epee).map_err(EpeeError)?;
  let mut epee = epee.fields().map_err(EpeeError)?;
  let mut distributions = field!(epee, "distributions", EpeeEntry::fields)?;

  let fixed_len_str = FixedLenStr(expected_len.checked_mul(8).ok_or_else(|| {
    InterfaceError::InternalError(
      "requested a distribution whose byte length doesn't fit within a `usize`".to_string(),
    )
  })?);
  let distribution =
    field!(distributions, "distribution", |value| fixed_len_str.to_fixed_len_str(value))?;
  read_u64_array_from_epee(expected_len, distribution)
}

/// Accumulate a set of outs from `get_outs.bin`.
pub(crate) fn accumulate_outs(
  epee: &[u8],
  amount: usize,
  res: &mut Vec<RingCtOutputInformation>,
) -> Result<(), InterfaceError> {
  let start = res.len();

  let mut epee = Epee::new(epee).map_err(EpeeError)?;
  let mut epee = epee.fields().map_err(EpeeError)?;
  let mut outs = field!(epee, "outs", EpeeEntry::iterate)?;
  while let Some(out) = outs.next() {
    let mut out = out.map_err(EpeeError)?.fields().map_err(EpeeError)?;

    let mut block_number = None;
    let mut key = None;
    let mut commitment = None;
    let mut transaction = None;
    let mut unlocked = None;

    while let Some(out) = out.next() {
      let (item_key, value) = out.map_err(EpeeError)?;
      match item_key {
        b"height" => block_number = Some(value.to_u64().map_err(EpeeError)?),
        b"key" => {
          key = Some(CompressedPoint(
            value.to_fixed_len_str(32).map_err(EpeeError)?.try_into().unwrap(),
          ))
        }
        b"mask" => {
          commitment = Some(CompressedPoint(
            value.to_fixed_len_str(32).map_err(EpeeError)?.try_into().unwrap(),
          ))
        }
        b"txid" => {
          transaction = Some(value.to_fixed_len_str(32).map_err(EpeeError)?.try_into().unwrap())
        }
        b"unlocked" => unlocked = Some(value.to_bool().map_err(EpeeError)?),
        _ => continue,
      }
    }

    let Some((block_number, key, commitment, transaction, unlocked)) =
      (|| Some((block_number?, key?, commitment?, transaction?, unlocked?)))()
    else {
      Err(InterfaceError::InvalidInterface(
        "missing field in output from `get_outs.bin`".to_string(),
      ))?
    };

    let block_number = usize::try_from(block_number).map_err(|_| {
      InterfaceError::InvalidInterface(
        "`get_outs.bin` returned an block number not representable within a `usize`".to_string(),
      )
    })?;
    let commitment = commitment.decompress().ok_or_else(|| {
      InterfaceError::InvalidInterface("`get_outs.bin` returned an invalid commitment".to_string())
    })?;

    res.push(RingCtOutputInformation { block_number, key, commitment, transaction, unlocked });
  }

  if res.len() != (start + amount) {
    Err(InterfaceError::InvalidInterface(
      "`get_outs.bin` had a distinct amount of outs than expected".to_string(),
    ))?;
  }

  Ok(())
}

pub(crate) fn extract_blocks_from_blocks_bin(
  blocks_bin: &[u8],
) -> Result<impl use<'_> + Iterator<Item = Result<Block, InterfaceError>>, InterfaceError> {
  let mut epee = Epee::new(blocks_bin).map_err(EpeeError)?;
  let mut epee = epee.fields().map_err(EpeeError)?;
  let Some(mut blocks) = optional_field!(epee, "blocks", EpeeEntry::iterate)? else {
    return Ok(vec![].into_iter());
  };

  let mut res = vec![];
  while let Some(block) = blocks.next() {
    let mut block = block.map_err(EpeeError)?.fields().map_err(EpeeError)?;
    let mut block = field!(block, "block", EpeeEntry::to_str)?;
    res.push(
      Block::read(&mut block)
        .map_err(|e| InterfaceError::InvalidInterface(format!("invalid block: {e:?}"))),
    );
    if !block.is_empty() {
      Err(InterfaceError::InvalidInterface("block had extraneous bytes after it".to_string()))?;
    }
  }
  Ok(res.into_iter())
}

pub(crate) fn extract_txs_from_blocks_bin(
  blocks_bin: &[u8],
) -> Result<impl use<'_> + Iterator<Item = Result<Transaction, InterfaceError>>, InterfaceError> {
  let mut epee = Epee::new(blocks_bin).map_err(EpeeError)?;
  let mut epee = epee.fields().map_err(EpeeError)?;
  let Some(mut blocks) = optional_field!(epee, "blocks", EpeeEntry::iterate)? else {
    return Ok(vec![].into_iter());
  };

  let mut res = vec![];
  while let Some(block) = blocks.next() {
    let mut block = block.map_err(EpeeError)?.fields().map_err(EpeeError)?;
    let mut transactions = field!(block, "txs", EpeeEntry::iterate)?;
    while let Some(transaction) = transactions.next() {
      let transaction = transaction.map_err(EpeeError)?;
      let mut transaction = transaction.to_str().map_err(EpeeError)?;
      res.push(
        Transaction::read(&mut transaction)
          .map_err(|e| InterfaceError::InvalidInterface(format!("invalid transaction: {e:?}"))),
      );
      if !transaction.is_empty() {
        Err(InterfaceError::InvalidInterface(
          "transaction had extraneous bytes after it".to_string(),
        ))?;
      }
    }
  }
  Ok(res.into_iter())
}

pub(crate) fn extract_output_indexes(epee: &[u8]) -> Result<Vec<u64>, InterfaceError> {
  let mut epee = Epee::new(epee).map_err(EpeeError)?;
  let mut epee = epee.fields().map_err(EpeeError)?;
  let Some(mut indexes) = optional_field!(epee, "o_indexes", EpeeEntry::iterate)? else {
    return Ok(vec![]);
  };

  let mut res = vec![];
  while let Some(index) = indexes.next() {
    res.push(index.map_err(EpeeError)?.to_u64().map_err(EpeeError)?);
  }
  Ok(res)
}
