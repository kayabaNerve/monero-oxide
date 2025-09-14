#[allow(unused_imports)]
use std_shims::prelude::*;
use std_shims::io;

use monero_oxide::{
  io::{CompressedPoint, read_byte, read_u64, read_bytes},
  transaction::{Pruned, Transaction},
  block::Block,
};

use crate::{InterfaceError, PrunedTransactionWithPrunableHash, RingCtOutputInformation};

mod compliant;
pub(crate) use compliant::*;

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

pub(crate) fn extract_blocks_from_blocks_bin(
  blocks: &[u8],
) -> Result<impl use<'_> + Iterator<Item = Result<Block, InterfaceError>>, InterfaceError> {
  let blocks = seek_all(blocks, Type::String, "block").map_err(|e| {
    InterfaceError::InvalidInterface(format!(
      "couldn't `seek_all` for `get_blocks_by_height.bin`: {e:?}"
    ))
  })?;

  Ok(blocks.map(|block| {
    let mut block_string = block
      .map_err(|e| InterfaceError::InvalidInterface(format!("couldn't seek `block`: {e:?}")))?
      .1;
    let _ = read_vi(&mut block_string)
      .map_err(|_| InterfaceError::InvalidInterface("couldn't read block's length".to_string()))?;
    Block::read(&mut block_string)
      .map_err(|_| InterfaceError::InvalidInterface("invalid block".to_string()))
  }))
}

pub(crate) fn extract_txs_from_blocks_bin(
  blocks: &[u8],
) -> Result<
  impl use<'_> + Iterator<Item = Result<PrunedTransactionWithPrunableHash, InterfaceError>>,
  InterfaceError,
> {
  let mut txs = seek_all(blocks, Type::String, "blob").map_err(|e| {
    InterfaceError::InvalidInterface(format!(
      "couldn't `seek_all` for `get_blocks_by_height.bin`: {e:?}"
    ))
  })?;
  let mut prunable_hashes = seek_all(blocks, Type::String, "prunable_hash").map_err(|e| {
    InterfaceError::InvalidInterface(format!(
      "couldn't `seek_all` for `get_blocks_by_height.bin`: {e:?}"
    ))
  })?;

  Ok(core::iter::from_fn(move || {
    let tx = txs.next();
    let prunable_hash = prunable_hashes.next();
    if tx.is_some() != prunable_hash.is_some() {
      return Some(Err(InterfaceError::InvalidInterface(
        "node had unbalanced amount of transactions, prunable hashes".to_string(),
      )));
    }

    let tx = tx?.map_err(|e| {
      InterfaceError::InvalidInterface(format!("couldn't seek transaction `block`: {e:?}"))
    });
    let prunable_hash = prunable_hash?.map_err(|e| {
      InterfaceError::InvalidInterface(format!("couldn't seek transaction `prunable_hash`: {e:?}"))
    });
    Some(tx.and_then(|(_, mut tx)| {
      prunable_hash.and_then(|(_, mut prunable_hash)| {
        let _ = read_vi(&mut tx).map_err(|_| {
          InterfaceError::InvalidInterface("couldn't read transactions's length".to_string())
        })?;
        let tx = Transaction::<Pruned>::read(&mut tx).map_err(|e| {
          InterfaceError::InvalidInterface(format!(
            "blocks.bin contains invalid pruned transaction: {e:?}"
          ))
        })?;
        let _ = read_vi(&mut prunable_hash).map_err(|_| {
          InterfaceError::InvalidInterface("couldn't read prumnable hash's length".to_string())
        })?;
        let prunable_hash = read_bytes::<_, 32>(&mut prunable_hash).map_err(|e| {
          InterfaceError::InvalidInterface(format!(
            "couldn't read prunable hash from blocks.bin: {e:?}",
          ))
        })?;

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
