#[allow(unused_imports)]
use std_shims::prelude::*;

use monero_oxide::{
  io::CompressedPoint,
  transaction::{Pruned, Transaction},
  block::Block,
};

#[rustfmt::skip]
use monero_epee_traits::{EpeeError as OriginalEpeeError, BytesLike, EpeeEntry, EpeeDecode, EpeeObject};
pub(super) use monero_epee_traits::{HEADER, VERSION, Type, Array};
use monero_epee_derive::EpeeDecode;

use crate::{
  InterfaceError, PrunedTransactionWithPrunableHash, UnvalidatedScannableBlock,
  RingCtOutputInformation,
};

struct EpeeError(OriginalEpeeError);
impl From<EpeeError> for InterfaceError {
  fn from(err: EpeeError) -> InterfaceError {
    InterfaceError::InvalidInterface(format!("EpeeError::{:?}", err.0))
  }
}

#[derive(Default, EpeeDecode)]
struct Status {
  status: [u8; 2],
}
/// Check the `status` field within an `epee`-encoded object.
pub(super) fn check_status(epee: &[u8]) -> Result<(), InterfaceError> {
  if Status::decode_root(epee).map_err(EpeeError)?.status != *b"OK" {
    return Err(InterfaceError::InvalidInterface("epee `status` wasn't \"OK\"".to_string()));
  }
  Ok(())
}

#[derive(Default)]
struct U64Blob(Vec<u64>);
impl EpeeDecode for U64Blob {
  fn decode<'encoding, 'parent, B: BytesLike<'encoding>>(
    entry: EpeeEntry<'encoding, 'parent, B>,
  ) -> Result<Self, OriginalEpeeError> {
    let mut blob = entry.to_str()?;
    if (blob.len() % 8) != 0 {
      Err(OriginalEpeeError::TypeError)?;
    }

    // This is safe to pre-allocate as this length is returned to us by our own buffer
    let len = blob.len() / 8;
    let mut res = Vec::with_capacity(len);
    let mut next = [0; 8];
    for _ in 0 .. len {
      blob.read_into_slice(&mut next)?;
      res.push(u64::from_le_bytes(next));
    }
    Ok(U64Blob(res))
  }
}
#[derive(Default, EpeeDecode)]
struct Distribution {
  start_height: Option<u64>,
  /*
    This does allocate for the length of whatever distribution is encoded, yet the encoding as a
    whole is checked to be approximate to the size of the expected encoding of an honest result,
    making this fine.
  */
  distribution: U64Blob,
}
#[derive(Default, EpeeDecode)]
struct Distributions {
  /*
    `distributions` is technically an array, but we assume only one distribution was requested,
    which allows us to treat it as a unit value and immediately access its fields.
  */
  distributions: Distribution,
}

/// Extract the `start_height` field from the response to `get_output_distribution.bin`.
///
/// This assumes only a single distribution was requested by the caller.
pub(super) fn extract_start_height(epee: &[u8]) -> Result<usize, InterfaceError> {
  let start_height = Distributions::decode_root(epee)
    .map_err(EpeeError)?
    .distributions
    .start_height
    .ok_or_else(|| {
      InterfaceError::InvalidInterface("`start_height` was omitted from `Distribution`".to_string())
    })?;
  usize::try_from(start_height).map_err(|_| {
    InterfaceError::InvalidInterface("`start_height` did not fit within a `usize`".to_string())
  })
}

/// Extract the `distribution` field from the response to `get_output_distribution.bin`.
///
/// This assumes only a single distribution was requested by the caller.
pub(super) fn extract_distribution(
  epee: &[u8],
  expected_len: usize,
) -> Result<Vec<u64>, InterfaceError> {
  let distribution =
    Distributions::decode_root(epee).map_err(EpeeError)?.distributions.distribution.0;
  if distribution.len() != expected_len {
    Err(InterfaceError::InvalidInterface(
      "RPC returned a distribution of an unexpected length".to_string(),
    ))?;
  }
  Ok(distribution)
}

#[derive(Default, EpeeDecode)]
struct Output {
  height: Option<u64>,
  key: Option<[u8; 32]>,
  mask: Option<[u8; 32]>,
  txid: Option<[u8; 32]>,
  unlocked: Option<bool>,
}
#[derive(Default, EpeeDecode)]
struct Outputs {
  outs: Vec<Output>,
}
/// Accumulate a set of outputs from `get_outs.bin`.
pub(super) fn accumulate_outputs(
  epee: &[u8],
  amount: usize,
  res: &mut Vec<RingCtOutputInformation>,
) -> Result<(), InterfaceError> {
  let outputs = Outputs::decode_root(epee).map_err(EpeeError)?;
  /*
    Here, we allocate (during the decoding) before we perform this length check (after decoding),
    yet this blob is of a bounded size so this shouldn't be an issue.

    TODO: Re-do the length check here to ensure it occurred?
  */
  if outputs.outs.len() != amount {
    Err(InterfaceError::InvalidInterface(
      "`get_outs.bin` had a distinct amount of outs than expected".to_string(),
    ))?;
  }
  for output in outputs.outs {
    let Output {
      height: Some(block_number),
      key: Some(key),
      mask: Some(commitment),
      txid: Some(transaction),
      unlocked: Some(unlocked),
    } = output
    else {
      Err(InterfaceError::InvalidInterface(
        "missing field in output from `get_outs.bin`".to_string(),
      ))?
    };

    let key = CompressedPoint(key);

    let block_number = usize::try_from(block_number).map_err(|_| {
      InterfaceError::InvalidInterface(
        "`get_outs.bin` returned an block number not representable within a `usize`".to_string(),
      )
    })?;

    let commitment = CompressedPoint(commitment).decompress().ok_or_else(|| {
      InterfaceError::InvalidInterface("`get_outs.bin` returned an invalid commitment".to_string())
    })?;

    res.push(RingCtOutputInformation { block_number, key, commitment, transaction, unlocked });
  }

  Ok(())
}

#[derive(Default, EpeeDecode)]
struct TransactionEntry {
  blob: Vec<u8>,
  prunable_hash: [u8; 32],
}
#[derive(Default, EpeeDecode)]
struct BlockCompleteEntry {
  block: Vec<u8>,
  txs: Vec<TransactionEntry>,
}
#[derive(Default, EpeeDecode)]
struct OutputIndicesPerTransaction {
  indices: Vec<u64>,
}
#[derive(Default, EpeeDecode)]
struct OutputIndicesPerBlock {
  indices: Vec<OutputIndicesPerTransaction>,
}
#[derive(Default, EpeeDecode)]
struct BlocksBin {
  blocks: Vec<BlockCompleteEntry>,
  output_indices: Vec<OutputIndicesPerBlock>,
}

/// Returns `None` if this methodology isn't applicable.
pub(super) fn extract_blocks_from_blocks_bin(
  blocks_bin: &[u8],
) -> Result<Option<impl use<'_> + Iterator<Item = UnvalidatedScannableBlock>>, InterfaceError> {
  let blocks_bin = BlocksBin::decode_root(blocks_bin).map_err(EpeeError)?;

  let mut res = vec![];
  for block_entry in blocks_bin.blocks {
    let block;
    {
      let mut encoding = block_entry.block.as_slice();
      block = Block::read(&mut encoding)
        .map_err(|e| InterfaceError::InvalidInterface(format!("invalid block: {e:?}")))?;
      if !encoding.is_empty() {
        Err(InterfaceError::InvalidInterface("block had extraneous bytes after it".to_string()))?;
      }
    }

    let mut transactions = vec![];
    for tx in block_entry.txs {
      let transaction = {
        let mut encoding = tx.blob.as_slice();
        let transaction = Transaction::<Pruned>::read(&mut encoding)
          .map_err(|e| InterfaceError::InvalidInterface(format!("invalid transaction: {e:?}")))?;
        if !encoding.is_empty() {
          Err(InterfaceError::InvalidInterface(
            "transaction had extraneous bytes after it".to_string(),
          ))?;
        }
        transaction
      };

      // Only use the prunable hash if this transaction has a well-defined prunable hash
      let prunable_hash =
        Some(tx.prunable_hash).filter(|_| !matches!(transaction, Transaction::V1 { .. }));

      /*
        If this is a transaction which SHOULD have a prunable hash, yet the prunable
        hash was either missing or `[0; 32]` (an uninitialized value with statistically
        negligible probability of occurring natturally), return `None`. This signifies
        this methodology shouldn't be used.

        https://github.com/monero-project/monero/issues/10120
      */
      if matches!(transaction, Transaction::V2 { proofs: Some(_), .. }) &&
        (prunable_hash.is_none() || (prunable_hash == Some([0; 32])))
      {
        return Ok(None);
      }

      let transaction = PrunedTransactionWithPrunableHash::new(transaction, prunable_hash)
        .ok_or_else(|| {
          InterfaceError::InvalidInterface("non-v1 transaction missing prunable hash".to_string())
        })?;
      transactions.push(transaction);
    }

    res.push((block, transactions));
  }

  let mut all_output_indexes = vec![];
  for block in blocks_bin.output_indices {
    for tx in block.indices {
      for index in tx.indices {
        all_output_indexes.push(index);
      }
    }
  }

  // From the flattened view of output indexes, identify the first output index for a RingCT
  // transaction within each block
  let mut all_output_indexes = all_output_indexes.as_slice();
  let mut handle_transaction = |output_index_for_first_ringct_output: &mut Option<u64>,
                                transaction: &Transaction<Pruned>| {
    let outputs = transaction.prefix().outputs.len();
    if all_output_indexes.len() < outputs {
      return Err(InterfaceError::InvalidInterface(
        "block entry omitted output indexes for present transactions".to_string(),
      ));
    }

    if (!matches!(transaction, Transaction::V1 { .. })) && (outputs != 0) {
      *output_index_for_first_ringct_output =
        output_index_for_first_ringct_output.or(Some(all_output_indexes[0]));
    }
    all_output_indexes = &all_output_indexes[outputs ..];
    Ok(())
  };
  let mut result = Vec::with_capacity(res.len());
  for (block, transactions) in res {
    let mut output_index_for_first_ringct_output = None;
    handle_transaction(
      &mut output_index_for_first_ringct_output,
      &block.miner_transaction().clone().into(),
    )?;
    for transaction in &transactions {
      handle_transaction(&mut output_index_for_first_ringct_output, transaction.as_ref())?;
    }
    result.push(UnvalidatedScannableBlock {
      block,
      transactions,
      output_index_for_first_ringct_output,
    });
  }
  if !all_output_indexes.is_empty() {
    Err(InterfaceError::InvalidInterface(
      "`get_blocks.bin` had a distinct amount of output indexes than transaction outputs"
        .to_string(),
    ))?;
  }

  Ok(Some(result.into_iter()))
}

#[derive(Default, EpeeDecode)]
struct OutputIndexes {
  o_indexes: Vec<u64>,
}
pub(super) fn extract_output_indexes(epee: &[u8]) -> Result<Vec<u64>, InterfaceError> {
  Ok(OutputIndexes::decode_root(epee).map_err(EpeeError)?.o_indexes)
}
