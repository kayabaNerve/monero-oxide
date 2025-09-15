use core::{ops::RangeInclusive, future::Future};
use alloc::{format, vec::Vec, string::ToString};

use monero_oxide::{
  transaction::{Pruned, Transaction},
  block::Block,
};

use crate::{InterfaceError, TransactionsError, ProvidesTransactions, ProvidesOutputs};

/// A block which is able to be scanned.
// TODO: Should these fields be private so we can check their integrity within a constructor?
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ScannableBlock {
  /// The block which is being scanned.
  pub block: Block,
  /// The non-miner transactions within this block.
  pub transactions: Vec<Transaction<Pruned>>,
  /// The output index for the first RingCT output within this block.
  ///
  /// None if there are no RingCT outputs within this block, Some otherwise.
  pub output_index_for_first_ringct_output: Option<u64>,
}

/// Extension trait for `ProvidesTransactions and `ProvidesOutputs`.
pub trait ExpandToScannableBlock: ProvidesTransactions + ProvidesOutputs {
  /// Expand a `Block` to a `ScannableBlock`.
  fn expand_to_scannable_block(
    &self,
    block: Block,
  ) -> impl Send + Future<Output = Result<ScannableBlock, TransactionsError>> {
    async move {
      let transactions = self.pruned_transactions(&block.transactions).await?;

      /*
        Requesting the output index for each output we sucessfully scan would cause a loss of
        privacy. We could instead request the output indexes for all outputs we scan, yet this
        would notably increase the amount of RPC calls we make.

        We solve this by requesting the output index for the first RingCT output in the block,
        which should be within the miner transaction. Then, as we scan transactions, we update the
        output index ourselves.

        Please note we only will scan RingCT outputs so we only need to track the RingCT output
        index. This decision was made due to spending CN outputs potentially having burdensome
        requirements (the need to make a v1 TX due to insufficient decoys).

        We bound ourselves to only scanning RingCT outputs by only scanning v2 transactions. This
        is safe and correct since:

        1) v1 transactions cannot create RingCT outputs.

           https://github.com/monero-project/monero/blob/cc73fe71162d564ffda8e549b79a350bca53c454
             /src/cryptonote_basic/cryptonote_format_utils.cpp#L866-L869

        2) v2 miner transactions implicitly create RingCT outputs.

           https://github.com/monero-project/monero/blob/cc73fe71162d564ffda8e549b79a350bca53c454
             /src/blockchain_db/blockchain_db.cpp#L232-L241

        3) v2 transactions must create RingCT outputs.

           https://github.com/monero-project/monero/blob/cc73fe71162d564ffda8e549b79a350bca53c45
             /src/cryptonote_core/blockchain.cpp#L3055-L3065

           That does bound on the hard fork version being >= 3, yet all v2 TXs have a hard fork
           version > 3.

           https://github.com/monero-project/monero/blob/cc73fe71162d564ffda8e549b79a350bca53c454
             /src/cryptonote_core/blockchain.cpp#L3417
      */

      // Get the index for the first output
      let mut output_index_for_first_ringct_output = None;
      let miner_tx_hash = block.miner_transaction.hash();
      let miner_tx = Transaction::<Pruned>::from(block.miner_transaction.clone());
      for (hash, tx) in core::iter::once((&miner_tx_hash, &miner_tx))
        .chain(block.transactions.iter().zip(&transactions))
      {
        // If this isn't a RingCT output, or there are no outputs, move to the next TX
        if (!matches!(tx, Transaction::V2 { .. })) || tx.prefix().outputs.is_empty() {
          continue;
        }

        let index =
          *ProvidesOutputs::output_indexes(self, *hash).await?.first().ok_or_else(|| {
            InterfaceError::InvalidInterface(
              "requested output indexes for a TX with outputs and got none".to_string(),
            )
          })?;
        output_index_for_first_ringct_output = Some(index);
        break;
      }

      Ok(ScannableBlock { block, transactions, output_index_for_first_ringct_output })
    }
  }
}

impl<P: ProvidesTransactions + ProvidesOutputs> ExpandToScannableBlock for P {}

/// Provides scannable blocks from an untrusted interface.
///
/// This provides all its methods yet
/// (`contiguous_scannable_blocks` || `scannable_block_by_number`) &&
/// (`scannable_blocks` || `scannable_block`) MUST be overriden, ideally the batch methods.
pub trait ProvidesUnvalidatedScannableBlocks: Sync {
  /// Get a contiguous range of `ScannableBlock`s.
  ///
  /// No validation is applied to the received blocks other than that they deserialize and have the
  /// expected length.
  fn contiguous_scannable_blocks(
    &self,
    range: RangeInclusive<usize>,
  ) -> impl Send + Future<Output = Result<Vec<ScannableBlock>, InterfaceError>> {
    async move {
      // If a caller requests an exorbitant amount of blocks, this may trigger an OOM kill
      // In order to maintain correctness, we have to attempt to service this request though
      let mut blocks =
        Vec::with_capacity(range.end().saturating_sub(*range.start()).saturating_add(1));
      for number in range {
        blocks.push(self.scannable_block_by_number(number).await?);
      }
      Ok(blocks)
    }
  }

  /// Get a list of `ScannableBlock`s by their hashes.
  ///
  /// No validation is applied to the received blocks other than that they deserialize and have the
  /// expected length.
  fn scannable_blocks(
    &self,
    hashes: &[[u8; 32]],
  ) -> impl Send + Future<Output = Result<Vec<ScannableBlock>, InterfaceError>> {
    async move {
      let mut blocks = Vec::with_capacity(hashes.len());
      for hash in hashes {
        blocks.push(self.scannable_block(*hash).await?);
      }
      Ok(blocks)
    }
  }

  /// Get a `ScannableBlock` by its hash.
  ///
  /// No validation is applied to the received blocks other than that it deserializes.
  fn scannable_block(
    &self,
    hash: [u8; 32],
  ) -> impl Send + Future<Output = Result<ScannableBlock, InterfaceError>> {
    async move {
      let mut blocks = self.scannable_blocks(&[hash]).await?;
      if blocks.len() != 1 {
        Err(InterfaceError::InternalError(format!(
          "`{}` returned {} blocks, expected {}",
          "ProvidesUnvalidatedScannableBlocks::scannable_blocks",
          blocks.len(),
          1,
        )))?;
      }
      Ok(blocks.pop().unwrap())
    }
  }

  /// Get a `ScannableBlock` by its number.
  ///
  /// No validation is applied to the received blocks other than that it deserializes.
  fn scannable_block_by_number(
    &self,
    number: usize,
  ) -> impl Send + Future<Output = Result<ScannableBlock, InterfaceError>> {
    async move {
      let mut blocks = self.contiguous_scannable_blocks(number ..= number).await?;
      if blocks.len() != 1 {
        Err(InterfaceError::InternalError(format!(
          "`{}` returned {} blocks, expected {}",
          "ProvidesUnvalidatedScannableBlocks::contiguous_scannable_blocks",
          blocks.len(),
          1,
        )))?;
      }
      Ok(blocks.pop().unwrap())
    }
  }
}

/// Provides scannable blocks which have been sanity-checked.
pub trait ProvidesScannableBlocks: Sync {
  /// Get a contiguous range of `ScannableBlock`s.
  ///
  /// The blocks will be validated to build upon each other, as expected, have the expected
  /// numbers, and have the expected amount of transactions.
  // TODO: For `version != 1` transactions, can we verify we have the expected transactions?
  fn contiguous_scannable_blocks(
    &self,
    range: RangeInclusive<usize>,
  ) -> impl Send + Future<Output = Result<Vec<ScannableBlock>, InterfaceError>>;

  /// Get a list of `ScannableBlock`s by their hashes.
  ///
  /// The blocks will be validated to be the requested blocks with well-formed numbers and have the
  /// expected amount of transactions.
  fn scannable_blocks(
    &self,
    hashes: &[[u8; 32]],
  ) -> impl Send + Future<Output = Result<Vec<ScannableBlock>, InterfaceError>>;

  /// Get a `ScannableBlock` by its hash.
  ///
  /// The block will be validated to be the requested block with a well-formed number and have the
  /// expected amount of transactions.
  fn scannable_block(
    &self,
    hash: [u8; 32],
  ) -> impl Send + Future<Output = Result<ScannableBlock, InterfaceError>>;

  /// Get a `ScannableBlock` by its number.
  ///
  /// The number of a block is its index on the blockchain, so the genesis block would have
  /// `number = 0`.
  ///
  /// The block will be validated to be a block with the requested number and have the expected
  /// amount of transactions.
  fn scannable_block_by_number(
    &self,
    number: usize,
  ) -> impl Send + Future<Output = Result<ScannableBlock, InterfaceError>>;
}

impl<P: ProvidesUnvalidatedScannableBlocks> ProvidesScannableBlocks for P {
  fn contiguous_scannable_blocks(
    &self,
    range: RangeInclusive<usize>,
  ) -> impl Send + Future<Output = Result<Vec<ScannableBlock>, InterfaceError>> {
    async move {
      let blocks =
        <P as ProvidesUnvalidatedScannableBlocks>::contiguous_scannable_blocks(self, range.clone())
          .await?;
      let expected_blocks =
        range.end().saturating_sub(*range.start()).checked_add(1).ok_or_else(|| {
          InterfaceError::InternalError(
            "amount of blocks requested wasn't representable in a `usize`".to_string(),
          )
        })?;
      if blocks.len() != expected_blocks {
        Err(InterfaceError::InternalError(format!(
          "`{}` returned {} blocks, expected {}",
          "ProvidesUnvalidatedScannableBlocks::contiguous_scannable_blocks",
          blocks.len(),
          expected_blocks,
        )))?;
      }
      crate::provides_blockchain::sanity_check_contiguous_blocks(
        range,
        blocks.iter().map(|scannable_block| &scannable_block.block),
      )?;

      for block in &blocks {
        if block.block.transactions.len() != block.transactions.len() {
          Err(InterfaceError::InvalidInterface(format!(
            "scannable block had {} transactions yet only received {}",
            block.block.transactions.len(),
            block.transactions.len()
          )))?;
        }
      }

      Ok(blocks)
    }
  }

  fn scannable_blocks(
    &self,
    hashes: &[[u8; 32]],
  ) -> impl Send + Future<Output = Result<Vec<ScannableBlock>, InterfaceError>> {
    async move {
      let blocks =
        <P as ProvidesUnvalidatedScannableBlocks>::scannable_blocks(self, hashes).await?;
      if blocks.len() != hashes.len() {
        Err(InterfaceError::InternalError(format!(
          "`{}` returned {} blocks, expected {}",
          "ProvidesUnvalidatedScannableBlocks::scannable_blocks",
          blocks.len(),
          hashes.len(),
        )))?;
      }
      crate::provides_blockchain::sanity_check_blocks(
        hashes,
        blocks.iter().map(|scannable_block| &scannable_block.block),
      )?;

      for block in &blocks {
        if block.block.transactions.len() != block.transactions.len() {
          Err(InterfaceError::InvalidInterface(format!(
            "scannable block had {} transactions yet only received {}",
            block.block.transactions.len(),
            block.transactions.len()
          )))?;
        }
      }

      Ok(blocks)
    }
  }

  fn scannable_block(
    &self,
    hash: [u8; 32],
  ) -> impl Send + Future<Output = Result<ScannableBlock, InterfaceError>> {
    async move {
      let block = <P as ProvidesUnvalidatedScannableBlocks>::scannable_block(self, hash).await?;
      crate::provides_blockchain::sanity_check_block_by_hash(&hash, &block.block)?;

      if block.block.transactions.len() != block.transactions.len() {
        Err(InterfaceError::InvalidInterface(format!(
          "scannable block had {} transactions yet only received {}",
          block.block.transactions.len(),
          block.transactions.len()
        )))?;
      }

      Ok(block)
    }
  }

  fn scannable_block_by_number(
    &self,
    number: usize,
  ) -> impl Send + Future<Output = Result<ScannableBlock, InterfaceError>> {
    async move {
      let block =
        <P as ProvidesUnvalidatedScannableBlocks>::scannable_block_by_number(self, number).await?;
      crate::provides_blockchain::sanity_check_block_by_number(number, &block.block)?;

      if block.block.transactions.len() != block.transactions.len() {
        Err(InterfaceError::InvalidInterface(format!(
          "scannable block had {} transactions yet only received {}",
          block.block.transactions.len(),
          block.transactions.len()
        )))?;
      }

      Ok(block)
    }
  }
}
