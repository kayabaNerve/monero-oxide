use core::{ops::RangeInclusive, future::Future};
use alloc::{vec::Vec, string::ToString};

use monero_oxide::block::Block;

use crate::{RpcError, ProvidesBlockchainMeta};

/// Provides the blockchain from an untrusted source.
///
/// This provides all its methods yet (`get_contiguous_blocks` || `get_block_by_number`) &&
/// (`get_blocks` || `get_block`) MUST be overriden, ideally the batch methods.
pub trait ProvidesUnvalidatedBlockchain: Sync + ProvidesBlockchainMeta {
  /// Get a contiguous range of blocks.
  ///
  /// No validation is applied to the received blocks other than that they deserialize.
  // This accepts a `RangeInclusive`, not a `impl RangeBounds`, to ensure the range is finite
  fn get_contiguous_blocks(
    &self,
    range: RangeInclusive<usize>,
  ) -> impl Send + Future<Output = Result<Vec<Block>, RpcError>> {
    async move {
      // If a caller requests an exorbitant amount of blocks, this may trigger an OOM kill
      // In order to maintain correctness, we have to attempt to service this request though
      let mut blocks = Vec::with_capacity(range.end().wrapping_sub(*range.start()));
      for number in range {
        blocks.push(self.get_block_by_number(number).await?);
      }
      Ok(blocks)
    }
  }

  /// Get a list of blocks by their hashes.
  ///
  /// No validation is applied to the received blocks other than that they deserialize.
  fn get_blocks(
    &self,
    hashes: &[[u8; 32]],
  ) -> impl Send + Future<Output = Result<Vec<Block>, RpcError>> {
    async move {
      let mut blocks = Vec::with_capacity(hashes.len());
      for hash in hashes {
        blocks.push(self.get_block(*hash).await?);
      }
      Ok(blocks)
    }
  }

  /* TODO
  /// Subscribe to blocks.
  fn subscribe(start: usize) -> impl Iterator<Item = Future<Output = Result<Block, RpcError>>> {}
  */

  /// Get a block by its hash.
  ///
  /// No validation is applied to the received block other than that it deserializes.
  fn get_block(&self, hash: [u8; 32]) -> impl Send + Future<Output = Result<Block, RpcError>> {
    async move {
      let mut blocks = self.get_blocks(&[hash]).await?;
      if blocks.len() != 1 {
        Err(RpcError::InternalError(format!(
          "`{}` returned {} blocks, expected {}",
          "ProvidesUnvalidatedBlockchain::get_blocks",
          blocks.len(),
          1,
        )))?;
      }
      Ok(blocks.pop().unwrap())
    }
  }

  /// Get a block by its number.
  ///
  /// The number of a block is its index on the blockchain, so the genesis block would have
  /// `number = 0`.
  ///
  /// No validation is applied to the received blocks other than that it deserializes.
  fn get_block_by_number(
    &self,
    number: usize,
  ) -> impl Send + Future<Output = Result<Block, RpcError>> {
    async move {
      let mut blocks = self.get_contiguous_blocks(number ..= number).await?;
      if blocks.len() != 1 {
        Err(RpcError::InternalError(format!(
          "`{}` returned {} blocks, expected {}",
          "ProvidesUnvalidatedBlockchain::get_contiguous_blocks",
          blocks.len(),
          1,
        )))?;
      }
      Ok(blocks.pop().unwrap())
    }
  }
}

/// Provides blocks which have been sanity-checked.
pub trait ProvidesBlockchain: ProvidesBlockchainMeta {
  /// Get a contiguous range of blocks.
  ///
  /// The blocks will be validated to build upon each other, as expected, and have the expected
  /// numbers.
  fn get_contiguous_blocks(
    &self,
    range: RangeInclusive<usize>,
  ) -> impl Send + Future<Output = Result<Vec<Block>, RpcError>>;

  /// Get a list of blocks by their hashes.
  ///
  /// The blocks will be validated to be the requested blocks with well-formed numbers.
  fn get_blocks(
    &self,
    hashes: &[[u8; 32]],
  ) -> impl Send + Future<Output = Result<Vec<Block>, RpcError>>;

  /// Get a block by its hash.
  ///
  /// The block will be validated to be the requested block with a well-formed number.
  fn get_block(&self, hash: [u8; 32]) -> impl Send + Future<Output = Result<Block, RpcError>>;

  /// Get a block by its index on the blockchain (number).
  ///
  /// The number of a block is its index on the blockchain, so the genesis block would have
  /// `number = 0`.
  ///
  /// The block will be validated to be a block with the requested number.
  fn get_block_by_number(
    &self,
    number: usize,
  ) -> impl Send + Future<Output = Result<Block, RpcError>>;
}

impl<P: ProvidesUnvalidatedBlockchain> ProvidesBlockchain for P {
  fn get_contiguous_blocks(
    &self,
    range: RangeInclusive<usize>,
  ) -> impl Send + Future<Output = Result<Vec<Block>, RpcError>> {
    async move {
      let blocks =
        <P as ProvidesUnvalidatedBlockchain>::get_contiguous_blocks(self, range.clone()).await?;
      let expected_blocks = range.end().wrapping_sub(*range.start());
      if blocks.len() != expected_blocks {
        Err(RpcError::InternalError(format!(
          "`{}` returned {} blocks, expected {}",
          "ProvidesUnvalidatedBlockchain::get_contiguous_blocks",
          blocks.len(),
          expected_blocks,
        )))?;
      }

      let mut parent = None;
      for (number, block) in range.zip(&blocks) {
        match block.number() {
          Some(actual_number) => {
            if actual_number != number {
              Err(RpcError::InvalidNode(format!(
                "requested block #{number}, received #{actual_number}"
              )))?;
            }
          }
          None => Err(RpcError::InvalidNode(format!(
            "source returned a block with an invalid miner transaction for #{number}",
          )))?,
        };

        let block_hash = block.hash();
        if let Some(parent) = parent.or((number == 0).then_some([0; 32])) {
          if parent != block.header.previous {
            Err(RpcError::InvalidNode(
              "
              source returned a block which doesn't build on the prior block \
              when requesting a contiguous series
            "
              .to_string(),
            ))?;
          }
        }
        parent = Some(block_hash);
      }

      Ok(blocks)
    }
  }

  fn get_blocks(
    &self,
    hashes: &[[u8; 32]],
  ) -> impl Send + Future<Output = Result<Vec<Block>, RpcError>> {
    async move {
      let blocks = <P as ProvidesUnvalidatedBlockchain>::get_blocks(self, hashes).await?;
      if blocks.len() != hashes.len() {
        Err(RpcError::InternalError(format!(
          "`{}` returned {} blocks, expected {}",
          "ProvidesUnvalidatedBlockchain::get_blocks",
          blocks.len(),
          hashes.len(),
        )))?;
      }

      for (block, hash) in blocks.iter().zip(hashes) {
        if block.number().is_none() {
          Err(RpcError::InvalidNode(format!(
            "source returned a block with an invalid miner transaction for {}",
            hex::encode(hash),
          )))?;
        }

        let actual_hash = block.hash();
        if &actual_hash != hash {
          Err(RpcError::InvalidNode(format!(
            "requested block {}, received {}",
            hex::encode(hash),
            hex::encode(actual_hash)
          )))?;
        }
      }

      Ok(blocks)
    }
  }

  fn get_block(&self, hash: [u8; 32]) -> impl Send + Future<Output = Result<Block, RpcError>> {
    async move {
      let block = <P as ProvidesUnvalidatedBlockchain>::get_block(self, hash).await?;

      if block.number().is_none() {
        Err(RpcError::InvalidNode(format!(
          "source returned a block with an invalid miner transaction for {}",
          hex::encode(hash),
        )))?;
      }

      let actual_hash = block.hash();
      if actual_hash != hash {
        Err(RpcError::InvalidNode(format!(
          "requested block {}, received {}",
          hex::encode(hash),
          hex::encode(actual_hash)
        )))?;
      }

      Ok(block)
    }
  }

  fn get_block_by_number(
    &self,
    number: usize,
  ) -> impl Send + Future<Output = Result<Block, RpcError>> {
    async move {
      let block = <P as ProvidesUnvalidatedBlockchain>::get_block_by_number(self, number).await?;

      match block.number() {
        Some(actual_number) => {
          if actual_number != number {
            Err(RpcError::InvalidNode(format!(
              "requested block #{number}, received #{actual_number}"
            )))?;
          }
        }
        None => Err(RpcError::InvalidNode(format!(
          "source returned a block with an invalid miner transaction for #{number}",
        )))?,
      };

      Ok(block)
    }
  }
}
