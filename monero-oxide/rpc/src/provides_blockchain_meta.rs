use core::future::Future;

use crate::RpcError;

/// Provides metadata from the blockchain.
pub trait ProvidesBlockchainMeta: Sync {
  /// Get the number of the latest block.
  ///
  /// The number of a block is its index on the blockchain, so the genesis block would have
  /// `number = 0`.
  fn get_latest_block_number(&self) -> impl Send + Future<Output = Result<usize, RpcError>>;

  /// Get the hash of a block by its number.
  ///
  /// The number of a block is its index on the blockchain, so the genesis block would have
  /// `number = 0`.
  fn get_block_hash(
    &self,
    number: usize,
  ) -> impl Send + Future<Output = Result<[u8; 32], RpcError>>;

  /// Get the active blockchain protocol version.
  ///
  /// This is specifically the major version within the most recent block header.
  fn get_hardfork_version(&self) -> impl Send + Future<Output = Result<u8, RpcError>>;
}
