use core::future::Future;
use alloc::vec::Vec;

use crate::RpcError;

/// Provides unvalidated information about outputs.
pub trait ProvidesUnvalidatedOutputs {
  /// Get the indexes for this transaction's outputs on the blockchain.
  ///
  /// No validation is performed.
  fn get_output_indexes(
    &self,
    hash: [u8; 32],
  ) -> impl Send + Future<Output = Result<Vec<u64>, RpcError>>;
}

/// Provides information about outputs.
pub trait ProvidesOutputs {
  /// Get the indexes for this transaction's outputs on the blockchain.
  ///
  /// No validation is performed.
  // We could check the outputs are contiguous if this was bound to only V2 transactions.
  fn get_output_indexes(
    &self,
    hash: [u8; 32],
  ) -> impl Send + Future<Output = Result<Vec<u64>, RpcError>>;
}

impl<P: ProvidesUnvalidatedOutputs> ProvidesOutputs for P {
  fn get_output_indexes(
    &self,
    hash: [u8; 32],
  ) -> impl Send + Future<Output = Result<Vec<u64>, RpcError>> {
    <P as ProvidesUnvalidatedOutputs>::get_output_indexes(self, hash)
  }
}
