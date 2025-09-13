use core::future::Future;
use alloc::{format, vec::Vec};

use curve25519_dalek::EdwardsPoint;
use monero_oxide::io::CompressedPoint;

use crate::SourceError;

/// The response to an query for the information of a RingCT output.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RingCtOutputInformation {
  /// The block number of the block this output was added to the chain in.
  pub block_number: usize,
  /// If the output is unlocked, per the node's local view.
  pub unlocked: bool,
  /// The output's key.
  ///
  /// This is a `CompressedPoint`, not an `EdwardsPoint`, as it may be invalid. `CompressedPoint`
  /// only asserts validity on decompression and allows representing invalid points.
  pub key: CompressedPoint,
  /// The output's commitment.
  pub commitment: EdwardsPoint,
  /// The transaction which created this output.
  pub transaction: [u8; 32],
}

/// Provides unvalidated information about outputs.
pub trait ProvidesUnvalidatedOutputs: Sync {
  /// Get the indexes for this transaction's outputs on the blockchain.
  ///
  /// No validation is performed.
  fn output_indexes(
    &self,
    hash: [u8; 32],
  ) -> impl Send + Future<Output = Result<Vec<u64>, SourceError>>;

  /// Get the specified outputs from the RingCT (zero-amount) pool.
  ///
  /// No validation of the outputs is performed other than confirming the correct amount is
  /// returned.
  fn ringct_outputs(
    &self,
    indexes: &[u64],
  ) -> impl Send + Future<Output = Result<Vec<RingCtOutputInformation>, SourceError>>;
}

/// Provides information about outputs.
pub trait ProvidesOutputs: Sync {
  /// Get the indexes for this transaction's outputs on the blockchain.
  ///
  /// No validation is performed.
  // We could check the outputs are contiguous if this was bound to only V2 transactions.
  fn output_indexes(
    &self,
    hash: [u8; 32],
  ) -> impl Send + Future<Output = Result<Vec<u64>, SourceError>>;

  /// Get the specified outputs from the RingCT (zero-amount) pool.
  ///
  /// No validation of the outputs is performed other than confirming the correct amount is
  /// returned.
  fn ringct_outputs(
    &self,
    indexes: &[u64],
  ) -> impl Send + Future<Output = Result<Vec<RingCtOutputInformation>, SourceError>>;
}

impl<P: ProvidesUnvalidatedOutputs> ProvidesOutputs for P {
  fn output_indexes(
    &self,
    hash: [u8; 32],
  ) -> impl Send + Future<Output = Result<Vec<u64>, SourceError>> {
    <P as ProvidesUnvalidatedOutputs>::output_indexes(self, hash)
  }

  /// Get the specified outputs from the RingCT (zero-amount) pool.
  ///
  /// No validation of the outputs is performed other than confirming the correct amount is
  /// returned.
  fn ringct_outputs(
    &self,
    indexes: &[u64],
  ) -> impl Send + Future<Output = Result<Vec<RingCtOutputInformation>, SourceError>> {
    async move {
      let outputs = <P as ProvidesUnvalidatedOutputs>::ringct_outputs(self, indexes).await?;
      if outputs.len() != indexes.len() {
        Err(SourceError::InternalError(format!(
          "`{}` returned {} outputs, expected {}",
          "ProvidesUnvalidatedOutputs::ringct_outputs",
          outputs.len(),
          indexes.len(),
        )))?;
      }
      Ok(outputs)
    }
  }
}
