#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

use core::{
  future::Future,
  fmt::Debug,
  ops::{Bound, RangeBounds},
};

extern crate alloc;
use alloc::{
  format, vec,
  vec::Vec,
  string::{String, ToString},
};
use curve25519_dalek::edwards::EdwardsPoint;

use serde::Deserialize;
use serde_json::json;

use monero_oxide::{io::*, transaction::Timelock, DEFAULT_LOCK_WINDOW};

mod monero_daemon;
pub use monero_daemon::*;

mod provides_transactions;
pub use provides_transactions::*;

mod provides_blockchain_meta;
pub use provides_blockchain_meta::*;

pub(crate) mod provides_blockchain;
pub use provides_blockchain::{ProvidesUnvalidatedBlockchain, ProvidesBlockchain};

mod provides_outputs;
pub use provides_outputs::*;

mod provides_scannable_blocks;
pub use provides_scannable_blocks::*;

mod provides_fee_rates;
pub use provides_fee_rates::*;

/// An error from the RPC.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum RpcError {
  /// An internal error.
  #[error("internal error ({0})")]
  InternalError(String),
  /// A connection error with the node.
  #[error("connection error ({0})")]
  ConnectionError(String),
  /// The node is invalid per the expected protocol.
  #[error("invalid node ({0})")]
  InvalidNode(String),
  /// Requested transactions weren't found.
  #[error("transactions not found")]
  TransactionsNotFound(Vec<[u8; 32]>),
  /// The transaction was pruned.
  ///
  /// Pruned transactions are not supported at this time.
  #[error("pruned transaction")]
  PrunedTransaction,
  /// A transaction (sent or received) was invalid.
  #[error("invalid transaction ({0:?})")]
  InvalidTransaction([u8; 32]),
  /// The returned fee was unusable.
  #[error("unexpected fee response")]
  InvalidFee,
  /// The priority intended for use wasn't usable.
  #[error("invalid priority")]
  InvalidPriority,
}

/// The response to an query for the information of a RingCT output.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OutputInformation {
  /// The block number of the block this output was added to the chain in.
  ///
  /// This is equivalent to he height of the blockchain at the time the block was added.
  pub height: usize,
  /// If the output is unlocked, per the node's local view.
  pub unlocked: bool,
  /// The output's key.
  ///
  /// This is a CompressedPoint, not an EdwardsPoint, as it may be invalid. CompressedPoint
  /// only asserts validity on decompression and allows representing compressed types.
  pub key: CompressedPoint,
  /// The output's commitment.
  pub commitment: EdwardsPoint,
  /// The transaction which created this output.
  pub transaction: [u8; 32],
}

fn rpc_hex(value: &str) -> Result<Vec<u8>, RpcError> {
  hex::decode(value).map_err(|_| RpcError::InvalidNode("expected hex wasn't hex".to_string()))
}

fn hash_hex(hash: &str) -> Result<[u8; 32], RpcError> {
  rpc_hex(hash)?.try_into().map_err(|_| RpcError::InvalidNode("hash wasn't 32-bytes".to_string()))
}

fn rpc_point(point: &str) -> Result<EdwardsPoint, RpcError> {
  CompressedPoint(
    rpc_hex(point)?
      .try_into()
      .map_err(|_| RpcError::InvalidNode(format!("invalid point: {point}")))?,
  )
  .decompress()
  .ok_or_else(|| RpcError::InvalidNode(format!("invalid point: {point}")))
}

/// A trait for any object which can be used to select RingCT decoys.
///
/// An implementation is provided for any satisfier of `Rpc`. It is not recommended to use an `Rpc`
/// object to satisfy this. This should be satisfied by a local store of the output distribution,
/// both for performance and to prevent potential attacks a remote node can perform.
pub trait DecoyRpc: Sync {
  /// Get the height the output distribution ends at.
  ///
  /// This is equivalent to the height of the blockchain it's for. This is intended to be cheaper
  /// than fetching the entire output distribution.
  fn get_output_distribution_end_height(
    &self,
  ) -> impl Send + Future<Output = Result<usize, RpcError>>;

  /// Get the RingCT (zero-amount) output distribution.
  ///
  /// `range` is in terms of block numbers. The result may be smaller than the requested range if
  /// the range starts before RingCT outputs were created on-chain.
  fn get_output_distribution(
    &self,
    range: impl Send + RangeBounds<usize>,
  ) -> impl Send + Future<Output = Result<Vec<u64>, RpcError>>;

  /// Get the specified outputs from the RingCT (zero-amount) pool.
  fn get_outs(
    &self,
    indexes: &[u64],
  ) -> impl Send + Future<Output = Result<Vec<OutputInformation>, RpcError>>;

  /// Get the specified outputs from the RingCT (zero-amount) pool, but only return them if their
  /// timelock has been satisfied.
  ///
  /// The timelock being satisfied is distinct from being free of the 10-block lock applied to all
  /// Monero transactions.
  ///
  /// The node is trusted for if the output is unlocked unless `fingerprintable_deterministic` is
  /// set to true. If `fingerprintable_deterministic` is set to true, the node's local view isn't
  /// used, yet the transaction's timelock is checked to be unlocked at the specified `height`.
  /// This offers a deterministic decoy selection, yet is fingerprintable as time-based timelocks
  /// aren't evaluated (and considered locked, preventing their selection).
  fn get_unlocked_outputs(
    &self,
    indexes: &[u64],
    height: usize,
    fingerprintable_deterministic: bool,
  ) -> impl Send + Future<Output = Result<Vec<Option<[EdwardsPoint; 2]>>, RpcError>>;
}

impl<R: MoneroDaemon + ProvidesTransactions + ProvidesBlockchainMeta> DecoyRpc for R {
  fn get_output_distribution_end_height(
    &self,
  ) -> impl Send + Future<Output = Result<usize, RpcError>> {
    async move {
      self.get_latest_block_number().await?.checked_add(1).ok_or_else(|| {
        RpcError::InvalidNode("output distribution end's wasn't representable".to_string())
      })
    }
  }

  fn get_output_distribution(
    &self,
    range: impl Send + RangeBounds<usize>,
  ) -> impl Send + Future<Output = Result<Vec<u64>, RpcError>> {
    async move {
      #[derive(Default, Debug, Deserialize)]
      struct Distribution {
        distribution: Vec<u64>,
        // A blockchain with just its genesis block has a height of 1
        start_height: usize,
      }

      #[derive(Debug, Deserialize)]
      struct Distributions {
        distributions: [Distribution; 1],
        status: String,
      }

      let from = match range.start_bound() {
        Bound::Included(from) => *from,
        Bound::Excluded(from) => from.checked_add(1).ok_or_else(|| {
          RpcError::InternalError("range's from wasn't representable".to_string())
        })?,
        Bound::Unbounded => 0,
      };
      let to = match range.end_bound() {
        Bound::Included(to) => *to,
        Bound::Excluded(to) => to
          .checked_sub(1)
          .ok_or_else(|| RpcError::InternalError("range's to wasn't representable".to_string()))?,
        Bound::Unbounded => self.get_latest_block_number().await?,
      };
      if from > to {
        Err(RpcError::InternalError(format!(
          "malformed range: inclusive start {from}, inclusive end {to}"
        )))?;
      }

      let zero_zero_case = (from == 0) && (to == 0);
      let distributions: Distributions = self
        .json_rpc_call(
          "get_output_distribution",
          Some(json!({
            "binary": false,
            "amounts": [0],
            "cumulative": true,
            // These are actually block numbers, not heights
            "from_height": from,
            "to_height": if zero_zero_case { 1 } else { to },
          })),
        )
        .await?;

      if distributions.status != "OK" {
        Err(RpcError::ConnectionError(
          "node couldn't service this request for the output distribution".to_string(),
        ))?;
      }

      let mut distributions = distributions.distributions;
      let Distribution { start_height, mut distribution } = core::mem::take(&mut distributions[0]);
      // start_height is also actually a block number, and it should be at least `from`
      // It may be after depending on when these outputs first appeared on the blockchain
      // Unfortunately, we can't validate without a binary search to find the RingCT activation
      // block and an iterative search from there, so we solely sanity check it
      if start_height < from {
        Err(RpcError::InvalidNode(format!(
          "requested distribution from {from} and got from {start_height}"
        )))?;
      }
      // It shouldn't be after `to` though
      if start_height > to {
        Err(RpcError::InvalidNode(format!(
          "requested distribution to {to} and got from {start_height}"
        )))?;
      }

      let expected_len = if zero_zero_case {
        2
      } else {
        (to - start_height).checked_add(1).ok_or_else(|| {
          RpcError::InternalError("expected length of distribution exceeded usize".to_string())
        })?
      };
      // Yet this is actually a height
      if expected_len != distribution.len() {
        Err(RpcError::InvalidNode(format!(
          "distribution length ({}) wasn't of the requested length ({})",
          distribution.len(),
          expected_len
        )))?;
      }
      // Requesting to = 0 returns the distribution for the entire chain
      // We work around this by requesting 0, 1 (yielding two blocks), then popping the second
      // block
      if zero_zero_case {
        distribution.pop();
      }

      // Check the distribution monotonically increases
      {
        let mut monotonic = 0;
        for d in &distribution {
          if *d < monotonic {
            Err(RpcError::InvalidNode(
              "received output distribution didn't increase monotonically".to_string(),
            ))?;
          }
          monotonic = *d;
        }
      }

      Ok(distribution)
    }
  }

  fn get_outs(
    &self,
    indexes: &[u64],
  ) -> impl Send + Future<Output = Result<Vec<OutputInformation>, RpcError>> {
    async move {
      #[derive(Debug, Deserialize)]
      struct OutputResponse {
        height: usize,
        unlocked: bool,
        key: String,
        mask: String,
        txid: String,
      }

      #[derive(Debug, Deserialize)]
      struct OutsResponse {
        status: String,
        outs: Vec<OutputResponse>,
      }

      // https://github.com/monero-project/monero/blob/cc73fe71162d564ffda8e549b79a350bca53c454
      //   /src/rpc/core_rpc_server.cpp#L67
      const MAX_OUTS: usize = 5000;

      let mut res = Vec::with_capacity(indexes.len());
      for indexes in indexes.chunks(MAX_OUTS) {
        let rpc_res: OutsResponse = self
          .rpc_call(
            "get_outs",
            Some(json!({
              "get_txid": true,
              "outputs": indexes.iter().map(|o| json!({
                "amount": 0,
                "index": o
              })).collect::<Vec<_>>()
            })),
          )
          .await?;

        if rpc_res.status != "OK" {
          Err(RpcError::InvalidNode("bad response to get_outs".to_string()))?;
        }

        if rpc_res.outs.len() != indexes.len() {
          Err(RpcError::InvalidNode("get_outs response omitted requested outputs".to_string()))?;
        }

        res.extend(
          rpc_res
            .outs
            .into_iter()
            .map(|output| {
              Ok(OutputInformation {
                height: output.height,
                unlocked: output.unlocked,
                key: CompressedPoint(
                  rpc_hex(&output.key)?
                    .try_into()
                    .map_err(|_| RpcError::InvalidNode("output key wasn't 32 bytes".to_string()))?,
                ),
                commitment: rpc_point(&output.mask)?,
                transaction: hash_hex(&output.txid)?,
              })
            })
            .collect::<Result<Vec<_>, RpcError>>()?,
        );
      }

      Ok(res)
    }
  }

  fn get_unlocked_outputs(
    &self,
    indexes: &[u64],
    height: usize,
    fingerprintable_deterministic: bool,
  ) -> impl Send + Future<Output = Result<Vec<Option<[EdwardsPoint; 2]>>, RpcError>> {
    async move {
      let outs = self.get_outs(indexes).await?;

      // Only need to fetch txs to do deterministic check on timelock
      let txs = if fingerprintable_deterministic {
        self.get_transactions(&outs.iter().map(|out| out.transaction).collect::<Vec<_>>()).await?
      } else {
        vec![]
      };

      // TODO: https://github.com/serai-dex/serai/issues/104
      outs
        .iter()
        .enumerate()
        .map(|(i, out)| {
          // Allow keys to be invalid, though if they are, return None to trigger selection of a
          // new decoy
          // Only valid keys can be used in CLSAG proofs, hence the need for re-selection, yet
          // invalid keys may honestly exist on the blockchain
          let Some(key) = out.key.decompress() else {
            return Ok(None);
          };
          Ok(Some([key, out.commitment]).filter(|_| {
            if fingerprintable_deterministic {
              // https://github.com/monero-project/monero/blob
              //   /cc73fe71162d564ffda8e549b79a350bca53c454/src/cryptonote_core
              //   /blockchain.cpp#L90
              const ACCEPTED_TIMELOCK_DELTA: usize = 1;

              // https://github.com/monero-project/monero/blob
              //   /cc73fe71162d564ffda8e549b79a350bca53c454/src/cryptonote_core
              //   /blockchain.cpp#L3836
              out.height.checked_add(DEFAULT_LOCK_WINDOW).is_some_and(|locked| locked <= height) &&
                (Timelock::Block(height.wrapping_add(ACCEPTED_TIMELOCK_DELTA - 1)) >=
                  txs[i].prefix().additional_timelock)
            } else {
              out.unlocked
            }
          }))
        })
        .collect()
    }
  }
}

/// A prelude of recommend imports to glob import.
pub mod prelude {
  pub use crate::{
    ScannableBlock, RpcError, MoneroDaemon, ProvidesTransactions, PublishTransaction,
    ProvidesBlockchainMeta, ProvidesBlockchain, ProvidesOutputs, ExpandToScannableBlock,
    ProvidesScannableBlocks, FeePriority, FeeRate, ProvidesFeeRates, DecoyRpc,
  };
}
