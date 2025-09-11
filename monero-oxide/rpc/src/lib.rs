#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

use core::fmt::Debug;

extern crate alloc;
use alloc::{vec::Vec, string::String};

mod provides_blockchain_meta;
pub use provides_blockchain_meta::*;

mod provides_transactions;
pub use provides_transactions::*;

pub(crate) mod provides_blockchain;
pub use provides_blockchain::{ProvidesUnvalidatedBlockchain, ProvidesBlockchain};

mod provides_outputs;
pub use provides_outputs::*;

mod provides_scannable_blocks;
pub use provides_scannable_blocks::*;

mod provides_decoys;
pub use provides_decoys::*;

mod provides_fee_rates;
pub use provides_fee_rates::*;

mod monero_daemon;
pub use monero_daemon::*;

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

/// A prelude of recommend imports to glob import.
pub mod prelude {
  pub use crate::{
    RpcError, MoneroDaemon, ProvidesBlockchainMeta, ProvidesTransactions, PublishTransaction,
    ProvidesBlockchain, ProvidesOutputs, ScannableBlock, ExpandToScannableBlock,
    ProvidesScannableBlocks, EvaluateUnlocked, ProvidesDecoys, FeePriority, FeeRate,
    ProvidesFeeRates,
  };
}
