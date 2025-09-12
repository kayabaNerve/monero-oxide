#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

use core::fmt::Debug;

extern crate alloc;
use alloc::string::String;

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

/// An error from the source.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum SourceError {
  /// An internal error.
  #[error("internal error ({0})")]
  InternalError(String),
  /// An error with the source.
  #[error("source error ({0})")]
  SourceError(String),
  /// The source is invalid per the expected protocol and should be disconnected from.
  #[error("invalid node ({0})")]
  InvalidSource(String),
}

/// A prelude of recommend imports to glob import.
pub mod prelude {
  pub use crate::{
    SourceError, MoneroDaemon, ProvidesBlockchainMeta, TransactionsError, ProvidesTransactions,
    PublishTransactionError, PublishTransaction, ProvidesBlockchain, ProvidesOutputs,
    ScannableBlock, ExpandToScannableBlock, ProvidesScannableBlocks, EvaluateUnlocked,
    ProvidesDecoys, FeePriority, FeeRate, FeeError, ProvidesFeeRates,
  };
}
