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
use std_shims::io;

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};

use serde::Deserialize;
use serde_json::json;

use monero_oxide::{
  io::*,
  transaction::{Timelock, Pruned, Transaction},
  block::Block,
  DEFAULT_LOCK_WINDOW,
};

mod provides_fee_rates;
pub use provides_fee_rates::*;

mod monero_daemon;
pub use monero_daemon::*;

mod provides_transactions;
pub use provides_transactions::*;

mod provides_blockchain_meta;
pub use provides_blockchain_meta::*;

mod provides_blockchain;
pub use provides_blockchain::*;

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

/// A block which is able to be scanned.
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
  /// This is a CompressedEdwardsY, not an EdwardsPoint, as it may be invalid. CompressedEdwardsY
  /// only asserts validity on decompression and allows representing compressed types.
  pub key: CompressedEdwardsY,
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

/// TODO: docstring
pub trait Rpc:
  MoneroDaemon + ProvidesTransactions + PublishTransaction + ProvidesBlockchain + ProvidesFeeRates
{
  /// Get a block's scannable form.
  fn get_scannable_block(
    &self,
    block: Block,
  ) -> impl Send + Future<Output = Result<ScannableBlock, RpcError>> {
    async move {
      let transactions = self.get_pruned_transactions(&block.transactions).await?;

      /*
        Requesting the output index for each output we sucessfully scan would cause a loss of
        privacy. We could instead request the output indexes for all outputs we scan, yet this
        would notably increase the amount of RPC calls we make.

        We solve this by requesting the output index for the first RingCT output in the block, which
        should be within the miner transaction. Then, as we scan transactions, we update the output
        index ourselves.

        Please note we only will scan RingCT outputs so we only need to track the RingCT output
        index. This decision was made due to spending CN outputs potentially having burdensome
        requirements (the need to make a v1 TX due to insufficient decoys).

        We bound ourselves to only scanning RingCT outputs by only scanning v2 transactions. This is
        safe and correct since:

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

        let index = *self.get_o_indexes(*hash).await?.first().ok_or_else(|| {
          RpcError::InvalidNode(
            "requested output indexes for a TX with outputs and got none".to_string(),
          )
        })?;
        output_index_for_first_ringct_output = Some(index);
        break;
      }

      Ok(ScannableBlock { block, transactions, output_index_for_first_ringct_output })
    }
  }

  /// Get a block's scannable form by its hash.
  // TODO: get_blocks.bin
  fn get_scannable_block_by_hash(
    &self,
    hash: [u8; 32],
  ) -> impl Send + Future<Output = Result<ScannableBlock, RpcError>> {
    async move { self.get_scannable_block(self.get_block(hash).await?).await }
  }

  /// Get a block's scannable form by its number.
  // TODO: get_blocks_by_height.bin
  fn get_scannable_block_by_number(
    &self,
    number: usize,
  ) -> impl Send + Future<Output = Result<ScannableBlock, RpcError>> {
    async move { self.get_scannable_block(self.get_block_by_number(number).await?).await }
  }

  /// Get the output indexes of the specified transaction.
  fn get_o_indexes(
    &self,
    hash: [u8; 32],
  ) -> impl Send + Future<Output = Result<Vec<u64>, RpcError>> {
    async move {
      // Given the immaturity of Rust epee libraries, this is a homegrown one which is only
      // validated to work against this specific function

      // Header for EPEE, an 8-byte magic and a version
      const EPEE_HEADER: &[u8] = b"\x01\x11\x01\x01\x01\x01\x02\x01\x01";

      // Read an EPEE VarInt, distinct from the VarInts used throughout the rest of the protocol
      fn read_epee_vi<R: io::Read>(reader: &mut R) -> io::Result<u64> {
        let vi_start = read_byte(reader)?;
        let len = match vi_start & 0b11 {
          0 => 1,
          1 => 2,
          2 => 4,
          3 => 8,
          _ => unreachable!(),
        };
        let mut vi = u64::from(vi_start >> 2);
        for i in 1 .. len {
          vi |= u64::from(read_byte(reader)?) << (((i - 1) * 8) + 6);
        }
        Ok(vi)
      }

      let mut request = EPEE_HEADER.to_vec();
      // Number of fields (shifted over 2 bits as the 2 LSBs are reserved for metadata)
      request.push(1 << 2);
      // Length of field name
      request.push(4);
      // Field name
      request.extend(b"txid");
      // Type of field
      request.push(10);
      // Length of string, since this byte array is technically a string
      request.push(32 << 2);
      // The "string"
      request.extend(hash);

      let indexes_buf = self.bin_call("get_o_indexes.bin", request).await?;
      let mut indexes = indexes_buf.as_slice();

      (|| {
        let mut res = None;
        let mut has_status = false;

        if read_bytes::<_, { EPEE_HEADER.len() }>(&mut indexes)? != EPEE_HEADER {
          Err(io::Error::other("invalid header"))?;
        }

        let read_object = |reader: &mut &[u8]| -> io::Result<Vec<u64>> {
          // Read the amount of fields
          let fields = read_byte(reader)? >> 2;

          for _ in 0 .. fields {
            // Read the length of the field's name
            let name_len = read_byte(reader)?;
            // Read the name of the field
            let name = read_raw_vec(read_byte, name_len.into(), reader)?;

            let type_with_array_flag = read_byte(reader)?;
            // The type of this field, without the potentially set array flag
            let kind = type_with_array_flag & (!0x80);
            let has_array_flag = type_with_array_flag != kind;

            // Read this many instances of the field
            let iters = if has_array_flag { read_epee_vi(reader)? } else { 1 };

            // Check the field type
            {
              #[allow(clippy::match_same_arms)]
              let (expected_type, expected_array_flag) = match name.as_slice() {
                b"o_indexes" => (5, true),
                b"status" => (10, false),
                b"untrusted" => (11, false),
                b"credits" => (5, false),
                b"top_hash" => (10, false),
                // On-purposely prints name as a byte vector to prevent printing arbitrary strings
                // This is a self-describing format so we don't have to error here, yet we don't
                // claim this to be a complete deserialization function
                // To ensure it works for this specific use case, it's best to ensure it's limited
                // to this specific use case (ensuring we have less variables to deal with)
                _ => {
                  Err(io::Error::other(format!("unrecognized field in get_o_indexes: {name:?}")))?
                }
              };
              if (expected_type != kind) || (expected_array_flag != has_array_flag) {
                let fmt_array_bool = |array_bool| if array_bool { "array" } else { "not array" };
                Err(io::Error::other(format!(
                  "field {name:?} was {kind} ({}), expected {expected_type} ({})",
                  fmt_array_bool(has_array_flag),
                  fmt_array_bool(expected_array_flag)
                )))?;
              }
            }

            let read_field_as_bytes = match kind {
              /*
              // i64
              1 => |reader: &mut &[u8]| read_raw_vec(read_byte, 8, reader),
              // i32
              2 => |reader: &mut &[u8]| read_raw_vec(read_byte, 4, reader),
              // i16
              3 => |reader: &mut &[u8]| read_raw_vec(read_byte, 2, reader),
              // i8
              4 => |reader: &mut &[u8]| read_raw_vec(read_byte, 1, reader),
              */
              // u64
              5 => |reader: &mut &[u8]| read_raw_vec(read_byte, 8, reader),
              /*
              // u32
              6 => |reader: &mut &[u8]| read_raw_vec(read_byte, 4, reader),
              // u16
              7 => |reader: &mut &[u8]| read_raw_vec(read_byte, 2, reader),
              // u8
              8 => |reader: &mut &[u8]| read_raw_vec(read_byte, 1, reader),
              // double
              9 => |reader: &mut &[u8]| read_raw_vec(read_byte, 8, reader),
              */
              // string, or any collection of bytes
              10 => |reader: &mut &[u8]| {
                let len = read_epee_vi(reader)?;
                read_raw_vec(
                  read_byte,
                  len.try_into().map_err(|_| io::Error::other("u64 length exceeded usize"))?,
                  reader,
                )
              },
              // bool
              11 => |reader: &mut &[u8]| read_raw_vec(read_byte, 1, reader),
              /*
              // object, errors here as it shouldn't be used on this call
              12 => {
                |_: &mut &[u8]| Err(io::Error::other("node used object in reply to get_o_indexes"))
              }
              // array, so far unused
              13 => |_: &mut &[u8]| Err(io::Error::other("node used the unused array type")),
              */
              _ => |_: &mut &[u8]| Err(io::Error::other("node used an invalid type")),
            };

            let mut bytes_res = vec![];
            for _ in 0 .. iters {
              bytes_res.push(read_field_as_bytes(reader)?);
            }

            let mut actual_res = Vec::with_capacity(bytes_res.len());
            match name.as_slice() {
              b"o_indexes" => {
                for o_index in bytes_res {
                  actual_res.push(read_u64(&mut o_index.as_slice())?);
                }
                res = Some(actual_res);
              }
              b"status" => {
                if bytes_res
                  .first()
                  .ok_or_else(|| io::Error::other("status was a 0-length array"))?
                  .as_slice() !=
                  b"OK"
                {
                  Err(io::Error::other("response wasn't OK"))?;
                }
                has_status = true;
              }
              b"untrusted" | b"credits" | b"top_hash" => continue,
              _ => Err(io::Error::other("unrecognized field in get_o_indexes"))?,
            }
          }

          if !has_status {
            Err(io::Error::other("response didn't contain a status"))?;
          }

          // If the Vec was empty, it would've been omitted, hence the unwrap_or
          Ok(res.unwrap_or(vec![]))
        };

        read_object(&mut indexes)
      })()
      .map_err(|e| RpcError::InvalidNode(format!("invalid binary response: {e:?}")))
    }
  }
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
                key: CompressedEdwardsY(
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
    ProvidesBlockchainMeta, ProvidesBlockchain, FeePriority, FeeRate, ProvidesFeeRates, Rpc,
    DecoyRpc,
  };
}
