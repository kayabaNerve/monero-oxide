#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

use core::{fmt::Debug, future::Future};

extern crate alloc;
use alloc::{
  format, vec,
  vec::Vec,
  string::{String, ToString},
};

use serde::{Serialize, Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};

use monero_oxide::transaction::{MAX_NON_MINER_TRANSACTION_SIZE, Input, Pruned, Transaction};
use monero_address::Address;

use monero_interface::*;

mod bin_rpc;

const BASE_RESPONSE_SIZE: usize = u16::MAX as usize;
const BYTE_FACTOR_IN_JSON_RESPONSE_SIZE: usize = 8;

/*
  Monero doesn't have a size limit on miner transactions and accordingly doesn't have a size limit
  on transactions, yet we would like _a_ bound (even if absurd) to limit a malicious remote node
  from sending a gigantic HTTP response and wasting our bandwidth.

  We consider the bound for a miner transaction as 300 KB, which is thousands of outputs and an
  entire Monero block (at its default block size limit).
*/
const fn const_max(a: usize, b: usize) -> usize {
  if a > b {
    a
  } else {
    b
  }
}
const TRANSACTION_SIZE_BOUND: usize = const_max(300_000, MAX_NON_MINER_TRANSACTION_SIZE);

fn rpc_hex(value: &str) -> Result<Vec<u8>, InterfaceError> {
  hex::decode(value)
    .map_err(|_| InterfaceError::InvalidInterface("expected hex wasn't hex".to_string()))
}

fn hash_hex(hash: &str) -> Result<[u8; 32], InterfaceError> {
  rpc_hex(hash)?
    .try_into()
    .map_err(|_| InterfaceError::InvalidInterface("hash wasn't 32-bytes".to_string()))
}

#[derive(Debug, Deserialize)]
struct JsonRpcResponse<T> {
  result: T,
}

#[rustfmt::skip]
/// An HTTP transport usable with a Monero daemon.
///
/// This is abstract such that users can use an HTTP library (which being their choice), a
/// Tor/i2p-based transport, or even a memory buffer an external service somehow routes.
///
/// While no implementors are directly provided, [monero-simple-request-rpc](
///   https://github.com/monero-oxide/monero-oxide/tree/main/monero-oxide/interface/daemon/simple-request
/// ) is recommended.
pub trait HttpTransport: Sync + Clone {
  /// Perform a POST request to the specified route with the specified body.
  ///
  /// The implementor is left to handle anything such as authentication.
  fn post(
    &self,
    route: &str,
    body: Vec<u8>,
    response_size_limit: Option<usize>,
  ) -> impl Send + Future<Output = Result<Vec<u8>, InterfaceError>>;
}

/// A connection to a Monero daemon.
#[derive(Clone)]
pub struct MoneroDaemon<T: HttpTransport>(pub T);

impl<T: Debug + HttpTransport> core::fmt::Debug for MoneroDaemon<T> {
  fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
    fmt.debug_struct("MoneroDaemon").field("0", &self.0).finish()
  }
}

#[rustfmt::skip]
impl<T: HttpTransport> MoneroDaemon<T> {
  /// Perform a RPC call to the specified route with the provided parameters.
  ///
  /// This is NOT a JSON-RPC call. They use a route of "json_rpc" and are available via
  /// `json_rpc_call`.
  pub fn rpc_call<'a, Params: Send + Serialize + Debug, Response: DeserializeOwned + Debug>(
    &'a self,
    route: &'a str,
    params: Option<Params>,
    response_size_limit: Option<usize>,
  ) -> impl use<'a, T, Params, Response> + Send + Future<Output = Result<Response, InterfaceError>> {
    async move {
      let res =
        self
          .0
          .post(
            route,
            if let Some(params) = params.as_ref() {
              serde_json::to_string(params)
                .map_err(|e| {
                  InterfaceError::InternalError(format!(
                    "couldn't convert parameters ({params:?}) to JSON: {e:?}"
                  ))
                })?
                .into_bytes()
            } else {
              vec![]
            },
            response_size_limit,
          )
          .await?;
      let res_str = std_shims::str::from_utf8(&res)
        .map_err(|_| InterfaceError::InvalidInterface("response wasn't utf-8".to_string()))?;
      serde_json::from_str(res_str).map_err(|_| {
        InterfaceError::InvalidInterface("response wasn't the expected json".to_string())
      })
    }
  }

  /// Perform a JSON-RPC call with the specified method with the provided parameters.
  pub fn json_rpc_call<'a, Response: DeserializeOwned + Debug>(
    &'a self,
    method: &'a str,
    params: Option<Value>,
    response_size_limit: Option<usize>,
  ) -> impl use<'a, T, Response> + Send + Future<Output = Result<Response, InterfaceError>> {
    async move {
      let mut req = json!({ "method": method });
      if let Some(params) = params {
        req
          .as_object_mut()
          .expect("accessing object as object failed?")
          .insert("params".into(), params);
      }
      Ok(
        self
          .rpc_call::<_, JsonRpcResponse<Response>>("json_rpc", Some(req), response_size_limit)
          .await?
          .result,
      )
    }
  }

  /// Generate blocks, with the specified address receiving the block reward.
  ///
  /// Returns the hashes of the generated blocks and the last block's alleged number.
  ///
  /// This is intended for testing purposes and does not validate the result.
  pub fn generate_blocks<'a, const ADDR_BYTES: u128>(
    &'a self,
    address: &'a Address<ADDR_BYTES>,
    block_count: usize,
  ) -> impl use<'a, T, ADDR_BYTES> + Send + Future<Output = Result<(Vec<[u8; 32]>, usize), InterfaceError>>
  {
    async move {
      #[derive(Debug, Deserialize)]
      struct BlocksResponse {
        blocks: Vec<String>,
        height: usize,
      }

      let res = self
        .json_rpc_call::<BlocksResponse>(
          "generateblocks",
          Some(json!({
            "wallet_address": address.to_string(),
            "amount_of_blocks": block_count,
          })),
          Some(BASE_RESPONSE_SIZE.saturating_add(
            BYTE_FACTOR_IN_JSON_RESPONSE_SIZE.saturating_mul(block_count.saturating_mul(32)),
          )),
        )
        .await?;

      let mut blocks = Vec::with_capacity(res.blocks.len());
      for block in res.blocks {
        blocks.push(hash_hex(&block)?);
      }
      Ok((blocks, res.height))
    }
  }
}

impl<T: HttpTransport> ProvidesBlockchainMeta for MoneroDaemon<T> {
  fn latest_block_number(&self) -> impl Send + Future<Output = Result<usize, InterfaceError>> {
    async move {
      #[derive(Debug, Deserialize)]
      struct HeightResponse {
        height: usize,
      }
      let res = self
        .rpc_call::<Option<()>, HeightResponse>("get_height", None, Some(BASE_RESPONSE_SIZE))
        .await?
        .height;
      res.checked_sub(1).ok_or_else(|| {
        InterfaceError::InvalidInterface(
          "node claimed the blockchain didn't even have the genesis block".to_string(),
        )
      })
    }
  }
}

mod provides_transaction {
  use super::*;

  // Monero errors if more than 100 is requested unless using a non-restricted RPC
  // https://github.com/monero-project/monero/blob/cc73fe71162d564ffda8e549b79a350bca53c454
  //   /src/rpc/core_rpc_server.cpp#L75
  const TXS_PER_REQUEST: usize = 100;

  #[derive(Debug, Deserialize)]
  struct TransactionResponse {
    tx_hash: String,
    as_hex: String,
    pruned_as_hex: String,
    prunable_hash: String,
  }
  #[derive(Debug, Deserialize)]
  struct TransactionsResponse {
    #[serde(default)]
    missed_tx: Vec<String>,
    txs: Vec<TransactionResponse>,
  }

  #[rustfmt::skip]
  impl<T: HttpTransport> ProvidesUnvalidatedTransactions for MoneroDaemon<T> {
    fn transactions(
      &self,
      hashes: &[[u8; 32]],
    ) -> impl Send + Future<Output = Result<Vec<Transaction>, TransactionsError>> {
      async move {
        let mut hashes_hex = hashes.iter().map(hex::encode).collect::<Vec<_>>();
        let mut all_txs = Vec::with_capacity(hashes.len());
        while !hashes_hex.is_empty() {
          let this_count = TXS_PER_REQUEST.min(hashes_hex.len());

          let txs: TransactionsResponse = self
            .rpc_call(
              "get_transactions",
              Some(json!({
                "txs_hashes": hashes_hex.drain(.. this_count).collect::<Vec<_>>(),
              })),
              Some(BASE_RESPONSE_SIZE.saturating_add(BYTE_FACTOR_IN_JSON_RESPONSE_SIZE.saturating_mul(this_count.saturating_mul(TRANSACTION_SIZE_BOUND)))),
            )
            .await?;

          if !txs.missed_tx.is_empty() {
            Err(TransactionsError::TransactionNotFound)?;
          }
          if txs.txs.len() != this_count {
            Err(InterfaceError::InvalidInterface(
              "not missing any transactions yet didn't return all transactions".to_string(),
            ))?;
          }

          all_txs.extend(txs.txs);
        }

        all_txs
          .iter()
          .map(|res| {
            // https://github.com/monero-project/monero/issues/8311
            let buf =
              rpc_hex(if !res.as_hex.is_empty() { &res.as_hex } else { &res.pruned_as_hex })?;
            let mut buf = buf.as_slice();
            let tx = Transaction::read(&mut buf).map_err(|_| {
              InterfaceError::InvalidInterface(format!(
                "node yielded transaction allegedly with hash {:?} which was invalid",
                rpc_hex(&res.tx_hash).ok().map(hex::encode),
              ))
            })?;
            if !buf.is_empty() {
              Err(InterfaceError::InvalidInterface("transaction had extra bytes after it".to_string()))?;
            }

            // We check this to ensure we didn't read a pruned transaction when we meant to read an
            // actual transaction. That shouldn't be possible, as they have different
            // serializations, yet it helps to ensure that if we applied the above exception (using
            //  the pruned data), it was for the right reason
            if res.as_hex.is_empty() {
              match tx.prefix().inputs.first() {
                Some(Input::Gen { .. }) => (),
                _ => Err(TransactionsError::PrunedTransaction)?,
              }
            }

            Ok(tx)
          })
          .collect()
      }
    }

    fn pruned_transactions(
      &self,
      hashes: &[[u8; 32]],
    ) -> impl Send + Future<Output = Result<Vec<PrunedTransactionWithPrunableHash>, TransactionsError>>
    {
      async move {
        let mut hashes_hex = hashes.iter().map(hex::encode).collect::<Vec<_>>();
        let mut all_txs = Vec::with_capacity(hashes.len());
        while !hashes_hex.is_empty() {
          let this_count = TXS_PER_REQUEST.min(hashes_hex.len());

          let txs: TransactionsResponse = self
            .rpc_call(
              "get_transactions",
              Some(json!({
                "txs_hashes": hashes_hex.drain(.. this_count).collect::<Vec<_>>(),
                "prune": true,
              })),
              Some(BASE_RESPONSE_SIZE.saturating_add(BYTE_FACTOR_IN_JSON_RESPONSE_SIZE.saturating_mul(this_count.saturating_mul(TRANSACTION_SIZE_BOUND)))),
            )
            .await?;

          if !txs.missed_tx.is_empty() {
            Err(TransactionsError::TransactionNotFound)?;
          }
          if txs.txs.len() != this_count {
            Err(InterfaceError::InvalidInterface(
              "not missing any transactions yet didn't return all pruned transactions".to_string(),
            ))?;
          }

          all_txs.extend(txs.txs);
        }

        all_txs
          .iter()
          .map(|res| {
            let buf = rpc_hex(&res.pruned_as_hex)?;
            let mut buf = buf.as_slice();
            let tx = Transaction::<Pruned>::read(&mut buf).map_err(|_| {
              InterfaceError::InvalidInterface(
                format!("node yielded transaction allegedly with hash {:?} which was invalid",
                rpc_hex(&res.tx_hash).ok().map(hex::encode),
            ))
            })?;
            if !buf.is_empty() {
              Err(InterfaceError::InvalidInterface(
                "pruned transaction had extra bytes after it".to_string(),
              ))?;
            }
            let prunable_hash = (!matches!(tx, Transaction::V1 { .. }))
              .then(|| hash_hex(&res.prunable_hash))
              .transpose()?;
            Ok(PrunedTransactionWithPrunableHash::new(tx, prunable_hash).unwrap())
          })
          .collect()
      }
    }
  }
}

impl<T: HttpTransport> PublishTransaction for MoneroDaemon<T> {
  fn publish_transaction(
    &self,
    tx: &Transaction,
  ) -> impl Send + Future<Output = Result<(), PublishTransactionError>> {
    async move {
      #[allow(dead_code)]
      #[derive(Debug, Deserialize)]
      struct SendRawResponse {
        status: String,
        double_spend: bool,
        fee_too_low: bool,
        invalid_input: bool,
        invalid_output: bool,
        low_mixin: bool,
        not_relayed: bool,
        overspend: bool,
        too_big: bool,
        too_few_outputs: bool,
        reason: String,
      }

      let res: SendRawResponse = self
        .rpc_call(
          "send_raw_transaction",
          Some(json!({ "tx_as_hex": hex::encode(tx.serialize()), "do_sanity_checks": false })),
          Some(BASE_RESPONSE_SIZE),
        )
        .await?;

      if res.status != "OK" {
        Err(PublishTransactionError::TransactionRejected(res.reason))?;
      }

      Ok(())
    }
  }
}

mod provides_fee_rates {
  use super::*;

  // Number of blocks the fee estimate will be valid for
  // https://github.com/monero-project/monero/blob/94e67bf96bbc010241f29ada6abc89f49a81759c
  //   /src/wallet/wallet2.cpp#L121
  const GRACE_BLOCKS_FOR_FEE_ESTIMATE: u64 = 10;

  impl<T: HttpTransport> ProvidesUnvalidatedFeeRates for MoneroDaemon<T> {
    fn fee_rate(
      &self,
      priority: FeePriority,
    ) -> impl Send + Future<Output = Result<FeeRate, FeeError>> {
      async move {
        #[derive(Debug, Deserialize)]
        struct FeeResponse {
          status: String,
          fees: Option<Vec<u64>>,
          fee: u64,
          quantization_mask: u64,
        }

        let res: FeeResponse = self
          .json_rpc_call(
            "get_fee_estimate",
            Some(json!({ "grace_blocks": GRACE_BLOCKS_FOR_FEE_ESTIMATE })),
            Some(BASE_RESPONSE_SIZE),
          )
          .await?;

        if res.status != "OK" {
          Err(FeeError::InvalidFee)?;
        }

        if let Some(fees) = res.fees {
          // https://github.com/monero-project/monero/blob/94e67bf96bbc010241f29ada6abc89f49a81759c/
          // src/wallet/wallet2.cpp#L7615-L7620
          let priority_idx = usize::try_from(if priority.to_u32() >= 4 {
            3
          } else {
            priority.to_u32().saturating_sub(1)
          })
          .map_err(|_| FeeError::InvalidFeePriority)?;

          if priority_idx >= fees.len() {
            Err(FeeError::InvalidFeePriority)?
          } else {
            FeeRate::new(fees[priority_idx], res.quantization_mask).ok_or(FeeError::InvalidFee)
          }
        } else {
          // https://github.com/monero-project/monero/blob/94e67bf96bbc010241f29ada6abc89f49a81759c/
          //   src/wallet/wallet2.cpp#L7569-L7584
          // https://github.com/monero-project/monero/blob/94e67bf96bbc010241f29ada6abc89f49a81759c/
          //   src/wallet/wallet2.cpp#L7660-L7661
          let priority_idx =
            usize::try_from(if priority.to_u32() == 0 { 1 } else { priority.to_u32() - 1 })
              .map_err(|_| FeeError::InvalidFeePriority)?;
          const MULTIPLIERS: [u64; 4] = [1, 5, 25, 1000];
          let fee_multiplier =
            *MULTIPLIERS.get(priority_idx).ok_or(FeeError::InvalidFeePriority)?;

          FeeRate::new(
            res.fee.checked_mul(fee_multiplier).ok_or(FeeError::InvalidFee)?,
            res.quantization_mask,
          )
          .ok_or(FeeError::InvalidFee)
        }
      }
    }
  }
}

/// A prelude of recommended imports to glob import.
pub mod prelude {
  pub use monero_interface::prelude::*;
  pub use crate::{HttpTransport, MoneroDaemon};
}
