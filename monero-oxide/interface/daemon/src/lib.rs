#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

use core::{
  fmt::Debug,
  ops::{Bound, RangeBounds},
  future::Future,
};

extern crate alloc;
use alloc::{
  format, vec,
  vec::Vec,
  string::{String, ToString},
};

use std_shims::io;

use curve25519_dalek::EdwardsPoint;

use serde::{Serialize, Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};

use monero_oxide::{
  io::{CompressedPoint, read_byte, read_u64, read_bytes},
  transaction::{MAX_NON_MINER_TRANSACTION_SIZE, Input, Timelock, Pruned, Transaction},
  block::Block,
  DEFAULT_LOCK_WINDOW,
};
use monero_address::Address;

use monero_interface::*;

mod epee;

const BASE_RESPONSE_SIZE: usize = u16::MAX as usize;
const BYTE_FACTOR_IN_JSON_RESPONSE_SIZE: usize = 100;

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

/*
  Monero doesn't have a block size limit, solely one contextual to the current blockchain. With a
  default size of 300 KB, we assume it won't reach 5 MB. Even if it does, we'll still accept a 5 MB
  block if it fits within our multiplicative allowance or other additive allowances.
*/
const BLOCK_SIZE_BOUND: usize = 5_000_000;

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

  /// Perform a binary call to the specified route with the provided parameters.
  fn bin_call<'a>(
    &'a self,
    route: &'a str,
    params: Vec<u8>,
    response_size_limit: Option<usize>,
  ) -> impl use<'a, T> + Send + Future<Output = Result<Vec<u8>, InterfaceError>> {
    async move {
      let res = self.0.post(route, params, response_size_limit).await?;
      epee::check_status(&res)?;
      Ok(res)
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
            let prunable_hash = matches!(tx, Transaction::V2 { .. })
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

impl<T: HttpTransport> ProvidesUnvalidatedBlockchain for MoneroDaemon<T> {
  fn block_by_number(
    &self,
    number: usize,
  ) -> impl Send + Future<Output = Result<Block, InterfaceError>> {
    async move {
      let request = [
        epee::HEADER,
        &[5 << 2],
        &[u8::try_from("requested_info".len()).unwrap()],
        "requested_info".as_bytes(),
        &[epee::Type::Uint8 as u8],
        &[0],
        &[u8::try_from("max_block_count".len()).unwrap()],
        "max_block_count".as_bytes(),
        &[epee::Type::Uint8 as u8],
        &[1],
        &[u8::try_from("prune".len()).unwrap()],
        "prune".as_bytes(),
        &[epee::Type::Bool as u8],
        &[1],
        &[u8::try_from("start_height".len()).unwrap()],
        "start_height".as_bytes(),
        &[epee::Type::Uint8 as u8],
        &[0],
        &[u8::try_from("heights".len()).unwrap()],
        "heights".as_bytes(),
        &[(epee::Type::Uint64 as u8) | epee::ARRAY_FLAG],
        &[1 << 2],
        &u64::try_from(number)
          .map_err(|_| {
            InterfaceError::InternalError(
              "block number wasn't representable as a `u64`".to_string(),
            )
          })?
          .to_le_bytes(),
      ]
      .concat();

      let res = self
        .bin_call(
          "get_blocks_by_height.bin",
          request,
          Some(BASE_RESPONSE_SIZE.saturating_add(BLOCK_SIZE_BOUND)),
        )
        .await?;
      let mut res = res.as_slice();

      let len = epee::seek(&mut res, epee::Type::String, "block")
        .map_err(|e| InterfaceError::InvalidInterface(format!("couldn't seek `block`: {e:?}")))?
        .unwrap_or(0);
      if len != 1 {
        Err(InterfaceError::InvalidInterface(
          "daemon didn't return one block as requested".to_string(),
        ))?;
      }

      let _ = epee::read_vi(&mut res)
        .map_err(|_| InterfaceError::InvalidInterface("couldn't read block's length".to_string()));
      Block::read(&mut res)
        .map_err(|_| InterfaceError::InvalidInterface("invalid block".to_string()))
    }
  }

  fn block(&self, hash: [u8; 32]) -> impl Send + Future<Output = Result<Block, InterfaceError>> {
    async move {
      #[derive(Debug, Deserialize)]
      struct BlockResponse {
        blob: String,
      }

      let res: BlockResponse = self
        .json_rpc_call(
          "get_block",
          Some(json!({ "hash": hex::encode(hash) })),
          Some(
            BASE_RESPONSE_SIZE
              .saturating_add(BYTE_FACTOR_IN_JSON_RESPONSE_SIZE.saturating_mul(BLOCK_SIZE_BOUND)),
          ),
        )
        .await?;

      Block::read(&mut rpc_hex(&res.blob)?.as_slice())
        .map_err(|_| InterfaceError::InvalidInterface("invalid block".to_string()))
    }
  }

  fn block_hash(
    &self,
    number: usize,
  ) -> impl Send + Future<Output = Result<[u8; 32], InterfaceError>> {
    async move {
      #[derive(Debug, Deserialize)]
      struct BlockHeaderResponse {
        hash: String,
      }
      #[derive(Debug, Deserialize)]
      struct BlockHeaderByHeightResponse {
        block_header: BlockHeaderResponse,
      }

      let header: BlockHeaderByHeightResponse = self
        .json_rpc_call(
          "get_block_header_by_height",
          Some(json!({ "height": number })),
          Some(
            BASE_RESPONSE_SIZE
              .saturating_add(BYTE_FACTOR_IN_JSON_RESPONSE_SIZE.saturating_mul(256)),
          ),
        )
        .await?;
      hash_hex(&header.block_header.hash)
    }
  }
}

impl<T: HttpTransport> ProvidesUnvalidatedOutputs for MoneroDaemon<T> {
  fn output_indexes(
    &self,
    hash: [u8; 32],
  ) -> impl Send + Future<Output = Result<Vec<u64>, InterfaceError>> {
    async move {
      let request = [
        epee::HEADER,
        &[1u8 << 2],
        &[u8::try_from("txid".len()).unwrap()],
        "txid".as_bytes(),
        &[epee::Type::String as u8],
        &[32u8 << 2],
        &hash,
      ]
      .concat();

      // 8 bytes per index, 10,000 indexes per transaction
      let epee_res = self
        .bin_call("get_o_indexes.bin", request, Some(BASE_RESPONSE_SIZE.saturating_add(10_000 * 8)))
        .await?;
      let mut epee_res = epee_res.as_slice();

      let mut res = vec![];
      if let Some(len) =
        epee::seek(&mut epee_res, epee::Type::Uint64, "o_indexes").map_err(|e| {
          InterfaceError::InvalidInterface(format!("couldn't seek `o_indexes`: {e:?}"))
        })?
      {
        for _ in 0 .. len {
          res.push(read_u64(&mut epee_res).map_err(|e| {
            InterfaceError::InvalidInterface(format!("incomplete `o_indexes`: {e:?}"))
          })?);
        }
      }
      Ok(res)
    }
  }

  fn ringct_outputs(
    &self,
    indexes: &[u64],
  ) -> impl Send + Future<Output = Result<Vec<RingCtOutputInformation>, InterfaceError>> {
    async move {
      // https://github.com/monero-project/monero/blob/cc73fe71162d564ffda8e549b79a350bca53c454
      //   /src/rpc/core_rpc_server.cpp#L67
      const MAX_OUTS: usize = 5000;

      let mut res = Vec::with_capacity(indexes.len());
      let mut request = Vec::with_capacity(indexes.len().max(MAX_OUTS) * 16);
      for indexes in indexes.chunks(MAX_OUTS) {
        let indexes_len_u64 =
          u64::try_from(indexes.len()).expect("requesting more than 2**64 indexes?");

        request.clear();
        request.extend(epee::HEADER);
        request.push(1 << 2);
        request.push(u8::try_from("outputs".len()).unwrap());
        request.extend("outputs".as_bytes());
        request.push((epee::Type::Object as u8) | epee::ARRAY_FLAG);
        request.extend(((indexes_len_u64 << 2) | 0b11).to_le_bytes());
        for index in indexes {
          request.push(2u8 << 2);

          request.push(u8::try_from("amount".len()).unwrap());
          request.extend("amount".as_bytes());
          request.push(epee::Type::Uint8 as u8);
          request.push(0);

          request.push(u8::try_from("index".len()).unwrap());
          request.extend("index".as_bytes());
          request.push(epee::Type::Uint64 as u8);
          request.extend(&index.to_le_bytes());
        }

        // This is the size of the data, doubled to account for epee's structure
        const BOUND_PER_OUT: usize = 2 * (8 + 8 + 32 + 32 + 32 + 1);

        let outs = self
          .bin_call(
            "get_outs.bin",
            request.clone(),
            Some(BASE_RESPONSE_SIZE.saturating_add(indexes.len().saturating_mul(BOUND_PER_OUT))),
          )
          .await?;
        let mut outs = outs.as_slice();
        let len = epee::seek(&mut outs, epee::Type::Object, "outs")
          .map_err(|e| InterfaceError::InvalidInterface(format!("couldn't seek `outs`: {e:?}")))?
          .unwrap_or(0);

        if len != indexes_len_u64 {
          Err(InterfaceError::InvalidInterface(
            "`get_outs` response omitted requested outputs or provided additional outputs"
              .to_string(),
          ))?;
        }

        let outs = &mut outs;
        let res = &mut res;
        (move || {
          for _ in 0 .. len {
            let fields = epee::read_vi(outs)?;
            if fields != 5 {
              Err(io::Error::other("unexpected amount of fields in `get_outs` out"))?;
            }

            let mut block_number = None;
            let mut key = None;
            let mut commitment = None;
            let mut transaction = None;
            let mut unlocked = None;
            for _ in 0 .. fields {
              match epee::read_key(outs)? {
                b"height" => {
                  let _ = epee::Type::read(outs)?;
                  block_number = Some(usize::try_from(read_u64(outs)?).map_err(|_| {
                    io::Error::other("`height` wasn't representable within a `usize`")
                  })?);
                }
                b"key" => {
                  let _ = epee::Type::read(outs)?;
                  let _ = epee::read_vi(outs)?;
                  key = Some(CompressedPoint(read_bytes(outs)?));
                }
                b"mask" => {
                  let _ = epee::Type::read(outs)?;
                  let _ = epee::read_vi(outs)?;
                  commitment = Some(
                    CompressedPoint(read_bytes(outs)?)
                      .decompress()
                      .ok_or_else(|| io::Error::other("`get_outs` out had invalid commitment"))?,
                  );
                }
                b"txid" => {
                  let _ = epee::Type::read(outs)?;
                  let _ = epee::read_vi(outs)?;
                  transaction = Some(read_bytes(outs)?);
                }
                b"unlocked" => {
                  let _ = epee::Type::read(outs)?;
                  unlocked = Some(read_byte(outs)? != 0);
                }
                _ => Err(io::Error::other("`get_outs` yielded response with unrecognized field"))?,
              }
            }
            let (
              Some(block_number),
              Some(key),
              Some(commitment),
              Some(transaction),
              Some(unlocked),
            ) = (block_number, key, commitment, transaction, unlocked)
            else {
              return Err(io::Error::other("missing field for out from `get_outs`"));
            };
            res.push(RingCtOutputInformation {
              block_number,
              unlocked,
              key,
              commitment,
              transaction,
            });
          }
          Ok(())
        })()
        .map_err(|e| {
          InterfaceError::InvalidInterface(format!(
            "couldn't deserialize `get_outs` response: {e:?}"
          ))
        })?;
      }

      Ok(res)
    }
  }
}

impl<T: HttpTransport> ProvidesUnvalidatedDecoys for MoneroDaemon<T> {
  fn ringct_output_distribution(
    &self,
    range: impl Send + RangeBounds<usize>,
  ) -> impl Send + Future<Output = Result<Vec<u64>, InterfaceError>> {
    async move {
      let from = match range.start_bound() {
        Bound::Included(from) => *from,
        Bound::Excluded(from) => from.checked_add(1).ok_or_else(|| {
          InterfaceError::InternalError("range's from wasn't representable".to_string())
        })?,
        Bound::Unbounded => 0,
      };
      let to = match range.end_bound() {
        Bound::Included(to) => *to,
        Bound::Excluded(to) => to.checked_sub(1).ok_or_else(|| {
          InterfaceError::InternalError("range's to wasn't representable".to_string())
        })?,
        Bound::Unbounded => self.latest_block_number().await?,
      };
      if from > to {
        Err(InterfaceError::InternalError(format!(
          "malformed range: inclusive start {from}, inclusive end {to}"
        )))?;
      }

      let zero_zero_case = (from == 0) && (to == 0);

      let request = [
        epee::HEADER,
        &[5u8 << 2],
        &[u8::try_from("from_height".len()).unwrap()],
        "from_height".as_bytes(),
        &[epee::Type::Uint64 as u8],
        &u64::try_from(from)
          .map_err(|_| {
            InterfaceError::InternalError(
              "range's from wasn't representable as a `u64`".to_string(),
            )
          })?
          .to_le_bytes(),
        &[u8::try_from("to_height".len()).unwrap()],
        "to_height".as_bytes(),
        &[epee::Type::Uint64 as u8],
        &(if zero_zero_case {
          1u64
        } else {
          u64::try_from(to).map_err(|_| {
            InterfaceError::InternalError("range's to wasn't representable as a `u64`".to_string())
          })?
        })
        .to_le_bytes(),
        &[u8::try_from("cumulative".len()).unwrap()],
        "cumulative".as_bytes(),
        &[epee::Type::Bool as u8],
        &[1],
        &[u8::try_from("compress".len()).unwrap()],
        "compress".as_bytes(),
        &[epee::Type::Bool as u8],
        &[0], // TODO
        &[u8::try_from("amounts".len()).unwrap()],
        "amounts".as_bytes(),
        &[(epee::Type::Uint8 as u8) | epee::ARRAY_FLAG],
        &[1u8 << 2],
        &[0],
      ]
      .concat();

      let distributions = self
        .bin_call(
          "get_output_distribution.bin",
          request,
          Some(
            BASE_RESPONSE_SIZE
              .saturating_add(to.saturating_sub(from).saturating_add(2).saturating_mul(8)),
          ),
        )
        .await?;

      let start_height = epee::extract_start_height(&distributions)?;
      let mut distribution = epee::extract_distribution(&distributions)?;

      // start_height is also actually a block number, and it should be at least `from`
      // It may be after depending on when these outputs first appeared on the blockchain
      // Unfortunately, we can't validate without a binary search to find the RingCT activation
      // block and an iterative search from there, so we solely sanity check it
      if start_height < from {
        Err(InterfaceError::InvalidInterface(format!(
          "requested distribution from {from} and got from {start_height}"
        )))?;
      }
      // It shouldn't be after `to` though
      if start_height > to {
        Err(InterfaceError::InvalidInterface(format!(
          "requested distribution to {to} and got from {start_height}"
        )))?;
      }

      let expected_len = if zero_zero_case {
        2
      } else {
        (to - start_height).checked_add(1).ok_or_else(|| {
          InterfaceError::InternalError(
            "expected length of distribution exceeded usize".to_string(),
          )
        })?
      };
      // Yet this is actually a height
      if expected_len != distribution.len() {
        Err(InterfaceError::InvalidInterface(format!(
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

      Ok(distribution)
    }
  }

  fn unlocked_ringct_outputs(
    &self,
    indexes: &[u64],
    evaluate_unlocked: EvaluateUnlocked,
  ) -> impl Send + Future<Output = Result<Vec<Option<[EdwardsPoint; 2]>>, TransactionsError>> {
    async move {
      let outs = <Self as ProvidesOutputs>::ringct_outputs(self, indexes).await?;

      // Only need to fetch transactions if we're doing a deterministic check on the timelock
      let txs =
        if matches!(evaluate_unlocked, EvaluateUnlocked::FingerprintableDeterministic { .. }) {
          <Self as ProvidesTransactions>::pruned_transactions(
            self,
            &outs.iter().map(|out| out.transaction).collect::<Vec<_>>(),
          )
          .await?
        } else {
          vec![]
        };

      // TODO: https://github.com/serai-dex/serai/issues/104
      outs
        .iter()
        .enumerate()
        .map(|(i, out)| {
          /*
            If the key is invalid, preventing it from being used as a decoy, return `None` to
            trigger selection of a replacement decoy.
          */
          let Some(key) = out.key.decompress() else {
            return Ok(None);
          };
          Ok(
            (match evaluate_unlocked {
              EvaluateUnlocked::Normal => out.unlocked,
              EvaluateUnlocked::FingerprintableDeterministic { block_number } => {
                // https://github.com/monero-project/monero/blob
                //   /cc73fe71162d564ffda8e549b79a350bca53c454/src/cryptonote_core
                //   /blockchain.cpp#L90
                const ACCEPTED_TIMELOCK_DELTA: usize = 1;

                let global_timelock_satisfied = out
                  .block_number
                  .checked_add(DEFAULT_LOCK_WINDOW - 1)
                  .is_some_and(|locked| locked <= block_number);

                // https://github.com/monero-project/monero/blob
                //   /cc73fe71162d564ffda8e549b79a350bca53c454/src/cryptonote_core
                //   /blockchain.cpp#L3836
                let transaction_timelock_satisfied =
                  Timelock::Block(block_number.saturating_add(ACCEPTED_TIMELOCK_DELTA)) >=
                    txs[i].prefix().additional_timelock;

                global_timelock_satisfied && transaction_timelock_satisfied
              }
            })
            .then_some([key, out.commitment]),
          )
        })
        .collect()
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
