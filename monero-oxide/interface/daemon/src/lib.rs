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
  io::CompressedPoint,
  transaction::{MAX_NON_MINER_TRANSACTION_SIZE, Input, Timelock, Pruned, Transaction},
  block::Block,
  DEFAULT_LOCK_WINDOW,
};
use monero_address::Address;

use monero_interface::*;

const BASE_RESPONSE_SIZE: usize = u16::MAX as usize;
const BYTE_FACTOR_IN_JSON_RESPONSE_SIZE: usize = 100;
const BYTE_FACTOR_IN_BIN_RESPONSE_SIZE: usize = 4;

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

fn rpc_point(point: &str) -> Result<EdwardsPoint, InterfaceError> {
  CompressedPoint(
    rpc_hex(point)?
      .try_into()
      .map_err(|_| InterfaceError::InvalidInterface("invalid point".to_string()))?,
  )
  .decompress()
  .ok_or_else(|| InterfaceError::InvalidInterface("invalid point".to_string()))
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
      let res = self
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
    async move { self.0.post(route, params, response_size_limit).await }
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
          Some(BASE_RESPONSE_SIZE.wrapping_add(
            BYTE_FACTOR_IN_JSON_RESPONSE_SIZE.wrapping_mul(block_count.wrapping_mul(32)),
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
              Some(BASE_RESPONSE_SIZE.wrapping_add(BYTE_FACTOR_IN_JSON_RESPONSE_SIZE.wrapping_mul(this_count.wrapping_mul(TRANSACTION_SIZE_BOUND)))),
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
              Some(BASE_RESPONSE_SIZE.wrapping_add(BYTE_FACTOR_IN_JSON_RESPONSE_SIZE.wrapping_mul(this_count.wrapping_mul(TRANSACTION_SIZE_BOUND)))),
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
      #[derive(Debug, Deserialize)]
      struct BlockResponse {
        blob: String,
      }

      let res: BlockResponse = self
        .json_rpc_call(
          "get_block",
          Some(json!({ "height": number })),
          Some(
            BASE_RESPONSE_SIZE
              .wrapping_add(BYTE_FACTOR_IN_JSON_RESPONSE_SIZE.wrapping_mul(BLOCK_SIZE_BOUND)),
          ),
        )
        .await?;

      Block::read(&mut rpc_hex(&res.blob)?.as_slice())
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
              .wrapping_add(BYTE_FACTOR_IN_JSON_RESPONSE_SIZE.wrapping_mul(BLOCK_SIZE_BOUND)),
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
            BASE_RESPONSE_SIZE.wrapping_add(BYTE_FACTOR_IN_JSON_RESPONSE_SIZE.wrapping_mul(256)),
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
      // Given the immaturity of Rust epee libraries, this is a homegrown one which is only
      // validated to work against this specific function

      use monero_oxide::io::*;

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

      // 8 bytes per index, 1024 indexes per transaction
      let indexes_buf = self
        .bin_call(
          "get_o_indexes.bin",
          request,
          Some(BASE_RESPONSE_SIZE.wrapping_add(BYTE_FACTOR_IN_BIN_RESPONSE_SIZE * 1024 * 8)),
        )
        .await?;
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
                _ => Err(io::Error::other("unrecognized field in get_o_indexes".to_string()))?,
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
      .map_err(|e| InterfaceError::InvalidInterface(format!("invalid binary response: {e:?}")))
    }
  }

  fn ringct_outputs(
    &self,
    indexes: &[u64],
  ) -> impl Send + Future<Output = Result<Vec<RingCtOutputInformation>, InterfaceError>> {
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
            Some(BASE_RESPONSE_SIZE.wrapping_add(
              BYTE_FACTOR_IN_JSON_RESPONSE_SIZE.wrapping_mul(indexes.len().wrapping_mul(128)),
            )),
          )
          .await?;

        if rpc_res.status != "OK" {
          Err(InterfaceError::InvalidInterface("bad response to get_outs".to_string()))?;
        }

        if rpc_res.outs.len() != indexes.len() {
          Err(InterfaceError::InvalidInterface(
            "get_outs response omitted requested outputs".to_string(),
          ))?;
        }

        res.extend(
          rpc_res
            .outs
            .into_iter()
            .map(|output| {
              Ok(RingCtOutputInformation {
                block_number: output.height,
                unlocked: output.unlocked,
                key: CompressedPoint(rpc_hex(&output.key)?.try_into().map_err(|_| {
                  InterfaceError::InvalidInterface("output key wasn't 32 bytes".to_string())
                })?),
                commitment: rpc_point(&output.mask)?,
                transaction: hash_hex(&output.txid)?,
              })
            })
            .collect::<Result<Vec<_>, InterfaceError>>()?,
        );
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
          Some(BASE_RESPONSE_SIZE.wrapping_add(
            BYTE_FACTOR_IN_JSON_RESPONSE_SIZE.wrapping_mul(to.max(2).wrapping_mul(16)),
          )),
        )
        .await?;

      if distributions.status != "OK" {
        Err(InterfaceError::InterfaceError(
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
                  Timelock::Block(block_number.wrapping_add(ACCEPTED_TIMELOCK_DELTA)) >=
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
