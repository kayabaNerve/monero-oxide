use core::{fmt::Debug, future::Future};
use alloc::{vec::Vec, string::String};

use serde::{Serialize, Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};

use monero_oxide::{
  transaction::{Input, Pruned, Transaction},
  block::Block,
};

use crate::{
  RpcError, PrunedTransactionWithPrunableHash, ProvidesUnvalidatedTransactions,
  ProvidesUnvalidatedBlockchain, Rpc, rpc_hex, hash_hex,
};

// Monero errors if more than 100 is requested unless using a non-restricted RPC
// https://github.com/monero-project/monero/blob/cc73fe71162d564ffda8e549b79a350bca53c454
//   /src/rpc/core_rpc_server.cpp#L75
const TXS_PER_REQUEST: usize = 100;

#[derive(Debug, Deserialize)]
struct JsonRpcResponse<T> {
  result: T,
}

/// An RPC connection to a Monero daemon.
///
/// This is abstract such that users can use an HTTP library (which being their choice), a
/// Tor/i2p-based transport, or even a memory buffer an external service somehow routes.
///
/// While no implementors are directly provided, [monero-simple-request-rpc](
///   https://github.com/monero-oxide/monero-oxide/tree/main/monero-oxide/rpc/simple-request
/// ) is recommended.
pub trait MoneroDaemon: Sync + Clone {
  /// Perform a POST request to the specified route with the specified body.
  ///
  /// The implementor is left to handle anything such as authentication.
  fn post(
    &self,
    route: &str,
    body: Vec<u8>,
  ) -> impl Send + Future<Output = Result<Vec<u8>, RpcError>>;

  /// Perform a RPC call to the specified route with the provided parameters.
  ///
  /// This is NOT a JSON-RPC call. They use a route of "json_rpc" and are available via
  /// `json_rpc_call`.
  fn rpc_call<Params: Send + Serialize + Debug, Response: DeserializeOwned + Debug>(
    &self,
    route: &str,
    params: Option<Params>,
  ) -> impl Send + Future<Output = Result<Response, RpcError>> {
    async move {
      let res = self
        .post(
          route,
          if let Some(params) = params.as_ref() {
            serde_json::to_string(params)
              .map_err(|e| {
                RpcError::InternalError(format!(
                  "couldn't convert parameters ({params:?}) to JSON: {e:?}"
                ))
              })?
              .into_bytes()
          } else {
            vec![]
          },
        )
        .await?;
      let res_str = std_shims::str::from_utf8(&res)
        .map_err(|_| RpcError::InvalidNode("response wasn't utf-8".to_string()))?;
      serde_json::from_str(res_str)
        .map_err(|_| RpcError::InvalidNode(format!("response wasn't the expected json: {res_str}")))
    }
  }

  /// Perform a JSON-RPC call with the specified method with the provided parameters.
  fn json_rpc_call<Response: DeserializeOwned + Debug>(
    &self,
    method: &str,
    params: Option<Value>,
  ) -> impl Send + Future<Output = Result<Response, RpcError>> {
    async move {
      let mut req = json!({ "method": method });
      if let Some(params) = params {
        req
          .as_object_mut()
          .expect("accessing object as object failed?")
          .insert("params".into(), params);
      }
      Ok(self.rpc_call::<_, JsonRpcResponse<Response>>("json_rpc", Some(req)).await?.result)
    }
  }

  /// Perform a binary call to the specified route with the provided parameters.
  fn bin_call(
    &self,
    route: &str,
    params: Vec<u8>,
  ) -> impl Send + Future<Output = Result<Vec<u8>, RpcError>> {
    async move { self.post(route, params).await }
  }
}

mod provides_transaction {
  use super::*;

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

  impl<D: MoneroDaemon> ProvidesUnvalidatedTransactions for D {
    fn get_transactions(
      &self,
      hashes: &[[u8; 32]],
    ) -> impl Send + Future<Output = Result<Vec<Transaction>, RpcError>> {
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
            )
            .await?;

          if !txs.missed_tx.is_empty() {
            Err(RpcError::TransactionsNotFound(
              txs.missed_tx.iter().map(|hash| hash_hex(hash)).collect::<Result<_, _>>()?,
            ))?;
          }
          if txs.txs.len() != this_count {
            Err(RpcError::InvalidNode(
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
            let tx = Transaction::read(&mut buf).map_err(|_| match hash_hex(&res.tx_hash) {
              Ok(hash) => RpcError::InvalidTransaction(hash),
              Err(err) => err,
            })?;
            if !buf.is_empty() {
              Err(RpcError::InvalidNode("transaction had extra bytes after it".to_string()))?;
            }

            // We check this to ensure we didn't read a pruned transaction when we meant to read an
            // actual transaction. That shouldn't be possible, as they have different
            // serializations, yet it helps to ensure that if we applied the above exception (using
            //  the pruned data), it was for the right reason
            if res.as_hex.is_empty() {
              match tx.prefix().inputs.first() {
                Some(Input::Gen { .. }) => (),
                _ => Err(RpcError::PrunedTransaction)?,
              }
            }

            Ok(tx)
          })
          .collect()
      }
    }

    fn get_pruned_transactions(
      &self,
      hashes: &[[u8; 32]],
    ) -> impl Send + Future<Output = Result<Vec<PrunedTransactionWithPrunableHash>, RpcError>> {
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
            )
            .await?;

          if !txs.missed_tx.is_empty() {
            Err(RpcError::TransactionsNotFound(
              txs.missed_tx.iter().map(|hash| hash_hex(hash)).collect::<Result<_, _>>()?,
            ))?;
          }

          all_txs.extend(txs.txs);
        }

        all_txs
          .iter()
          .map(|res| {
            let buf = rpc_hex(&res.pruned_as_hex)?;
            let mut buf = buf.as_slice();
            let tx =
              Transaction::<Pruned>::read(&mut buf).map_err(|_| match hash_hex(&res.tx_hash) {
                Ok(hash) => RpcError::InvalidTransaction(hash),
                Err(err) => err,
              })?;
            if !buf.is_empty() {
              Err(RpcError::InvalidNode(
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

impl<D: MoneroDaemon> ProvidesUnvalidatedBlockchain for D {
  fn get_latest_block_number(&self) -> impl Send + Future<Output = Result<usize, RpcError>> {
    async move {
      #[derive(Debug, Deserialize)]
      struct HeightResponse {
        height: usize,
      }
      let res = self.rpc_call::<Option<()>, HeightResponse>("get_height", None).await?.height;
      res.checked_sub(1).ok_or_else(|| {
        RpcError::InvalidNode(
          "node claimed the blockchain didn't even have the genesis block".to_string(),
        )
      })
    }
  }

  fn get_block_by_number(
    &self,
    number: usize,
  ) -> impl Send + Future<Output = Result<Block, RpcError>> {
    async move {
      #[derive(Debug, Deserialize)]
      struct BlockResponse {
        blob: String,
      }

      let res: BlockResponse =
        self.json_rpc_call("get_block", Some(json!({ "height": number }))).await?;

      Block::read(&mut rpc_hex(&res.blob)?.as_slice())
        .map_err(|_| RpcError::InvalidNode("invalid block".to_string()))
    }
  }

  fn get_block(&self, hash: [u8; 32]) -> impl Send + Future<Output = Result<Block, RpcError>> {
    async move {
      #[derive(Debug, Deserialize)]
      struct BlockResponse {
        blob: String,
      }

      let res: BlockResponse =
        self.json_rpc_call("get_block", Some(json!({ "hash": hex::encode(hash) }))).await?;

      Block::read(&mut rpc_hex(&res.blob)?.as_slice())
        .map_err(|_| RpcError::InvalidNode("invalid block".to_string()))
    }
  }
}

impl<D: MoneroDaemon> Rpc for D {}
