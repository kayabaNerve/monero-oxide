use core::{
  fmt::Debug,
  ops::{RangeInclusive, Bound, RangeBounds},
  future::Future,
};

use alloc::{
  format, vec,
  vec::Vec,
  string::{String, ToString},
};

use curve25519_dalek::EdwardsPoint;

use serde::Deserialize;
use serde_json::json;

use monero_oxide::{
  io::read_u64,
  transaction::{Timelock, Transaction},
  block::Block,
  DEFAULT_LOCK_WINDOW,
};

use monero_interface::*;

use crate::{
  BASE_RESPONSE_SIZE, BYTE_FACTOR_IN_JSON_RESPONSE_SIZE, HttpTransport, MoneroDaemon, rpc_hex,
  hash_hex,
};

mod epee;

/*
  Monero doesn't have a block size limit, solely one contextual to the current blockchain. With a
  default size of 300 KB, we assume it won't reach 5 MB. Even if it does, we'll still accept a 5 MB
  block if it fits within our multiplicative allowance or other additive allowances.
*/
const BLOCK_SIZE_BOUND: usize = 5_000_000;

impl<T: HttpTransport> MoneroDaemon<T> {
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
}

impl<T: HttpTransport> MoneroDaemon<T> {
  async fn fetch_contiguous_blocks(
    &self,
    range: RangeInclusive<usize>,
  ) -> Result<(usize, Vec<u8>), InterfaceError> {
    let Some(requested_blocks_sub_one) = range.end().checked_sub(*range.start()) else {
      return Ok((0, vec![]));
    };
    let Some(requested_blocks) = requested_blocks_sub_one.checked_add(1) else {
      Err(InterfaceError::InternalError(
        "requested more blocks than representable in a `usize`".to_string(),
      ))?
    };
    let Ok(requested_blocks_u64) = u64::try_from(requested_blocks) else {
      Err(InterfaceError::InternalError(
        "amount of requested blocks wasn't representable in a `u64`".to_string(),
      ))?
    };

    let Ok(start) = u64::try_from(*range.start()) else {
      Err(InterfaceError::InternalError("start block wasn't representable in a `u64`".to_string()))?
    };
    let Ok(end) = u64::try_from(*range.end()) else {
      Err(InterfaceError::InternalError("start block wasn't representable in a `u64`".to_string()))?
    };

    let mut request = vec![
      epee::HEADER,
      &[3 << 2],
      &[u8::try_from("requested_info".len()).unwrap()],
      "requested_info".as_bytes(),
      &[epee::Type::Uint8 as u8],
      &[0],
      &[u8::try_from("prune".len()).unwrap()],
      "prune".as_bytes(),
      &[epee::Type::Bool as u8],
      &[1],
      &[u8::try_from("heights".len()).unwrap()],
      "heights".as_bytes(),
      &[(epee::Type::Uint64 as u8) | epee::ARRAY_FLAG],
      &((requested_blocks_u64 << 2) | 0b11).to_le_bytes(),
    ]
    .concat();
    request.reserve(requested_blocks * 8);
    for i in start ..= end {
      request.extend(&i.to_le_bytes());
    }

    // TODO: Do we have to chunk these requests?
    let blocks = self
      .bin_call(
        "get_blocks_by_height.bin",
        request,
        Some(BASE_RESPONSE_SIZE.saturating_add(requested_blocks.saturating_mul(BLOCK_SIZE_BOUND))),
      )
      .await?;

    Ok((requested_blocks, blocks))
  }
}

impl<T: HttpTransport> ProvidesUnvalidatedBlockchain for MoneroDaemon<T> {
  fn contiguous_blocks(
    &self,
    range: RangeInclusive<usize>,
  ) -> impl Send + Future<Output = Result<Vec<Block>, InterfaceError>> {
    async move {
      let (requested_blocks, blocks) = self.fetch_contiguous_blocks(range).await?;
      let mut res = Vec::with_capacity(requested_blocks);

      let mut blocks = epee::extract_blocks_from_blocks_bin(&blocks)?;
      for block in (&mut blocks).take(requested_blocks) {
        res.push(block?);
      }

      if res.len() != requested_blocks {
        Err(InterfaceError::InvalidInterface(format!(
          "node returned {} blocks, requested {requested_blocks}",
          res.len()
        )))?;
      }
      if blocks.next().is_some() {
        Err(InterfaceError::InvalidInterface(
          "epee response had extra instances of `block`".to_string(),
        ))?;
      }

      Ok(res)
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

impl<T: HttpTransport> ProvidesUnvalidatedScannableBlocks for MoneroDaemon<T> {
  fn contiguous_scannable_blocks(
    &self,
    range: RangeInclusive<usize>,
  ) -> impl Send + Future<Output = Result<Vec<ScannableBlock>, InterfaceError>> {
    async move {
      let (requested_blocks, blocks_bin) = self.fetch_contiguous_blocks(range).await?;
      let mut res = Vec::with_capacity(requested_blocks);

      let mut blocks = epee::extract_blocks_from_blocks_bin(&blocks_bin)?;
      let mut txs = epee::extract_txs_from_blocks_bin(&blocks_bin)?;

      // NOTE: If we rip out the very fast index alone, we can calculate all of the rest
      let mut output_indices_per_transaction =
        epee::seek_all(&blocks_bin, epee::Type::Uint64, "indices").map_err(|e| {
          InterfaceError::InvalidInterface(format!(
            "couldn't `seek_all` for `get_blocks_by_height.bin`: {e:?}"
          ))
        })?;

      for block in (&mut blocks).take(requested_blocks) {
        let block = block?;
        let mut block_txs = vec![];

        let mut output_index_for_first_ringct_output = None;
        let mut update_output_index_for_first_ringct_output = |tx: &Transaction<_>| {
          let mut indices = output_indices_per_transaction
            .next()
            .ok_or_else(|| {
              InterfaceError::InvalidInterface(
                "`get_blocks.bin` contained insufficient output indices".to_string(),
              )
            })?
            .map_err(|e| {
              InterfaceError::InvalidInterface(format!("couldn't seek to `indices`: {e:?}"))
            })?;
          #[allow(clippy::collapsible_if)]
          if output_index_for_first_ringct_output.is_none() {
            if matches!(tx, Transaction::V2 { .. }) && (!tx.prefix().outputs.is_empty()) {
              output_index_for_first_ringct_output =
                Some(read_u64(&mut indices.1).map_err(|e| {
                  InterfaceError::InvalidInterface(format!(
                    "couldn't read output index from epee: {e:?}"
                  ))
                })?);
            }
          }
          Ok(())
        };
        let pruned_miner_transaction = block.miner_transaction.clone().into();
        update_output_index_for_first_ringct_output(&pruned_miner_transaction)?;

        for hash in &block.transactions {
          let tx = txs.next().ok_or_else(|| {
            InterfaceError::InvalidInterface(
              "`get_blocks.bin` contained less transactions than specified in its blocks"
                .to_string(),
            )
          })??;
          let tx = tx.verify_as_possible(*hash).map_err(|_| {
            InterfaceError::InvalidInterface(
              "failed to verify pruned transaction in scannable block".to_string(),
            )
          })?;
          update_output_index_for_first_ringct_output(&tx)?;
          block_txs.push(tx);
        }

        res.push(ScannableBlock {
          block,
          transactions: block_txs,
          output_index_for_first_ringct_output,
        });
      }

      if res.len() != requested_blocks {
        Err(InterfaceError::InvalidInterface(format!(
          "node returned {} blocks, requested {requested_blocks}",
          res.len()
        )))?;
      }
      if blocks.next().is_some() ||
        txs.next().is_some() ||
        output_indices_per_transaction.next().is_some()
      {
        Err(InterfaceError::InvalidInterface(
          "epee response had extra instances of `block`, `blob`, or `indices`".to_string(),
        ))?;
      }

      Ok(res)
    }
  }

  fn scannable_block(
    &self,
    hash: [u8; 32],
  ) -> impl Send + Future<Output = Result<ScannableBlock, InterfaceError>> {
    async move {
      let block = <Self as ProvidesBlockchain>::block(self, hash).await?;
      <Self as ExpandToScannableBlock>::expand_to_scannable_block(self, block).await.map_err(|e| {
        match e {
          TransactionsError::InterfaceError(e) => e,
          TransactionsError::TransactionNotFound => InterfaceError::InvalidInterface(
            "node sent us blocks it doesn't have the transactions for".to_string(),
          ),
          TransactionsError::PrunedTransaction => InterfaceError::InternalError(
            "requesting pruned transactions yet errored on pruned transaction".to_string(),
          ),
        }
      })
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

        epee::accumulate_outs(&outs, indexes.len(), &mut res).map_err(|e| {
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
