use core::{
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

use monero_oxide::{
  transaction::{Output, Timelock, PotentiallyPruned, Transaction},
  block::Block,
  DEFAULT_LOCK_WINDOW,
};

use monero_interface::*;

use crate::{
  MAX_RPC_RESPONSE_SIZE, BASE_RESPONSE_SIZE, TRANSACTION_SIZE_BOUND, HttpTransport, MoneroDaemon,
  rpc_hex, hash_hex,
};

mod epee;

impl<T: HttpTransport> MoneroDaemon<T> {
  /// Perform a binary call to the specified route with the provided parameters.
  fn bin_call<'a>(
    &'a self,
    route: &'a str,
    params: Vec<u8>,
    response_size_limit: usize,
  ) -> impl use<'a, T> + Send + Future<Output = Result<Vec<u8>, InterfaceError>> {
    async move {
      let res = self
        .transport
        .post(route, params, self.response_size_limits.then_some(response_size_limit))
        .await?;
      epee::check_status(&res)?;
      Ok(res)
    }
  }
}

impl<T: HttpTransport> MoneroDaemon<T> {
  // This MUST NOT be called with a start of `0`.
  async fn fetch_contiguous_blocks(
    &self,
    range: RangeInclusive<usize>,
  ) -> Result<(usize, Vec<Vec<u8>>), InterfaceError> {
    /*
      The following code uses `get_blocks.bin`, with the request specifying the `start_height`
      field. Monero only observes this field if it has a non-zero value, hence why we must bound
      the start is non-zero here. The caller is required to ensure they handle the zero case
      themselves.

      https://github.com/monero-project/monero/blob/b591866fcfed400bc89631686655aa769ec5f2dd
        /src/cryptonote_core/blockchain.cpp#L2745
    */
    if *range.start() == 0 {
      Err(InterfaceError::InternalError(
        "attempting to fetch contiguous blocks from 0".to_string(),
      ))?;
    }

    let Some(requested_blocks_sub_one) = range.end().checked_sub(*range.start()) else {
      return Ok((0, vec![]));
    };
    let Some(requested_blocks) = requested_blocks_sub_one.checked_add(1) else {
      Err(InterfaceError::InternalError(
        "requested more blocks than representable in a `usize`".to_string(),
      ))?
    };

    let Ok(mut start) = u64::try_from(*range.start()) else {
      Err(InterfaceError::InternalError("start block wasn't representable in a `u64`".to_string()))?
    };
    let Ok(end) = u64::try_from(*range.end()) else {
      Err(InterfaceError::InternalError("end block wasn't representable in a `u64`".to_string()))?
    };
    let Ok(mut remaining_blocks) = u64::try_from(requested_blocks) else {
      Err(InterfaceError::InternalError(
        "amount of requested blocks wasn't representable in a `u64`".to_string(),
      ))?
    };

    let expected_request_header_len = 32;
    let expected_request_len = expected_request_header_len + 8 + 25;
    let mut request = Vec::with_capacity(expected_request_len);
    request.extend(epee::HEADER);
    request.push(epee::VERSION);
    request.push(3 << 2);

    request.push(u8::try_from("prune".len()).unwrap());
    request.extend("prune".as_bytes());
    request.push(epee::Type::Bool as u8);
    request.push(1);
    request.push(u8::try_from("start_height".len()).unwrap());
    request.extend("start_height".as_bytes());
    request.push(epee::Type::Uint64 as u8);
    debug_assert_eq!(expected_request_header_len, request.len());

    let mut blocks = vec![];
    while start <= end {
      request.truncate(expected_request_header_len);

      request.extend(start.to_le_bytes());

      /*
        This field is for a not-yet-released version of Monero, with the relevant pull request
        being https://github.com/monero-project/monero/pull/9901. Older version of Monero will
        ignore this field and return as many blocks as it wants in response to our request. Newer
        versions of Monero won't waste our mutual bandwidth however.
      */
      request.push(u8::try_from("max_block_count".len()).unwrap());
      request.extend("max_block_count".as_bytes());
      request.push(epee::Type::Uint64 as u8);
      request.extend(remaining_blocks.to_le_bytes());

      debug_assert_eq!(expected_request_len, request.len());

      let res = self.bin_call("get_blocks.bin", request.clone(), MAX_RPC_RESPONSE_SIZE).await?;

      let blocks_received = {
        let mut blocks_received = 0;
        for item in epee::extract_blocks_from_blocks_bin(&res)? {
          item?;
          blocks_received += 1;
        }
        blocks_received
      };
      if blocks_received == 0 {
        Err(InterfaceError::InvalidInterface(
          "received zero blocks when requesting multiple".to_string(),
        ))?;
      }

      blocks.push(res);

      remaining_blocks = remaining_blocks.saturating_sub(blocks_received);
      start = (end - remaining_blocks) + 1;
    }

    Ok((requested_blocks, blocks))
  }
}

fn chained_iters<'a, I: Iterator, F: Fn(&'a [u8]) -> Result<I, InterfaceError>>(
  values: &'a [Vec<u8>],
  f: F,
) -> Result<impl use<'a, I, F> + Iterator<Item = I::Item>, InterfaceError> {
  Ok(values.iter().map(|value| f(value)).collect::<Result<Vec<_>, _>>()?.into_iter().flatten())
}

impl<T: HttpTransport> ProvidesUnvalidatedBlockchain for MoneroDaemon<T> {
  // TODO: Don't use `get_blocks.bin` here, which also yields transactions, yet a batch request for
  // the blocks alone.
  fn contiguous_blocks(
    &self,
    mut range: RangeInclusive<usize>,
  ) -> impl Send + Future<Output = Result<Vec<Block>, InterfaceError>> {
    async move {
      let mut res = vec![];
      // Handle the exceptional case where we're also requesting the genesis block, which
      // `fetch_contiguous_blocks` cannot handle
      if *range.start() == 0 {
        res.push(
          ProvidesUnvalidatedBlockchain::block(
            self,
            ProvidesUnvalidatedBlockchain::block_hash(self, 0).await?,
          )
          .await?,
        );
        range = 1 ..= *range.end();
      }
      let (requested_blocks, blocks_bin) = self.fetch_contiguous_blocks(range).await?;
      res.reserve(requested_blocks);

      for block in
        chained_iters(&blocks_bin, epee::extract_blocks_from_blocks_bin)?.take(requested_blocks)
      {
        res.push(block?);
      }

      Ok(res)
    }
  }

  fn block(&self, hash: [u8; 32]) -> impl Send + Future<Output = Result<Block, InterfaceError>> {
    async move {
      #[derive(Deserialize)]
      struct BlockResponse {
        blob: String,
      }

      let res: BlockResponse = self
        .json_rpc_call_core(
          "get_block",
          Some(format!(r#"{{ "hash": "{}" }}"#, hex::encode(hash))),
          MAX_RPC_RESPONSE_SIZE,
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
      #[derive(Deserialize)]
      struct BlockHeaderResponse {
        hash: String,
      }
      #[derive(Deserialize)]
      struct BlockHeaderByHeightResponse {
        block_header: BlockHeaderResponse,
      }

      let header: BlockHeaderByHeightResponse = self
        .json_rpc_call_core(
          "get_block_header_by_height",
          Some(format!(r#"{{ "height": {number} }}"#)),
          BASE_RESPONSE_SIZE,
        )
        .await?;
      hash_hex(&header.block_header.hash)
    }
  }
}

// TODO: `get_blocks.bin` returns the output index information we want. We don't need to make any
// more requests
async fn update_output_index<P: PotentiallyPruned, T: HttpTransport>(
  daemon: &MoneroDaemon<T>,
  next_ringct_output_index: &mut Option<u64>,
  output_index_for_first_ringct_output: &mut Option<u64>,
  tx_hash: [u8; 32],
  tx: &Transaction<P>,
) -> Result<(), InterfaceError> {
  if matches!(tx, Transaction::V2 { .. }) {
    // If we don't currently have the initial output index, fetch it via this transaction
    if next_ringct_output_index.is_none() && (!tx.prefix().outputs.is_empty()) {
      let indexes = <MoneroDaemon<T> as ProvidesOutputs>::output_indexes(daemon, tx_hash).await?;
      if tx.prefix().outputs.len() != indexes.len() {
        Err(InterfaceError::InvalidInterface(format!(
          "TX had {} outputs yet `get_o_indexes` returned {}",
          tx.prefix().outputs.len(),
          indexes.len()
        )))?;
      }
      *next_ringct_output_index = Some(indexes[0]);
    }

    // Populate the block's first RingCT output's index, if it wasn't already
    *output_index_for_first_ringct_output =
      output_index_for_first_ringct_output.or(*next_ringct_output_index);

    // Advance the next output index past this transaction
    if let Some(next_ringct_output_index) = next_ringct_output_index {
      *next_ringct_output_index = next_ringct_output_index
        .checked_add(
          u64::try_from(tx.prefix().outputs.len())
            .expect("amount of transaction outputs exceeded 2**64?"),
        )
        .ok_or_else(|| {
          InterfaceError::InvalidInterface("output index exceeded `u64::MAX`".to_string())
        })?;
    }
  }

  Ok(())
}

impl<T: HttpTransport> ProvidesUnvalidatedScannableBlocks for MoneroDaemon<T> {
  fn contiguous_scannable_blocks(
    &self,
    mut range: RangeInclusive<usize>,
  ) -> impl Send + Future<Output = Result<Vec<UnvalidatedScannableBlock>, InterfaceError>> {
    async move {
      let mut res = vec![];
      // Handle the exceptional case where we're also requesting the genesis block, which
      // `fetch_contiguous_blocks` cannot handle
      if *range.start() == 0 {
        res.push(
          ProvidesUnvalidatedScannableBlocks::scannable_block(
            self,
            ProvidesUnvalidatedBlockchain::block_hash(self, 0).await?,
          )
          .await?,
        );
        range = 1 ..= *range.end();
      }
      let (requested_blocks, blocks_bin) = self.fetch_contiguous_blocks(range).await?;
      res.reserve(requested_blocks);

      let blocks = chained_iters(&blocks_bin, epee::extract_blocks_from_blocks_bin)?;
      let mut txs = chained_iters(&blocks_bin, epee::extract_txs_from_blocks_bin)?;

      let mut next_ringct_output_index = None;
      for block in blocks.take(requested_blocks) {
        let block = block?;

        let mut block_txs = vec![];

        let mut output_index_for_first_ringct_output = None;

        update_output_index(
          self,
          &mut next_ringct_output_index,
          &mut output_index_for_first_ringct_output,
          block.miner_transaction().hash(),
          block.miner_transaction(),
        )
        .await?;

        for hash in &block.transactions {
          let tx = txs.next().ok_or_else(|| {
            InterfaceError::InvalidInterface(
              "`get_blocks.bin` contained less transactions than specified in its blocks"
                .to_string(),
            )
          })?;

          update_output_index(
            self,
            &mut next_ringct_output_index,
            &mut output_index_for_first_ringct_output,
            *hash,
            tx.as_ref(),
          )
          .await?;

          block_txs.push(tx);
        }

        res.push(UnvalidatedScannableBlock {
          block,
          transactions: block_txs,
          output_index_for_first_ringct_output,
        });
      }

      Ok(res)
    }
  }

  fn scannable_block(
    &self,
    hash: [u8; 32],
  ) -> impl Send + Future<Output = Result<UnvalidatedScannableBlock, InterfaceError>> {
    async move {
      let block = <Self as ProvidesBlockchain>::block(self, hash).await?;
      let transactions =
        <Self as ProvidesUnvalidatedTransactions>::pruned_transactions(self, &block.transactions)
          .await
          .map_err(|e| match e {
            TransactionsError::InterfaceError(e) => e,
            TransactionsError::TransactionNotFound => InterfaceError::InvalidInterface(
              "daemon sent us a block it doesn't have the transactions for".to_string(),
            ),
            TransactionsError::PrunedTransaction => InterfaceError::InternalError(
              "complaining about receiving a pruned transaction when".to_string() +
                " requesting a pruned transaction",
            ),
          })?;
      let mut next_ringct_output_index = None;
      let mut output_index_for_first_ringct_output = None;
      update_output_index(
        self,
        &mut next_ringct_output_index,
        &mut output_index_for_first_ringct_output,
        block.miner_transaction().hash(),
        block.miner_transaction(),
      )
      .await?;
      for (hash, transaction) in block.transactions.iter().zip(&transactions) {
        update_output_index(
          self,
          &mut next_ringct_output_index,
          &mut output_index_for_first_ringct_output,
          *hash,
          transaction.as_ref(),
        )
        .await?;
      }
      Ok(UnvalidatedScannableBlock { block, transactions, output_index_for_first_ringct_output })
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
        epee::HEADER.as_slice(),
        &[epee::VERSION],
        &[1 << 2],
        &[u8::try_from("txid".len()).unwrap()],
        "txid".as_bytes(),
        &[epee::Type::String as u8],
        &[32 << 2],
        &hash,
      ]
      .concat();

      const OUTPUTS_AMOUNT_BOUND: usize = TRANSACTION_SIZE_BOUND.div_ceil(Output::SIZE_LOWER_BOUND);
      let epee = self
        .bin_call(
          "get_o_indexes.bin",
          request,
          BASE_RESPONSE_SIZE.saturating_add(OUTPUTS_AMOUNT_BOUND * 8),
        )
        .await?;

      epee::extract_output_indexes(&epee)
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

      let expected_request_header_len = 19;
      let expected_request_len =
        expected_request_header_len + 8 + (indexes.len().min(MAX_OUTS) * 25);
      let mut request = Vec::with_capacity(expected_request_len);
      request.extend(epee::HEADER);
      request.push(epee::VERSION);
      request.push(1 << 2);
      request.push(u8::try_from("outputs".len()).unwrap());
      request.extend("outputs".as_bytes());
      request.push((epee::Type::Object as u8) | (epee::Array::Array as u8));
      debug_assert_eq!(request.len(), expected_request_header_len);

      let mut res = Vec::with_capacity(indexes.len());
      let mut first_iter = true;
      for indexes in indexes.chunks(MAX_OUTS) {
        // Form the request
        {
          request.truncate(expected_request_header_len);

          let indexes_len_u64 =
            u64::try_from(indexes.len()).expect("requesting more than 2**64 indexes?");
          // TODO: This can truncate if the responses if an absurd amount is requested
          // https://github.com/monero-oxide/monero-oxide/issues/93
          request.extend(((indexes_len_u64 << 2) | 0b11).to_le_bytes());

          for index in indexes {
            request.push(2 << 2);

            request.push(u8::try_from("amount".len()).unwrap());
            request.extend("amount".as_bytes());
            request.push(epee::Type::Uint8 as u8);
            request.push(0);

            request.push(u8::try_from("index".len()).unwrap());
            request.extend("index".as_bytes());
            request.push(epee::Type::Uint64 as u8);
            request.extend(&index.to_le_bytes());
          }

          // Only checked on the first iteration as the final chunk may be shorter
          if first_iter {
            debug_assert_eq!(expected_request_len, request.len());
            first_iter = false;
          }
        }

        // This is the size of the data, doubled to account for epee's structure
        const BOUND_PER_OUT: usize = 2 * (8 + 8 + 32 + 32 + 32 + 1);

        let outs = self
          .bin_call(
            "get_outs.bin",
            request.clone(),
            BASE_RESPONSE_SIZE.saturating_add(indexes.len().saturating_mul(BOUND_PER_OUT)),
          )
          .await?;

        epee::accumulate_outs(&outs, indexes.len(), &mut res)?;
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
        epee::HEADER.as_slice(),
        &[epee::VERSION],
        &[5 << 2],
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
        &[0], // TODO: Use compression
        &[u8::try_from("amounts".len()).unwrap()],
        "amounts".as_bytes(),
        &[(epee::Type::Uint8 as u8) | (epee::Array::Array as u8)],
        &[1 << 2],
        &[0],
      ]
      .concat();

      let distributions = self
        .bin_call(
          "get_output_distribution.bin",
          request,
          BASE_RESPONSE_SIZE
            .saturating_add(to.saturating_sub(from).saturating_add(2).saturating_mul(8)),
        )
        .await?;

      let start_height = epee::extract_start_height(&distributions)?;

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

      let mut distribution = epee::extract_distribution(&distributions, expected_len)?;

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
