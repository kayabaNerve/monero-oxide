use core::{ops::RangeInclusive, future::Future};

use alloc::{format, vec, vec::Vec, string::ToString};

use monero_oxide::transaction::{PotentiallyPruned, Transaction};

use monero_interface::*;

use crate::{MAX_RPC_RESPONSE_SIZE, HttpTransport, MoneroDaemon};

use super::epee;

impl<T: HttpTransport> MoneroDaemon<T> {
  // This MUST NOT be called with a start of `0`.
  pub(super) async fn fetch_contiguous_blocks(
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

pub(super) fn chained_iters<'a, I: Iterator, F: Fn(&'a [u8]) -> Result<I, InterfaceError>>(
  values: &'a [Vec<u8>],
  f: F,
) -> Result<impl use<'a, I, F> + Iterator<Item = I::Item>, InterfaceError> {
  Ok(values.iter().map(|value| f(value)).collect::<Result<Vec<_>, _>>()?.into_iter().flatten())
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
        res.push(ProvidesUnvalidatedScannableBlocks::scannable_block_by_number(self, 0).await?);
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

  fn scannable_block_by_number(
    &self,
    number: usize,
  ) -> impl Send + Future<Output = Result<UnvalidatedScannableBlock, InterfaceError>> {
    async move {
      ProvidesUnvalidatedScannableBlocks::scannable_block(
        self,
        ProvidesUnvalidatedBlockchain::block_hash(self, number).await?,
      )
      .await
    }
  }
}
