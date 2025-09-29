use core::{ops::RangeInclusive, future::Future};

use alloc::{
  format, vec,
  vec::Vec,
  string::{String, ToString},
};

use serde::Deserialize;

use monero_oxide::block::{BlockHeader, Block};

use monero_interface::*;

use crate::{
  MAX_RPC_RESPONSE_SIZE, BASE_RESPONSE_SIZE, BYTE_FACTOR_IN_JSON_RESPONSE_SIZE, HttpTransport,
  MoneroDaemon, JsonRpcResponse, rpc_hex, hash_hex,
};

#[derive(Deserialize)]
struct BlockResponse {
  blob: String,
}

/// The JSON-encoded request for a block.
///
/// The request's ID will equal the number of the block requested.
fn block_request(number: usize) -> String {
  format!(
    r#"{{
      "jsonrpc": "2.0",
      "method": "get_block",
      "params": {{ "height": {number} }},
      "id": {number}
    }}"#
  )
}

impl<T: HttpTransport> ProvidesUnvalidatedBlockchain for MoneroDaemon<T> {
  /*
    When fetching blocks, we don't use `get_blocks.bin` (nor `get_blocks_by_height.bin`) as they
    will always include the transactions, when we have no need for them here. With
    `get_blocks.bin`, we give Monero the start block and receive as many blocks fit in the
    response. Here however, we specify all the blocks we want and expect to receive all of the
    requested blocks, which means we have to be careful our requested response does not exceed the
    size limit.

    To solve this, we will dynamically adjust the amount of blocks requested based on the sizes of
    received responses, and on error, retry while requesting just a single block.

    Note these are solely blocks, without any transactions, so they should only be a few KB each
    and far from the response's size limit.
  */
  fn contiguous_blocks(
    &self,
    mut range: RangeInclusive<usize>,
  ) -> impl Send + Future<Output = Result<Vec<Block>, InterfaceError>> {
    const GENEROUS_TRANSACTIONS_PER_BLOCK_ESTIMATE: usize = 1000;
    const BLOCK_SIZE_ESTIMATE: usize =
      BlockHeader::SIZE_UPPER_BOUND + 10 + (GENEROUS_TRANSACTIONS_PER_BLOCK_ESTIMATE * 32);
    const BLOCK_JSON_SIZE_ESTIMATE: usize = BYTE_FACTOR_IN_JSON_RESPONSE_SIZE * BLOCK_SIZE_ESTIMATE;
    const BLOCKS_PER_RESPONSE_ESTIMATE: usize =
      (MAX_RPC_RESPONSE_SIZE - BASE_RESPONSE_SIZE) / BLOCK_JSON_SIZE_ESTIMATE;

    async move {
      let mut res =
        Vec::with_capacity(range.end().saturating_sub(*range.start()).saturating_add(1));

      // Optimistically use our estimate for the initial request, before we gain context on the
      // actual sizes
      let mut blocks_per_request = BLOCKS_PER_RESPONSE_ESTIMATE;
      while *range.start() <= *range.end() {
        // If the server doesn't support batched JSON-RPC requests, don't request multiple blocks
        // within a single request
        if !self.supports_json_rpc_batch_requests {
          blocks_per_request = 1;
        }

        // Prepare a new request
        let start = *range.start();
        let end =
          start.checked_add(blocks_per_request - 1).unwrap_or(*range.end()).min(*range.end());
        let request_len = end - start + 1;

        let single_block = start == end;
        let request = if single_block {
          block_request(start)
        } else {
          let mut request = String::with_capacity(request_len * 30);
          request.push('[');
          for number in start ..= end {
            request.push_str(&block_request(number));
            request.push(',');
          }
          request.pop(); // Pop the trailing comma
          request.push(']');
          request
        };

        let json_blocks =
          match self.rpc_call_core("json_rpc", Some(request), MAX_RPC_RESPONSE_SIZE).await {
            Ok(json_blocks) => json_blocks,
            Err(e) => {
              // If we only requested a single block, propagate the error
              if single_block {
                Err(e)?;
              }
              // If we requested multiple blocks, retry while only requesting a single block
              blocks_per_request = 1;
              continue;
            }
          };
        let response_byte_length = json_blocks.len();

        let mut json_blocks: Vec<JsonRpcResponse<BlockResponse>> = (if single_block {
          serde_json::from_str(&json_blocks).map(|block| vec![block])
        } else {
          serde_json::from_str(&json_blocks)
        })
        .map_err(|_| {
          InterfaceError::InvalidInterface(
            "`get_block` response wasn't the expected JSON".to_string(),
          )
        })?;

        if json_blocks.len() != request_len {
          Err(InterfaceError::InvalidInterface(format!(
            "requested {request_len} blocks but received {}",
            json_blocks.len()
          )))?;
        }
        json_blocks.sort_by_key(|result| result.id);
        for (number, json) in (start ..= end).zip(&json_blocks) {
          if json.id != Some(number) {
            Err(InterfaceError::InvalidInterface(format!(
              "request with ID {number} received response in complimentary position with ID {:?}",
              json.id
            )))?;
          }

          let block = Block::read(&mut rpc_hex(&json.result.blob)?.as_slice())
            .map_err(|_| InterfaceError::InvalidInterface("invalid block".to_string()))?;
          res.push(block);
        }

        // Update the range
        range = (match range.start().checked_add(request_len) {
          Some(new_start) => new_start,
          // We've completed the request as an unrepresentable number is greater than the
          // representable end
          None => return Ok(res),
        }) ..= *range.end();

        // Update the amount to request
        const TARGET_RESPONSE_SIZE: usize = ((MAX_RPC_RESPONSE_SIZE - BASE_RESPONSE_SIZE) * 4) / 5;
        // If this is less than the targetted response size, increase the next request's length
        // by up to 50%
        if response_byte_length < TARGET_RESPONSE_SIZE {
          let fifty_percent_more = blocks_per_request + (blocks_per_request / 2);
          let proportional =
            TARGET_RESPONSE_SIZE / response_byte_length.div_ceil(blocks_per_request);
          blocks_per_request = fifty_percent_more.min(proportional);
        }
        // If this is more than the targetted amount of the response size limit, halve the current
        // request limit
        if response_byte_length > TARGET_RESPONSE_SIZE {
          blocks_per_request = (blocks_per_request / 2).max(1);
        }
      }

      Ok(res)
    }
  }

  fn block(&self, hash: [u8; 32]) -> impl Send + Future<Output = Result<Block, InterfaceError>> {
    async move {
      let res: BlockResponse = self
        .json_rpc_call_internal(
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
        .json_rpc_call_internal(
          "get_block_header_by_height",
          Some(format!(r#"{{ "height": {number} }}"#)),
          BASE_RESPONSE_SIZE,
        )
        .await?;
      hash_hex(&header.block_header.hash)
    }
  }
}
