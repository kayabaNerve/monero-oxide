use core::future::Future;
use alloc::vec::Vec;
use monero_oxide::transaction::{Pruned, Transaction};
use crate::RpcError;

/// A pruned transaction with the hash of its pruned data, if `version != 1`.
pub struct PrunedTransactionWithPrunableHash {
  transaction: Transaction<Pruned>,
  prunable_hash: Option<[u8; 32]>,
}

impl PrunedTransactionWithPrunableHash {
  /// Create a new `PrunedTransactionWithPrunableHash`.
  ///
  /// This expects `(version != 1) == (prunable_hash = Some(_))` and returns `None` otherwise.
  pub fn new(transaction: Transaction<Pruned>, prunable_hash: Option<[u8; 32]>) -> Option<Self> {
    let expects_prunable_hash = matches!(transaction, Transaction::V2 { .. });
    if expects_prunable_hash != prunable_hash.is_some() {
      None?;
    }
    Some(Self { transaction, prunable_hash })
  }

  /// Retrieve the contained transaction.
  pub fn retrieve(self) -> Transaction<Pruned> {
    self.transaction
  }

  /// Verify the transaction has the expected hash, if possible.
  ///
  /// This only works for transaction where `version != 1`. Transactions where `version = 1` will
  /// be returned without any verification.
  ///
  /// If verification fails, the actual hash of the transaction is returned as the error.
  pub fn verify_as_possible(self, hash: [u8; 32]) -> Result<Transaction<Pruned>, [u8; 32]> {
    if let Some(prunable_hash) = self.prunable_hash {
      let actual_hash = self.transaction.hash_with_prunable_hash(prunable_hash).unwrap();
      if actual_hash != hash {
        Err(actual_hash)?;
      }
    }
    Ok(self.transaction)
  }
}

/// Provides unvalidated transactions from an untrusted RPC.
///
/// This provides all four methods yet either `get_transactions` and `get_pruned_transactions` or
/// `get_transaction` and `get_pruned_transaction` MUST be overriden, ideally the former.
pub trait ProvidesUnvalidatedTransactions: Sync {
  /// Get the specified transactions.
  ///
  /// This returns all of the requested deserialized transactions.
  fn get_transactions(
    &self,
    hashes: &[[u8; 32]],
  ) -> impl Send + Future<Output = Result<Vec<Transaction>, RpcError>> {
    async move {
      if hashes.is_empty() {
        return Ok(vec![]);
      }

      let mut txs = Vec::with_capacity(hashes.len());
      for hash in hashes {
        txs.push(self.get_transaction(*hash).await?);
      }
      Ok(txs)
    }
  }

  /// Get the specified transactions in their pruned format.
  fn get_pruned_transactions(
    &self,
    hashes: &[[u8; 32]],
  ) -> impl Send + Future<Output = Result<Vec<PrunedTransactionWithPrunableHash>, RpcError>> {
    async move {
      if hashes.is_empty() {
        return Ok(vec![]);
      }

      let mut txs = Vec::with_capacity(hashes.len());
      for hash in hashes {
        txs.push(self.get_pruned_transaction(*hash).await?);
      }
      Ok(txs)
    }
  }

  /// Get the specified transaction.
  fn get_transaction(
    &self,
    hash: [u8; 32],
  ) -> impl Send + Future<Output = Result<Transaction, RpcError>> {
    async move { self.get_transactions(&[hash]).await.map(|mut txs| txs.swap_remove(0)) }
  }

  /// Get the specified transaction in its pruned format.
  fn get_pruned_transaction(
    &self,
    hash: [u8; 32],
  ) -> impl Send + Future<Output = Result<PrunedTransactionWithPrunableHash, RpcError>> {
    async move { self.get_pruned_transactions(&[hash]).await.map(|mut txs| txs.swap_remove(0)) }
  }
}

/// Provides transactions which have been sanity-checked.
pub trait ProvidesTransactions: Sync {
  /// Get the specified transactions.
  ///
  /// This returns all of the requested deserialized transactions, ensuring they're the requested
  /// transactions.
  fn get_transactions(
    &self,
    hashes: &[[u8; 32]],
  ) -> impl Send + Future<Output = Result<Vec<Transaction>, RpcError>>;

  /// Get the specified transactions in their pruned format.
  ///
  /// This returns all of the requested deserialized transactions, ensuring they're the requested
  /// transactions if `version != 1`.
  fn get_pruned_transactions(
    &self,
    hashes: &[[u8; 32]],
  ) -> impl Send + Future<Output = Result<Vec<Transaction<Pruned>>, RpcError>>;

  /// Get the specified transaction.
  ///
  /// This returns the requested transaction, ensuring it is the requested transaction.
  fn get_transaction(
    &self,
    hash: [u8; 32],
  ) -> impl Send + Future<Output = Result<Transaction, RpcError>>;

  /// Get the specified transaction in its pruned format.
  ///
  /// This returns the requested transaction, ensuring it is the requested transaction if
  /// `version != 1`.
  fn get_pruned_transaction(
    &self,
    hash: [u8; 32],
  ) -> impl Send + Future<Output = Result<Transaction<Pruned>, RpcError>>;
}

impl<P: ProvidesUnvalidatedTransactions> ProvidesTransactions for P {
  fn get_transactions(
    &self,
    hashes: &[[u8; 32]],
  ) -> impl Send + Future<Output = Result<Vec<Transaction>, RpcError>> {
    async move {
      let txs = <P as ProvidesUnvalidatedTransactions>::get_transactions(self, hashes).await?;
      if txs.len() != hashes.len() {
        Err(RpcError::InternalError(format!(
        "`ProvidesUnvalidatedTransactions::get_transactions` returned {} transactions, expected {}",
        txs.len(),
        hashes.len(),
      )))?;
      }

      for (tx, expected_hash) in txs.iter().zip(hashes) {
        let hash = tx.hash();
        if &hash != expected_hash {
          Err(RpcError::InvalidNode(format!(
            "RPC returned TX {} when {} was requested",
            hex::encode(hash),
            hex::encode(expected_hash)
          )))?;
        }
      }
      Ok(txs)
    }
  }

  fn get_pruned_transactions(
    &self,
    hashes: &[[u8; 32]],
  ) -> impl Send + Future<Output = Result<Vec<Transaction<Pruned>>, RpcError>> {
    async move {
      let unvalidated =
        <P as ProvidesUnvalidatedTransactions>::get_pruned_transactions(self, hashes).await?;
      if unvalidated.len() != hashes.len() {
        Err(RpcError::InternalError(format!(
          "`{}` returned {} transactions, expected {}",
          "ProvidesUnvalidatedTransactions::get_pruned_transactions",
          unvalidated.len(),
          hashes.len(),
        )))?;
      }

      let mut txs = Vec::with_capacity(unvalidated.len());
      for (tx, expected_hash) in unvalidated.into_iter().zip(hashes) {
        match tx.verify_as_possible(*expected_hash) {
          Ok(tx) => txs.push(tx),
          Err(hash) => Err(RpcError::InvalidNode(format!(
            "RPC returned TX {} when {} was requested",
            hex::encode(hash),
            hex::encode(expected_hash)
          )))?,
        }
      }
      Ok(txs)
    }
  }

  fn get_transaction(
    &self,
    hash: [u8; 32],
  ) -> impl Send + Future<Output = Result<Transaction, RpcError>> {
    async move {
      let tx = <P as ProvidesUnvalidatedTransactions>::get_transaction(self, hash).await?;
      let actual_hash = tx.hash();
      if actual_hash != hash {
        Err(RpcError::InvalidNode(format!(
          "RPC returned TX {} when {} was requested",
          hex::encode(actual_hash),
          hex::encode(hash)
        )))?;
      }
      Ok(tx)
    }
  }

  fn get_pruned_transaction(
    &self,
    hash: [u8; 32],
  ) -> impl Send + Future<Output = Result<Transaction<Pruned>, RpcError>> {
    async move {
      let unvalidated =
        <P as ProvidesUnvalidatedTransactions>::get_pruned_transaction(self, hash).await?;

      match unvalidated.verify_as_possible(hash) {
        Ok(tx) => Ok(tx),
        Err(actual_hash) => Err(RpcError::InvalidNode(format!(
          "RPC returned TX {} when {} was requested",
          hex::encode(actual_hash),
          hex::encode(hash)
        )))?,
      }
    }
  }
}
