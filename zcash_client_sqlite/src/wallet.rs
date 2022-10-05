//! Functions for querying information in the wdb database.
//!
//! These functions should generally not be used directly; instead,
//! their functionality is available via the [`WalletRead`] and
//! [`WalletWrite`] traits.
//!
//! [`WalletRead`]: zcash_client_backend::data_api::WalletRead
//! [`WalletWrite`]: zcash_client_backend::data_api::WalletWrite

use group::ff::PrimeField;
use rusqlite::{named_params, OptionalExtension, ToSql};
use std::collections::HashMap;
use std::convert::TryFrom;

#[cfg(feature = "transparent-inputs")]
use std::collections::HashSet;

use zcash_primitives::{
    block::BlockHash,
    consensus::{self, BlockHeight, BranchId, NetworkUpgrade, Parameters},
    memo::{Memo, MemoBytes},
    merkle_tree::{CommitmentTree, IncrementalWitness},
    sapling::{Node, Note, Nullifier, PaymentAddress},
    transaction::{components::Amount, Transaction, TxId},
    zip32::{
        sapling::{DiversifiableFullViewingKey, ExtendedFullViewingKey},
        AccountId, DiversifierIndex,
    },
};

use zcash_client_backend::{
    address::{RecipientAddress, UnifiedAddress},
    data_api::error::Error,
    encoding::{encode_payment_address_p, encode_transparent_address_p},
    keys::UnifiedFullViewingKey,
    wallet::{WalletShieldedOutput, WalletTx},
    DecryptedOutput,
};

use crate::{error::SqliteClientError, DataConnStmtCache, NoteId, WalletDb, PRUNING_HEIGHT};

use zcash_primitives::legacy::TransparentAddress;

#[cfg(feature = "transparent-inputs")]
use {
    crate::UtxoId,
    rusqlite::params,
    zcash_client_backend::{encoding::AddressCodec, wallet::WalletTransparentOutput},
    zcash_primitives::{
        legacy::{keys::IncomingViewingKey, Script},
        transaction::components::{OutPoint, TxOut},
    },
};

pub mod init;
pub mod transact;

pub(crate) enum PoolType {
    Transparent,
    Sapling,
}

impl PoolType {
    pub(crate) fn typecode(&self) -> i64 {
        // These constants are *incidentally* shared with the typecodes
        // for unified addresses, but this is exclusively an internal
        // implementation detail.
        match self {
            PoolType::Transparent => 0i64,
            PoolType::Sapling => 2i64,
        }
    }
}

/// This trait provides a generalization over shielded output representations.
#[deprecated(note = "This trait will be removed in a future release.")]
pub trait ShieldedOutput {
    fn index(&self) -> usize;
    fn account(&self) -> AccountId;
    fn to(&self) -> &PaymentAddress;
    fn note(&self) -> &Note;
    fn memo(&self) -> Option<&MemoBytes>;
    fn is_change(&self) -> Option<bool>;
    fn nullifier(&self) -> Option<Nullifier>;
}

#[allow(deprecated)]
impl ShieldedOutput for WalletShieldedOutput<Nullifier> {
    fn index(&self) -> usize {
        self.index
    }
    fn account(&self) -> AccountId {
        self.account
    }
    fn to(&self) -> &PaymentAddress {
        &self.to
    }
    fn note(&self) -> &Note {
        &self.note
    }
    fn memo(&self) -> Option<&MemoBytes> {
        None
    }
    fn is_change(&self) -> Option<bool> {
        Some(self.is_change)
    }

    fn nullifier(&self) -> Option<Nullifier> {
        Some(self.nf)
    }
}

#[allow(deprecated)]
impl ShieldedOutput for DecryptedOutput {
    fn index(&self) -> usize {
        self.index
    }
    fn account(&self) -> AccountId {
        self.account
    }
    fn to(&self) -> &PaymentAddress {
        &self.to
    }
    fn note(&self) -> &Note {
        &self.note
    }
    fn memo(&self) -> Option<&MemoBytes> {
        Some(&self.memo)
    }
    fn is_change(&self) -> Option<bool> {
        None
    }
    fn nullifier(&self) -> Option<Nullifier> {
        None
    }
}

/// Returns the address for the account.
///
/// # Examples
///
/// ```
/// use tempfile::NamedTempFile;
/// use zcash_primitives::{
///     consensus::{self, Network},
///     zip32::AccountId,
/// };
/// use zcash_client_sqlite::{
///     WalletDb,
///     wallet::get_address,
/// };
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db = WalletDb::for_path(data_file, Network::TestNetwork).unwrap();
/// let addr = get_address(&db, AccountId::from(0));
/// ```
#[deprecated(
    note = "This function will be removed in a future release. Use zcash_client_backend::data_api::WalletRead::get_address instead."
)]
pub fn get_address<P: consensus::Parameters>(
    wdb: &WalletDb<P>,
    account: AccountId,
) -> Result<Option<PaymentAddress>, SqliteClientError> {
    // This returns the most recently generated address.
    let addr: String = wdb.conn.query_row(
        "SELECT address
        FROM addresses WHERE account = ?
        ORDER BY diversifier_index_be DESC
        LIMIT 1",
        [u32::from(account)],
        |row| row.get(0),
    )?;

    RecipientAddress::decode(&wdb.params, &addr)
        .ok_or_else(|| {
            SqliteClientError::CorruptedData("Not a valid Zcash recipient address".to_owned())
        })
        .map(|addr| match addr {
            // TODO: Return the UA, not its Sapling component.
            RecipientAddress::Unified(ua) => ua.sapling().cloned(),
            _ => None,
        })
}

pub(crate) fn get_max_account_id<P>(
    wdb: &WalletDb<P>,
) -> Result<Option<AccountId>, SqliteClientError> {
    // This returns the most recently generated address.
    wdb.conn
        .query_row("SELECT MAX(account) FROM accounts", [], |row| {
            let account_id: Option<u32> = row.get(0)?;
            Ok(account_id.map(AccountId::from))
        })
        .map_err(SqliteClientError::from)
}

pub(crate) fn add_account<P: consensus::Parameters>(
    wdb: &WalletDb<P>,
    account: AccountId,
    key: &UnifiedFullViewingKey,
) -> Result<(), SqliteClientError> {
    add_account_internal(&wdb.conn, &wdb.params, "accounts", account, key)
}

pub(crate) fn add_account_internal<P: consensus::Parameters, E: From<rusqlite::Error>>(
    conn: &rusqlite::Connection,
    network: &P,
    accounts_table: &'static str,
    account: AccountId,
    key: &UnifiedFullViewingKey,
) -> Result<(), E> {
    let ufvk_str: String = key.encode(network);
    conn.execute(
        &format!(
            "INSERT INTO {} (account, ufvk) VALUES (:account, :ufvk)",
            accounts_table
        ),
        named_params![":account": &<u32>::from(account), ":ufvk": &ufvk_str],
    )?;

    // Always derive the default Unified Address for the account.
    let (address, mut idx) = key.default_address();
    let address_str: String = address.encode(network);
    // the diversifier index is stored in big-endian order to allow sorting
    idx.0.reverse();
    conn.execute(
        "INSERT INTO addresses (account, diversifier_index_be, address)
        VALUES (:account, :diversifier_index_be, :address)",
        named_params![
            ":account": &<u32>::from(account),
            ":diversifier_index_be": &&idx.0[..],
            ":address": &address_str,
        ],
    )?;

    Ok(())
}

pub(crate) fn get_current_address<P: consensus::Parameters>(
    wdb: &WalletDb<P>,
    account: AccountId,
) -> Result<Option<(UnifiedAddress, DiversifierIndex)>, SqliteClientError> {
    // This returns the most recently generated address.
    let addr: Option<(String, Vec<u8>)> = wdb
        .conn
        .query_row(
            "SELECT address, diversifier_index_be
            FROM addresses WHERE account = :account
            ORDER BY diversifier_index_be DESC
            LIMIT 1",
            named_params![":account": &u32::from(account)],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;

    addr.map(|(addr_str, di_vec)| {
        let mut di_be: [u8; 11] = di_vec.try_into().map_err(|_| {
            SqliteClientError::CorruptedData(
                "Diverisifier index is not an 11-byte value".to_owned(),
            )
        })?;
        di_be.reverse();

        RecipientAddress::decode(&wdb.params, &addr_str)
            .ok_or_else(|| {
                SqliteClientError::CorruptedData("Not a valid Zcash recipient address".to_owned())
            })
            .and_then(|addr| match addr {
                RecipientAddress::Unified(ua) => Ok(ua),
                _ => Err(SqliteClientError::CorruptedData(format!(
                    "Addresses table contains {} which is not a unified address",
                    addr_str,
                ))),
            })
            .map(|addr| (addr, DiversifierIndex(di_be)))
    })
    .transpose()
}

#[cfg(feature = "transparent-inputs")]
pub(crate) fn get_transparent_receivers<P: consensus::Parameters>(
    wdb: &WalletDb<P>,
    account: AccountId,
) -> Result<HashSet<TransparentAddress>, SqliteClientError> {
    let mut ret = HashSet::new();

    // Get all UAs derived
    let mut ua_query = wdb
        .conn
        .prepare("SELECT address FROM addresses WHERE account = :account")?;
    let mut rows = ua_query.query(named_params![":account": &u32::from(account)])?;

    while let Some(row) = rows.next()? {
        let ua_str: String = row.get(0)?;
        let ua = RecipientAddress::decode(&wdb.params, &ua_str)
            .ok_or_else(|| {
                SqliteClientError::CorruptedData("Not a valid Zcash recipient address".to_owned())
            })
            .and_then(|addr| match addr {
                RecipientAddress::Unified(ua) => Ok(ua),
                _ => Err(SqliteClientError::CorruptedData(format!(
                    "Addresses table contains {} which is not a unified address",
                    ua_str,
                ))),
            })?;
        if let Some(taddr) = ua.transparent() {
            ret.insert(*taddr);
        }
    }

    // Get the UFVK for the account.
    let ufvk_str: String = wdb.conn.query_row(
        "SELECT ufvk FROM accounts WHERE account = :account",
        [u32::from(account)],
        |row| row.get(0),
    )?;
    let ufvk = UnifiedFullViewingKey::decode(&wdb.params, &ufvk_str)
        .map_err(SqliteClientError::CorruptedData)?;

    // Derive the default transparent address (if it wasn't already part of a derived UA).
    if let Some(tfvk) = ufvk.transparent() {
        let tivk = tfvk.derive_external_ivk()?;
        let taddr = tivk.default_address().0;
        ret.insert(taddr);
    }

    Ok(ret)
}

/// Returns the [`UnifiedFullViewingKey`]s for the wallet.
pub(crate) fn get_unified_full_viewing_keys<P: consensus::Parameters>(
    wdb: &WalletDb<P>,
) -> Result<HashMap<AccountId, UnifiedFullViewingKey>, SqliteClientError> {
    // Fetch the UnifiedFullViewingKeys we are tracking
    let mut stmt_fetch_accounts = wdb
        .conn
        .prepare("SELECT account, ufvk FROM accounts ORDER BY account ASC")?;

    let rows = stmt_fetch_accounts.query_map([], |row| {
        let acct: u32 = row.get(0)?;
        let account = AccountId::from(acct);
        let ufvk_str: String = row.get(1)?;
        let ufvk = UnifiedFullViewingKey::decode(&wdb.params, &ufvk_str)
            .map_err(SqliteClientError::CorruptedData);

        Ok((account, ufvk))
    })?;

    let mut res: HashMap<AccountId, UnifiedFullViewingKey> = HashMap::new();
    for row in rows {
        let (account_id, ufvkr) = row?;
        res.insert(account_id, ufvkr?);
    }

    Ok(res)
}

/// Checks whether the specified [`ExtendedFullViewingKey`] is valid and corresponds to the
/// specified account.
///
/// [`ExtendedFullViewingKey`]: zcash_primitives::zip32::ExtendedFullViewingKey
#[deprecated(
    note = "This function will be removed in a future release. Use zcash_client_backend::data_api::WalletRead::is_valid_account_extfvk instead."
)]
pub fn is_valid_account_extfvk<P: consensus::Parameters>(
    wdb: &WalletDb<P>,
    account: AccountId,
    extfvk: &ExtendedFullViewingKey,
) -> Result<bool, SqliteClientError> {
    wdb.conn
        .prepare("SELECT ufvk FROM accounts WHERE account = ?")?
        .query_row([u32::from(account).to_sql()?], |row| {
            row.get(0).map(|ufvk_str: String| {
                UnifiedFullViewingKey::decode(&wdb.params, &ufvk_str)
                    .map_err(SqliteClientError::CorruptedData)
            })
        })
        .optional()
        .map_err(SqliteClientError::from)
        .and_then(|row| {
            if let Some(ufvk) = row {
                ufvk.map(|ufvk| {
                    ufvk.sapling().map(|dfvk| dfvk.to_bytes())
                        == Some(DiversifiableFullViewingKey::from(extfvk.clone()).to_bytes())
                })
            } else {
                Ok(false)
            }
        })
}

/// Returns the balance for the account, including all mined unspent notes that we know
/// about.
///
/// WARNING: This balance is potentially unreliable, as mined notes may become unmined due
/// to chain reorgs. You should generally not show this balance to users without some
/// caveat. Use [`get_balance_at`] where you need a more reliable indication of the
/// wallet balance.
///
/// # Examples
///
/// ```
/// use tempfile::NamedTempFile;
/// use zcash_primitives::{
///     consensus::Network,
///     zip32::AccountId,
/// };
/// use zcash_client_sqlite::{
///     WalletDb,
///     wallet::get_balance,
/// };
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db = WalletDb::for_path(data_file, Network::TestNetwork).unwrap();
/// let addr = get_balance(&db, AccountId::from(0));
/// ```
#[deprecated(
    note = "This function will be removed in a future release. Use zcash_client_backend::data_api::WalletRead::get_balance_at instead."
)]
pub fn get_balance<P>(wdb: &WalletDb<P>, account: AccountId) -> Result<Amount, SqliteClientError> {
    let balance = wdb.conn.query_row(
        "SELECT SUM(value) FROM received_notes
        INNER JOIN transactions ON transactions.id_tx = received_notes.tx
        WHERE account = ? AND spent IS NULL AND transactions.block IS NOT NULL",
        [u32::from(account)],
        |row| row.get(0).or(Ok(0)),
    )?;

    match Amount::from_i64(balance) {
        Ok(amount) if !amount.is_negative() => Ok(amount),
        _ => Err(SqliteClientError::CorruptedData(
            "Sum of values in received_notes is out of range".to_string(),
        )),
    }
}

/// Returns the verified balance for the account at the specified height,
/// This may be used to obtain a balance that ignores notes that have been
/// received so recently that they are not yet deemed spendable.
///
/// # Examples
///
/// ```
/// use tempfile::NamedTempFile;
/// use zcash_primitives::{
///     consensus::{BlockHeight, Network},
///     zip32::AccountId,
/// };
/// use zcash_client_sqlite::{
///     WalletDb,
///     wallet::get_balance_at,
/// };
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db = WalletDb::for_path(data_file, Network::TestNetwork).unwrap();
/// let addr = get_balance_at(&db, AccountId::from(0), BlockHeight::from_u32(0));
/// ```
#[deprecated(
    note = "This function will be removed in a future release. Use zcash_client_backend::data_api::WalletRead::get_balance_at instead."
)]
pub fn get_balance_at<P>(
    wdb: &WalletDb<P>,
    account: AccountId,
    anchor_height: BlockHeight,
) -> Result<Amount, SqliteClientError> {
    let balance = wdb.conn.query_row(
        "SELECT SUM(value) FROM received_notes
        INNER JOIN transactions ON transactions.id_tx = received_notes.tx
        WHERE account = ? AND spent IS NULL AND transactions.block <= ?",
        [u32::from(account), u32::from(anchor_height)],
        |row| row.get(0).or(Ok(0)),
    )?;

    match Amount::from_i64(balance) {
        Ok(amount) if !amount.is_negative() => Ok(amount),
        _ => Err(SqliteClientError::CorruptedData(
            "Sum of values in received_notes is out of range".to_string(),
        )),
    }
}

/// Returns the memo for a received note.
///
/// The note is identified by its row index in the `received_notes` table within the wdb
/// database.
///
/// # Examples
///
/// ```
/// use tempfile::NamedTempFile;
/// use zcash_primitives::consensus::Network;
/// use zcash_client_sqlite::{
///     NoteId,
///     WalletDb,
///     wallet::get_received_memo,
/// };
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db = WalletDb::for_path(data_file, Network::TestNetwork).unwrap();
/// let memo = get_received_memo(&db, 27);
/// ```
#[deprecated(
    note = "This function will be removed in a future release. Use zcash_client_backend::data_api::WalletRead::get_memo instead."
)]
pub fn get_received_memo<P>(wdb: &WalletDb<P>, id_note: i64) -> Result<Memo, SqliteClientError> {
    let memo_bytes: Vec<_> = wdb.conn.query_row(
        "SELECT memo FROM received_notes
        WHERE id_note = ?",
        [id_note],
        |row| row.get(0),
    )?;

    MemoBytes::from_bytes(&memo_bytes)
        .and_then(Memo::try_from)
        .map_err(SqliteClientError::from)
}

/// Looks up a transaction by its internal database identifier.
pub(crate) fn get_transaction<P: Parameters>(
    wdb: &WalletDb<P>,
    id_tx: i64,
) -> Result<Transaction, SqliteClientError> {
    let (tx_bytes, block_height): (Vec<_>, BlockHeight) = wdb.conn.query_row(
        "SELECT raw, block FROM transactions
        WHERE id_tx = ?",
        [id_tx],
        |row| {
            let h: u32 = row.get(1)?;
            Ok((row.get(0)?, BlockHeight::from(h)))
        },
    )?;

    Transaction::read(
        &tx_bytes[..],
        BranchId::for_height(&wdb.params, block_height),
    )
    .map_err(SqliteClientError::from)
}

/// Returns the memo for a sent note.
///
/// The note is identified by its row index in the `sent_notes` table within the wdb
/// database.
///
/// # Examples
///
/// ```
/// use tempfile::NamedTempFile;
/// use zcash_primitives::consensus::Network;
/// use zcash_client_sqlite::{
///     NoteId,
///     WalletDb,
///     wallet::get_sent_memo,
/// };
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db = WalletDb::for_path(data_file, Network::TestNetwork).unwrap();
/// let memo = get_sent_memo(&db, 12);
/// ```
#[deprecated(
    note = "This function will be removed in a future release. Use zcash_client_backend::data_api::WalletRead::get_memo instead."
)]
pub fn get_sent_memo<P>(wdb: &WalletDb<P>, id_note: i64) -> Result<Memo, SqliteClientError> {
    let memo_bytes: Vec<_> = wdb.conn.query_row(
        "SELECT memo FROM sent_notes
        WHERE id_note = ?",
        [id_note],
        |row| row.get(0),
    )?;

    MemoBytes::from_bytes(&memo_bytes)
        .and_then(Memo::try_from)
        .map_err(SqliteClientError::from)
}

/// Returns the minimum and maximum heights for blocks stored in the wallet database.
///
/// # Examples
///
/// ```
/// use tempfile::NamedTempFile;
/// use zcash_primitives::consensus::Network;
/// use zcash_client_sqlite::{
///     WalletDb,
///     wallet::block_height_extrema,
/// };
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db = WalletDb::for_path(data_file, Network::TestNetwork).unwrap();
/// let bounds = block_height_extrema(&db);
/// ```
#[deprecated(
    note = "This function will be removed in a future release. Use zcash_client_backend::data_api::WalletRead::block_height_extrema instead."
)]
pub fn block_height_extrema<P>(
    wdb: &WalletDb<P>,
) -> Result<Option<(BlockHeight, BlockHeight)>, rusqlite::Error> {
    wdb.conn
        .query_row("SELECT MIN(height), MAX(height) FROM blocks", [], |row| {
            let min_height: u32 = row.get(0)?;
            let max_height: u32 = row.get(1)?;
            Ok(Some((
                BlockHeight::from(min_height),
                BlockHeight::from(max_height),
            )))
        })
        //.optional() doesn't work here because a failed aggregate function
        //produces a runtime error, not an empty set of rows.
        .or(Ok(None))
}

/// Returns the block height at which the specified transaction was mined,
/// if any.
///
/// # Examples
///
/// ```
/// use tempfile::NamedTempFile;
/// use zcash_primitives::consensus::Network;
/// use zcash_primitives::transaction::TxId;
/// use zcash_client_sqlite::{
///     WalletDb,
///     wallet::get_tx_height,
/// };
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db = WalletDb::for_path(data_file, Network::TestNetwork).unwrap();
/// let height = get_tx_height(&db, TxId::from_bytes([0u8; 32]));
/// ```
#[deprecated(
    note = "This function will be removed in a future release. Use zcash_client_backend::data_api::WalletRead::get_tx_height instead."
)]
pub fn get_tx_height<P>(
    wdb: &WalletDb<P>,
    txid: TxId,
) -> Result<Option<BlockHeight>, rusqlite::Error> {
    wdb.conn
        .query_row(
            "SELECT block FROM transactions WHERE txid = ?",
            [txid.as_ref().to_vec()],
            |row| row.get(0).map(u32::into),
        )
        .optional()
}

/// Returns the block hash for the block at the specified height,
/// if any.
///
/// # Examples
///
/// ```
/// use tempfile::NamedTempFile;
/// use zcash_primitives::consensus::{H0, Network};
/// use zcash_client_sqlite::{
///     WalletDb,
///     wallet::get_block_hash,
/// };
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db = WalletDb::for_path(data_file, Network::TestNetwork).unwrap();
/// let hash = get_block_hash(&db, H0);
/// ```
#[deprecated(
    note = "This function will be removed in a future release. Use zcash_client_backend::data_api::WalletRead::get_block_hash instead."
)]
pub fn get_block_hash<P>(
    wdb: &WalletDb<P>,
    block_height: BlockHeight,
) -> Result<Option<BlockHash>, rusqlite::Error> {
    wdb.conn
        .query_row(
            "SELECT hash FROM blocks WHERE height = ?",
            [u32::from(block_height)],
            |row| {
                let row_data = row.get::<_, Vec<_>>(0)?;
                Ok(BlockHash::from_slice(&row_data))
            },
        )
        .optional()
}

/// Gets the height to which the database must be rewound if any rewind greater than the pruning
/// height is attempted.
#[deprecated(note = "This function will be removed in a future release.")]
pub fn get_rewind_height<P>(wdb: &WalletDb<P>) -> Result<Option<BlockHeight>, SqliteClientError> {
    wdb.conn
        .query_row(
            "SELECT MIN(tx.block)
             FROM received_notes n
             JOIN transactions tx ON tx.id_tx = n.tx
             WHERE n.spent IS NULL",
            [],
            |row| {
                row.get(0)
                    .map(|maybe_height: Option<u32>| maybe_height.map(|height| height.into()))
            },
        )
        .map_err(SqliteClientError::from)
}

/// Rewinds the database to the given height.
///
/// If the requested height is greater than or equal to the height of the last scanned
/// block, this function does nothing.
///
/// This should only be executed inside a transactional context.
pub(crate) fn rewind_to_height<P: consensus::Parameters>(
    wdb: &WalletDb<P>,
    block_height: BlockHeight,
) -> Result<(), SqliteClientError> {
    let sapling_activation_height = wdb
        .params
        .activation_height(NetworkUpgrade::Sapling)
        .ok_or(SqliteClientError::BackendError(Error::SaplingNotActive))?;

    // Recall where we synced up to previously.
    let last_scanned_height = wdb
        .conn
        .query_row("SELECT MAX(height) FROM blocks", [], |row| {
            row.get(0)
                .map(|h: u32| h.into())
                .or_else(|_| Ok(sapling_activation_height - 1))
        })?;

    if block_height < last_scanned_height - PRUNING_HEIGHT {
        #[allow(deprecated)]
        if let Some(h) = get_rewind_height(wdb)? {
            if block_height > h {
                return Err(SqliteClientError::RequestedRewindInvalid(h, block_height));
            }
        }
    }

    // nothing to do if we're deleting back down to the max height
    if block_height < last_scanned_height {
        // Decrement witnesses.
        wdb.conn.execute(
            "DELETE FROM sapling_witnesses WHERE block > ?",
            [u32::from(block_height)],
        )?;

        // Rewind received notes
        wdb.conn.execute(
            "DELETE FROM received_notes
                WHERE id_note IN (
                    SELECT rn.id_note
                    FROM received_notes rn
                    LEFT OUTER JOIN transactions tx
                    ON tx.id_tx = rn.tx
                    WHERE tx.block IS NOT NULL AND tx.block > ?
                );",
            [u32::from(block_height)],
        )?;

        // Do not delete sent notes; this can contain data that is not recoverable
        // from the chain. Wallets must continue to operate correctly in the
        // presence of stale sent notes that link to unmined transactions.

        // Rewind utxos
        wdb.conn.execute(
            "DELETE FROM utxos WHERE height > ?",
            [u32::from(block_height)],
        )?;

        // Un-mine transactions.
        wdb.conn.execute(
            "UPDATE transactions SET block = NULL, tx_index = NULL WHERE block IS NOT NULL AND block > ?",
            [u32::from(block_height)],
        )?;

        // Now that they aren't depended on, delete scanned blocks.
        wdb.conn.execute(
            "DELETE FROM blocks WHERE height > ?",
            [u32::from(block_height)],
        )?;
    }

    Ok(())
}

/// Returns the commitment tree for the block at the specified height,
/// if any.
///
/// # Examples
///
/// ```
/// use tempfile::NamedTempFile;
/// use zcash_primitives::consensus::{Network, H0};
/// use zcash_client_sqlite::{
///     WalletDb,
///     wallet::get_commitment_tree,
/// };
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db = WalletDb::for_path(data_file, Network::TestNetwork).unwrap();
/// let tree = get_commitment_tree(&db, H0);
/// ```
#[deprecated(
    note = "This function will be removed in a future release. Use zcash_client_backend::data_api::WalletRead::get_commitment_tree instead."
)]
pub fn get_commitment_tree<P>(
    wdb: &WalletDb<P>,
    block_height: BlockHeight,
) -> Result<Option<CommitmentTree<Node>>, SqliteClientError> {
    wdb.conn
        .query_row_and_then(
            "SELECT sapling_tree FROM blocks WHERE height = ?",
            [u32::from(block_height)],
            |row| {
                let row_data: Vec<u8> = row.get(0)?;
                CommitmentTree::read(&row_data[..]).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        row_data.len(),
                        rusqlite::types::Type::Blob,
                        Box::new(e),
                    )
                })
            },
        )
        .optional()
        .map_err(SqliteClientError::from)
}

/// Returns the incremental witnesses for the block at the specified height,
/// if any.
///
/// # Examples
///
/// ```
/// use tempfile::NamedTempFile;
/// use zcash_primitives::consensus::{Network, H0};
/// use zcash_client_sqlite::{
///     WalletDb,
///     wallet::get_witnesses,
/// };
///
/// let data_file = NamedTempFile::new().unwrap();
/// let db = WalletDb::for_path(data_file, Network::TestNetwork).unwrap();
/// let witnesses = get_witnesses(&db, H0);
/// ```
#[deprecated(
    note = "This function will be removed in a future release. Use zcash_client_backend::data_api::WalletRead::get_witnesses instead."
)]
pub fn get_witnesses<P>(
    wdb: &WalletDb<P>,
    block_height: BlockHeight,
) -> Result<Vec<(NoteId, IncrementalWitness<Node>)>, SqliteClientError> {
    let mut stmt_fetch_witnesses = wdb
        .conn
        .prepare("SELECT note, witness FROM sapling_witnesses WHERE block = ?")?;
    let witnesses = stmt_fetch_witnesses
        .query_map([u32::from(block_height)], |row| {
            let id_note = NoteId::ReceivedNoteId(row.get(0)?);
            let wdb: Vec<u8> = row.get(1)?;
            Ok(IncrementalWitness::read(&wdb[..]).map(|witness| (id_note, witness)))
        })
        .map_err(SqliteClientError::from)?;

    // unwrap database error & IO error from IncrementalWitness::read
    let res: Vec<_> = witnesses.collect::<Result<Result<_, _>, _>>()??;
    Ok(res)
}

/// Retrieve the nullifiers for notes that the wallet is tracking
/// that have not yet been confirmed as a consequence of the spending
/// transaction being included in a block.
#[deprecated(
    note = "This function will be removed in a future release. Use zcash_client_backend::data_api::WalletRead::get_nullifiers instead."
)]
pub fn get_nullifiers<P>(
    wdb: &WalletDb<P>,
) -> Result<Vec<(AccountId, Nullifier)>, SqliteClientError> {
    // Get the nullifiers for the notes we are tracking
    let mut stmt_fetch_nullifiers = wdb.conn.prepare(
        "SELECT rn.id_note, rn.account, rn.nf, tx.block as block
            FROM received_notes rn
            LEFT OUTER JOIN transactions tx
            ON tx.id_tx = rn.spent
            WHERE block IS NULL",
    )?;
    let nullifiers = stmt_fetch_nullifiers.query_map([], |row| {
        let account: u32 = row.get(1)?;
        let nf_bytes: Vec<u8> = row.get(2)?;
        Ok((
            AccountId::from(account),
            Nullifier::from_slice(&nf_bytes).unwrap(),
        ))
    })?;

    let res: Vec<_> = nullifiers.collect::<Result<_, _>>()?;
    Ok(res)
}

/// Returns the nullifiers for the notes that this wallet is tracking.
pub(crate) fn get_all_nullifiers<P>(
    wdb: &WalletDb<P>,
) -> Result<Vec<(AccountId, Nullifier)>, SqliteClientError> {
    // Get the nullifiers for the notes we are tracking
    let mut stmt_fetch_nullifiers = wdb.conn.prepare(
        "SELECT rn.id_note, rn.account, rn.nf
            FROM received_notes rn",
    )?;
    let nullifiers = stmt_fetch_nullifiers.query_map([], |row| {
        let account: u32 = row.get(1)?;
        let nf_bytes: Vec<u8> = row.get(2)?;
        Ok((
            AccountId::from(account),
            Nullifier::from_slice(&nf_bytes).unwrap(),
        ))
    })?;

    let res: Vec<_> = nullifiers.collect::<Result<_, _>>()?;
    Ok(res)
}

/// Returns unspent transparent outputs that have been received by this wallet at the given
/// transparent address, such that the block that included the transaction was mined at a
/// height less than or equal to the provided `max_height`.
#[cfg(feature = "transparent-inputs")]
pub(crate) fn get_unspent_transparent_outputs<P: consensus::Parameters>(
    wdb: &WalletDb<P>,
    address: &TransparentAddress,
    max_height: BlockHeight,
) -> Result<Vec<WalletTransparentOutput>, SqliteClientError> {
    let mut stmt_blocks = wdb.conn.prepare(
        "SELECT u.prevout_txid, u.prevout_idx, u.script, u.value_zat, u.height, tx.block as block
         FROM utxos u
         LEFT OUTER JOIN transactions tx
         ON tx.id_tx = u.spent_in_tx
         WHERE u.address = ?
         AND u.height <= ?
         AND block IS NULL",
    )?;

    let addr_str = address.encode(&wdb.params);

    let rows = stmt_blocks.query_map(params![addr_str, u32::from(max_height)], |row| {
        let id: Vec<u8> = row.get(0)?;

        let mut txid_bytes = [0u8; 32];
        txid_bytes.copy_from_slice(&id);
        let index: u32 = row.get(1)?;
        let script_pubkey = Script(row.get(2)?);
        let value = Amount::from_i64(row.get(3)?).unwrap();
        let height: u32 = row.get(4)?;

        Ok(WalletTransparentOutput {
            outpoint: OutPoint::new(txid_bytes, index),
            txout: TxOut {
                value,
                script_pubkey,
            },
            height: BlockHeight::from(height),
        })
    })?;

    let mut utxos = Vec::<WalletTransparentOutput>::new();

    for utxo in rows {
        utxos.push(utxo.unwrap())
    }
    Ok(utxos)
}

/// Inserts information about a scanned block into the database.
#[deprecated(
    note = "This function will be removed in a future release. Use zcash_client_backend::data_api::WalletWrite::advance_by_block instead."
)]
pub fn insert_block<'a, P>(
    stmts: &mut DataConnStmtCache<'a, P>,
    block_height: BlockHeight,
    block_hash: BlockHash,
    block_time: u32,
    commitment_tree: &CommitmentTree<Node>,
) -> Result<(), SqliteClientError> {
    stmts.stmt_insert_block(block_height, block_hash, block_time, commitment_tree)
}

/// Inserts information about a mined transaction that was observed to
/// contain a note related to this wallet into the database.
#[deprecated(
    note = "This function will be removed in a future release. Use zcash_client_backend::data_api::WalletWrite::advance_by_block instead."
)]
pub fn put_tx_meta<'a, P, N>(
    stmts: &mut DataConnStmtCache<'a, P>,
    tx: &WalletTx<N>,
    height: BlockHeight,
) -> Result<i64, SqliteClientError> {
    if !stmts.stmt_update_tx_meta(height, tx.index, &tx.txid)? {
        // It isn't there, so insert our transaction into the database.
        stmts.stmt_insert_tx_meta(&tx.txid, height, tx.index)
    } else {
        // It was there, so grab its row number.
        stmts.stmt_select_tx_ref(&tx.txid)
    }
}

/// Inserts full transaction data into the database.
#[deprecated(
    note = "This function will be removed in a future release. Use zcash_client_backend::data_api::WalletWrite::store_decrypted_tx instead."
)]
pub fn put_tx_data<'a, P>(
    stmts: &mut DataConnStmtCache<'a, P>,
    tx: &Transaction,
    fee: Option<Amount>,
    created_at: Option<time::OffsetDateTime>,
) -> Result<i64, SqliteClientError> {
    let txid = tx.txid();

    let mut raw_tx = vec![];
    tx.write(&mut raw_tx)?;

    if !stmts.stmt_update_tx_data(tx.expiry_height(), &raw_tx, fee, &txid)? {
        // It isn't there, so insert our transaction into the database.
        stmts.stmt_insert_tx_data(&txid, created_at, tx.expiry_height(), &raw_tx, fee)
    } else {
        // It was there, so grab its row number.
        stmts.stmt_select_tx_ref(&txid)
    }
}

/// Marks a given nullifier as having been revealed in the construction
/// of the specified transaction.
///
/// Marking a note spent in this fashion does NOT imply that the
/// spending transaction has been mined.
#[deprecated(
    note = "This function will be removed in a future release. Use zcash_client_backend::data_api::WalletWrite::store_sent_tx instead."
)]
pub fn mark_sapling_note_spent<'a, P>(
    stmts: &mut DataConnStmtCache<'a, P>,
    tx_ref: i64,
    nf: &Nullifier,
) -> Result<(), SqliteClientError> {
    stmts.stmt_mark_sapling_note_spent(tx_ref, nf)?;
    Ok(())
}

/// Marks the given UTXO as having been spent.
#[cfg(feature = "transparent-inputs")]
pub(crate) fn mark_transparent_utxo_spent<'a, P>(
    stmts: &mut DataConnStmtCache<'a, P>,
    tx_ref: i64,
    outpoint: &OutPoint,
) -> Result<(), SqliteClientError> {
    stmts.stmt_mark_transparent_utxo_spent(tx_ref, outpoint)?;

    Ok(())
}

/// Adds the given received UTXO to the datastore.
#[cfg(feature = "transparent-inputs")]
pub(crate) fn put_received_transparent_utxo<'a, P: consensus::Parameters>(
    stmts: &mut DataConnStmtCache<'a, P>,
    output: &WalletTransparentOutput,
) -> Result<UtxoId, SqliteClientError> {
    stmts
        .stmt_insert_received_transparent_utxo(output)
        .map(UtxoId)
}

/// Removes all records of UTXOs that were recorded as having been received
/// at block heights greater than the given height.
#[cfg(feature = "transparent-inputs")]
#[deprecated(
    note = "This method will be removed in a future update. Use zcash_client_backend::data_api::WalletWrite::rewind_to_height instead."
)]
pub fn delete_utxos_above<'a, P: consensus::Parameters>(
    stmts: &mut DataConnStmtCache<'a, P>,
    taddr: &TransparentAddress,
    height: BlockHeight,
) -> Result<usize, SqliteClientError> {
    stmts.stmt_delete_utxos(taddr, height)
}

/// Records the specified shielded output as having been received.
///
/// This implementation relies on the facts that:
/// - A transaction will not contain more than 2^63 shielded outputs.
/// - A note value will never exceed 2^63 zatoshis.
#[deprecated(
    note = "This method will be removed in a future release. Use zcash_client_backend::data_api::WalletWrite::store_decrypted_tx instead."
)]
#[allow(deprecated)]
pub fn put_received_note<'a, P, T: ShieldedOutput>(
    stmts: &mut DataConnStmtCache<'a, P>,
    output: &T,
    tx_ref: i64,
) -> Result<NoteId, SqliteClientError> {
    let rcm = output.note().rcm().to_repr();
    let account = output.account();
    let diversifier = output.to().diversifier();
    let value = output.note().value;
    let memo = output.memo();
    let is_change = output.is_change();
    let output_index = output.index();
    let nf = output.nullifier();

    // First try updating an existing received note into the database.
    if !stmts.stmt_update_received_note(
        account,
        diversifier,
        value,
        rcm,
        &nf,
        memo,
        is_change,
        tx_ref,
        output_index,
    )? {
        // It isn't there, so insert our note into the database.
        stmts.stmt_insert_received_note(
            tx_ref,
            output_index,
            account,
            diversifier,
            value,
            rcm,
            &nf,
            memo,
            is_change,
        )
    } else {
        // It was there, so grab its row number.
        stmts.stmt_select_received_note(tx_ref, output.index())
    }
}

/// Records the incremental witness for the specified note,
/// as of the given block height.
#[deprecated(
    note = "This method will be removed in a future release. Use zcash_client_backend::data_api::WalletWrite::store_decrypted_tx instead."
)]
pub fn insert_witness<'a, P>(
    stmts: &mut DataConnStmtCache<'a, P>,
    note_id: i64,
    witness: &IncrementalWitness<Node>,
    height: BlockHeight,
) -> Result<(), SqliteClientError> {
    stmts.stmt_insert_witness(NoteId::ReceivedNoteId(note_id), height, witness)
}

/// Removes old incremental witnesses up to the given block height.
#[deprecated(
    note = "This method will be removed in a future update. Use zcash_client_backend::data_api::WalletWrite::advance_by_block instead."
)]
pub fn prune_witnesses<P>(
    stmts: &mut DataConnStmtCache<'_, P>,
    below_height: BlockHeight,
) -> Result<(), SqliteClientError> {
    stmts.stmt_prune_witnesses(below_height)
}

/// Marks notes that have not been mined in transactions
/// as expired, up to the given block height.
#[deprecated(
    note = "This method will be removed in a future update. Use zcash_client_backend::data_api::WalletWrite::advance_by_block instead."
)]
pub fn update_expired_notes<P>(
    stmts: &mut DataConnStmtCache<'_, P>,
    height: BlockHeight,
) -> Result<(), SqliteClientError> {
    stmts.stmt_update_expired(height)
}

/// Records information about a note that your wallet created.
#[deprecated(
    note = "This method will be removed in a future update. Use zcash_client_backend::data_api::WalletWrite::store_decrypted_tx instead."
)]
#[allow(deprecated)]
pub fn put_sent_note<'a, P: consensus::Parameters>(
    stmts: &mut DataConnStmtCache<'a, P>,
    tx_ref: i64,
    output_index: usize,
    account: AccountId,
    to: &PaymentAddress,
    value: Amount,
    memo: Option<&MemoBytes>,
) -> Result<(), SqliteClientError> {
    // Try updating an existing sent note.
    if !stmts.stmt_update_sent_note(
        account,
        &encode_payment_address_p(&stmts.wallet_db.params, to),
        value,
        memo,
        tx_ref,
        PoolType::Sapling,
        output_index,
    )? {
        // It isn't there, so insert.
        insert_sent_note(stmts, tx_ref, output_index, account, to, value, memo)?
    }

    Ok(())
}

/// Adds information about a sent transparent UTXO to the database if it does not already
/// exist, or updates it if a record for the UTXO already exists.
///
/// `output_index` is the index within transparent UTXOs of the transaction that contains the recipient output.
#[deprecated(
    note = "This method will be removed in a future update. Use zcash_client_backend::data_api::WalletWrite::store_decrypted_tx instead."
)]
#[allow(deprecated)]
pub fn put_sent_utxo<'a, P: consensus::Parameters>(
    stmts: &mut DataConnStmtCache<'a, P>,
    tx_ref: i64,
    output_index: usize,
    account: AccountId,
    to: &TransparentAddress,
    value: Amount,
) -> Result<(), SqliteClientError> {
    // Try updating an existing sent UTXO.
    if !stmts.stmt_update_sent_note(
        account,
        &encode_transparent_address_p(&stmts.wallet_db.params, to),
        value,
        None,
        tx_ref,
        PoolType::Transparent,
        output_index,
    )? {
        // It isn't there, so insert.
        insert_sent_utxo(stmts, tx_ref, output_index, account, to, value)?
    }

    Ok(())
}

/// Inserts a sent note into the wallet database.
///
/// `output_index` is the index within the transaction that contains the recipient output:
///
/// - If `to` is a Sapling address, this is an index into the Sapling outputs of the
///   transaction.
/// - If `to` is a transparent address, this is an index into the transparent outputs of
///   the transaction.
#[deprecated(
    note = "This method will be removed in a future update. Use zcash_client_backend::data_api::WalletWrite::store_sent_tx instead."
)]
pub fn insert_sent_note<'a, P: consensus::Parameters>(
    stmts: &mut DataConnStmtCache<'a, P>,
    tx_ref: i64,
    output_index: usize,
    account: AccountId,
    to: &PaymentAddress,
    value: Amount,
    memo: Option<&MemoBytes>,
) -> Result<(), SqliteClientError> {
    let to_str = encode_payment_address_p(&stmts.wallet_db.params, to);

    stmts.stmt_insert_sent_note(
        tx_ref,
        PoolType::Sapling,
        output_index,
        account,
        &to_str,
        value,
        memo,
    )
}

/// Inserts information about a sent transparent UTXO into the wallet database.
///
/// `output_index` is the index within transparent UTXOs of the transaction that contains the recipient output.
#[deprecated(
    note = "This method will be removed in a future update. Use zcash_client_backend::data_api::WalletWrite::store_sent_tx instead."
)]
pub fn insert_sent_utxo<'a, P: consensus::Parameters>(
    stmts: &mut DataConnStmtCache<'a, P>,
    tx_ref: i64,
    output_index: usize,
    account: AccountId,
    to: &TransparentAddress,
    value: Amount,
) -> Result<(), SqliteClientError> {
    let to_str = encode_transparent_address_p(&stmts.wallet_db.params, to);

    stmts.stmt_insert_sent_note(
        tx_ref,
        PoolType::Transparent,
        output_index,
        account,
        &to_str,
        value,
        None,
    )
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use secrecy::Secret;
    use tempfile::NamedTempFile;

    use zcash_primitives::transaction::components::Amount;

    use zcash_client_backend::data_api::WalletRead;

    use crate::{tests, wallet::init::init_wallet_db, AccountId, WalletDb};

    use super::{get_address, get_balance};

    #[test]
    fn empty_database_has_no_balance() {
        let data_file = NamedTempFile::new().unwrap();
        let mut db_data = WalletDb::for_path(data_file.path(), tests::network()).unwrap();
        init_wallet_db(&mut db_data, Some(Secret::new(vec![]))).unwrap();

        // Add an account to the wallet
        tests::init_test_accounts_table(&db_data);

        // The account should be empty
        assert_eq!(
            get_balance(&db_data, AccountId::from(0)).unwrap(),
            Amount::zero()
        );

        // We can't get an anchor height, as we have not scanned any blocks.
        assert_eq!(db_data.get_target_and_anchor_heights(10).unwrap(), None);

        // An invalid account has zero balance
        assert!(get_address(&db_data, AccountId::from(1)).is_err());
        assert_eq!(
            get_balance(&db_data, AccountId::from(0)).unwrap(),
            Amount::zero()
        );
    }
}
