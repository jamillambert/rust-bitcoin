// SPDX-License-Identifier: CC0-1.0

use bitcoin::blockdata::transaction::Transaction;
use bitcoin::consensus::encode::{deserialize_hex, FromHexError};
use bitcoin::consensus::DecodeError;

#[test]
fn deserialize_tx_hex() {
    let hex = include_str!("data/previous_tx_0_hex"); // An arbitrary transaction.
    assert!(deserialize_hex::<Transaction>(hex).is_ok())
}

#[test]
fn deserialize_tx_hex_too_many_bytes() {
    let mut hex = include_str!("data/previous_tx_0_hex").to_string(); // An arbitrary transaction.
    hex.push_str("abcdef");
    assert!(matches!(
        deserialize_hex::<Transaction>(&hex).unwrap_err(),
        FromHexError::Decode(DecodeError::TooManyBytes)
    ));
}
