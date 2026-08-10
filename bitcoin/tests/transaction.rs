// SPDX-License-Identifier: CC0-1.0

use bitcoin::blockdata::transaction::Transaction;
use bitcoin::consensus::encode::deserialize;
use hex::test_hex_unwrap as hex;

#[test]
fn huge_witness() {
    deserialize::<Transaction>(&hex!(include_str!("data/huge_witness.hex").trim())).unwrap();
}
