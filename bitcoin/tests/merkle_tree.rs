// SPDX-License-Identifier: CC0-1.0

use bitcoin::blockdata::block::Block;
use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::sha256d;
use bitcoin::hashes::Hash;
use bitcoin::merkle_tree::{calculate_root, calculate_root_inline};

#[test]
fn both_merkle_root_functions_return_the_same_result() {
    // testnet block 000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b
    let segwit_block = include_bytes!("data/testnet_block_000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b.raw");
    let block: Block = deserialize(&segwit_block[..]).expect("Failed to deserialize block");
    assert!(block.check_merkle_root()); // Sanity check.

    let hashes_iter = block.txdata.iter().map(|obj| obj.compute_txid().to_raw_hash());

    let mut hashes_array: [sha256d::Hash; 15] = [Hash::all_zeros(); 15];
    for (i, hash) in hashes_iter.clone().enumerate() {
        hashes_array[i] = hash;
    }

    let from_iter = calculate_root(hashes_iter);
    let from_array = calculate_root_inline(&mut hashes_array);
    assert_eq!(from_iter, from_array);
}
