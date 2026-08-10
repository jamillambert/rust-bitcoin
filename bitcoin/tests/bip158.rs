// SPDX-License-Identifier: CC0-1.0

#![cfg(feature = "std")]

use std::collections::HashMap;

use bitcoin::bip158::{BlockFilter, Error, FilterHeader};
use bitcoin::blockdata::block::Block;
use bitcoin::blockdata::script::ScriptBuf;
use bitcoin::consensus::encode::deserialize;
use bitcoin::BlockHash;
use hex::test_hex_unwrap as hex;
use serde_json::Value;

#[test]
fn test_blockfilters() {
    // test vectors from: https://github.com/jimpo/bitcoin/blob/c7efb652f3543b001b4dd22186a354605b14f47e/src/test/data/blockfilters.json
    let data = include_str!("data/blockfilters.json");

    let testdata = serde_json::from_str::<Value>(data).unwrap().as_array().unwrap().clone();
    for t in testdata.iter().skip(1) {
        let block_hash = t.get(1).unwrap().as_str().unwrap().parse::<BlockHash>().unwrap();
        let block: Block = deserialize(&hex!(t.get(2).unwrap().as_str().unwrap())).unwrap();
        assert_eq!(block.block_hash(), block_hash);
        let scripts = t.get(3).unwrap().as_array().unwrap();
        let previous_filter_header =
            t.get(4).unwrap().as_str().unwrap().parse::<FilterHeader>().unwrap();
        let filter_content = hex!(t.get(5).unwrap().as_str().unwrap());
        let filter_header =
            t.get(6).unwrap().as_str().unwrap().parse::<FilterHeader>().unwrap();

        let mut txmap = HashMap::new();
        let mut si = scripts.iter();
        for tx in block.txdata.iter().skip(1) {
            for input in tx.input.iter() {
                txmap.insert(
                    input.previous_output,
                    ScriptBuf::from(hex!(si.next().unwrap().as_str().unwrap())),
                );
            }
        }

        let filter = BlockFilter::new_script_filter(&block, |o| {
            if let Some(s) = txmap.get(o) {
                Ok(s.clone())
            } else {
                Err(Error::UtxoMissing(*o))
            }
        })
        .unwrap();

        let test_filter = BlockFilter::new(filter_content.as_slice());

        assert_eq!(test_filter.content, filter.content);

        let block_hash = &block.block_hash();
        assert!(filter
            .match_all(
                block_hash,
                &mut txmap.values().filter_map(|s| if !s.is_empty() {
                    Some(s.as_bytes())
                } else {
                    None
                })
            )
            .unwrap());

        for script in txmap.values() {
            let query = [script];
            if !script.is_empty() {
                assert!(filter
                    .match_any(block_hash, &mut query.iter().map(|s| s.as_bytes()))
                    .unwrap());
            }
        }

        assert_eq!(filter_header, filter.filter_header(&previous_filter_header));
    }
}
