#![cfg_attr(fuzzing, no_main)]
#![cfg_attr(not(fuzzing), allow(unused))]

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::encoding::{decode_from_slice, encode_to_vec};
use honggfuzz::fuzz;

fn main() {
    loop {
        fuzz!(|data: &[u8]| {
            do_test(data);
        });
    }
}

macro_rules! compare_encoding {
    ($data:expr, $ty:ty) => {{
        let old_result: Result<$ty, _> = deserialize($data);
        let new_result: Result<$ty, _> = decode_from_slice($data);

        match (old_result, new_result) {
            (Ok(old_obj), Ok(new_obj)) => {
                let old_encoded = serialize(&old_obj);
                let new_encoded = encode_to_vec(&new_obj);
                assert_eq!(old_encoded, new_encoded);
            }
            (Err(_), Err(_)) => {}
            (old, new) => panic!("decoder mismatch: old={old:?} new={new:?}"),
        }
    }};
}

#[rustfmt::skip]
fn do_test(data: &[u8]) {
    compare_encoding!(data, bitcoin::Block);
    compare_encoding!(data, bitcoin::Transaction);
    compare_encoding!(data, bitcoin::TxIn);
    compare_encoding!(data, bitcoin::TxOut);
    compare_encoding!(data, bitcoin::OutPoint);
    compare_encoding!(data, bitcoin::Witness);
    compare_encoding!(data, bitcoin::Sequence);
    compare_encoding!(data, bitcoin::Amount);
    compare_encoding!(data, bitcoin::ScriptBuf);
    compare_encoding!(data, bitcoin::CompactTarget);
    compare_encoding!(data, bitcoin::BlockHash);
    compare_encoding!(data, bitcoin::TxMerkleNode);
    compare_encoding!(data, bitcoin::WitnessMerkleNode);

    compare_encoding!(data, bitcoin::block::Header);
    compare_encoding!(data, bitcoin::absolute::LockTime);
    compare_encoding!(data, bitcoin::block::Version);
    compare_encoding!(data, bitcoin::transaction::Version);

    compare_encoding!(data, bitcoin::p2p::ServiceFlags);
    compare_encoding!(data, bitcoin::p2p::Magic);
    compare_encoding!(data, bitcoin::p2p::address::Address);
    compare_encoding!(data, bitcoin::bip152::BlockTransactions);
    compare_encoding!(data, bitcoin::bip152::BlockTransactionsRequest);
    compare_encoding!(data, bitcoin::bip152::HeaderAndShortIds);
    compare_encoding!(data, bitcoin::bip152::PrefilledTransaction);
    compare_encoding!(data, bitcoin::bip152::ShortId);
    compare_encoding!(data, bitcoin::MerkleBlock);
    compare_encoding!(data, bitcoin::merkle_tree::PartialMerkleTree);
    compare_encoding!(data, bitcoin::p2p::message_blockdata::GetBlocksMessage);
    compare_encoding!(data, bitcoin::p2p::message_blockdata::GetHeadersMessage);
    compare_encoding!(data, bitcoin::p2p::message_bloom::FilterAdd);
    compare_encoding!(data, bitcoin::p2p::message_bloom::FilterLoad);
    compare_encoding!(data, bitcoin::p2p::message_bloom::BloomFlags);
    compare_encoding!(data, bitcoin::p2p::message_compact_blocks::SendCmpct);
    compare_encoding!(data, bitcoin::p2p::message_filter::CFHeaders);
    compare_encoding!(data, bitcoin::p2p::message_filter::CFilter);
    compare_encoding!(data, bitcoin::p2p::message_filter::CFCheckpt);
    compare_encoding!(data, bitcoin::p2p::message_filter::GetCFCheckpt);
    compare_encoding!(data, bitcoin::p2p::message_filter::GetCFHeaders);
    compare_encoding!(data, bitcoin::p2p::message_filter::GetCFilters);
    compare_encoding!(data, bitcoin::bip158::FilterHash);
    compare_encoding!(data, bitcoin::bip158::FilterHeader);
    compare_encoding!(data, bitcoin::p2p::message_network::Reject);
    compare_encoding!(data, bitcoin::p2p::message_network::RejectReason);
    compare_encoding!(data, bitcoin::p2p::message_network::VersionMessage);

    compare_encoding!(data, bitcoin::p2p::address::AddrV2);
    compare_encoding!(data, bitcoin::p2p::address::AddrV2Message);
    if data.get(..4) != Some(&[0u8; 4]) {
        compare_encoding!(data, bitcoin::p2p::message_blockdata::Inventory);
    }
}

#[cfg(all(test, fuzzing))]
mod tests {
    fn extend_vec_from_hex(hex: &str, out: &mut Vec<u8>) {
        let mut b = 0;
        for (idx, c) in hex.as_bytes().iter().enumerate() {
            b <<= 4;
            match *c {
                b'A'..=b'F' => b |= c - b'A' + 10,
                b'a'..=b'f' => b |= c - b'a' + 10,
                b'0'..=b'9' => b |= c - b'0',
                _ => panic!("Bad hex"),
            }
            if (idx & 1) == 1 {
                out.push(b);
                b = 0;
            }
        }
    }

    #[test]
    fn duplicate_crash() {
        let mut a = Vec::new();
        extend_vec_from_hex("00003cb1133bb113", &mut a);
        super::do_test(&a);
    }
}
