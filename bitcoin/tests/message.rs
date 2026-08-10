// SPDX-License-Identifier: CC0-1.0

use std::net::Ipv4Addr;

use bitcoin::bip152::BlockTransactionsRequest;
use bitcoin::blockdata::block::Block;
use bitcoin::blockdata::script::ScriptBuf;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::sha256d::Hash;
use bitcoin::hashes::Hash as HashTrait;
use bitcoin::merkle_tree::MerkleBlock;
use bitcoin::p2p::address::{AddrV2, AddrV2Message, Address};
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_blockdata::{GetBlocksMessage, GetHeadersMessage, Inventory};
use bitcoin::p2p::message_bloom::{BloomFlags, FilterAdd, FilterLoad};
use bitcoin::p2p::message_compact_blocks::{GetBlockTxn, SendCmpct};
use bitcoin::p2p::message_filter::{CFCheckpt, CFHeaders, CFilter, GetCFCheckpt, GetCFHeaders, GetCFilters};
use bitcoin::p2p::message_network::{Reject, RejectReason, VersionMessage};
use bitcoin::p2p::{Magic, ServiceFlags};
use bitcoin::blockdata::block;
use hex::test_hex_unwrap as hex;

fn hash(slice: [u8; 32]) -> Hash { Hash::from_slice(&slice).unwrap() }

#[test]
fn full_round_ser_der_raw_network_message_test() {
    let version_msg: VersionMessage = deserialize(&hex!("721101000100000000000000e6e0845300000000010000000000000000000000000000000000ffff0000000000000100000000000000fd87d87eeb4364f22cf54dca59412db7208d47d920cffce83ee8102f5361746f7368693a302e392e39392f2c9f040001")).unwrap();
    let tx: Transaction = deserialize(&hex!("0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000")).unwrap();
    let block: Block = deserialize(&include_bytes!("data/testnet_block_000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b.raw")[..]).unwrap();
    let header: block::Header = deserialize(&hex!("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b")).unwrap();
    let script: ScriptBuf =
        deserialize(&hex!("1976a91431a420903c05a0a7de2de40c9f02ebedbacdc17288ac")).unwrap();
    let merkle_block: MerkleBlock = deserialize(&hex!("0100000079cda856b143d9db2c1caff01d1aecc8630d30625d10e8b4b8b0000000000000b50cc069d6a3e33e3ff84a5c41d9d3febe7c770fdcc96b2c3ff60abe184f196367291b4d4c86041b8fa45d630100000001b50cc069d6a3e33e3ff84a5c41d9d3febe7c770fdcc96b2c3ff60abe184f19630101")).unwrap();
    let cmptblock = deserialize(&hex!("00000030d923ad36ff2d955abab07f8a0a6e813bc6e066b973e780c5e36674cad5d1cd1f6e265f2a17a0d35cbe701fe9d06e2c6324cfe135f6233e8b767bfa3fb4479b71115dc562ffff7f2006000000000000000000000000010002000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0302ee00ffffffff0100f9029500000000015100000000")).unwrap();
    let blocktxn = deserialize(&hex!("2e93c0cff39ff605020072d96bc3a8d20b8447e294d08092351c8583e08d9b5a01020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402dc0000ffffffff0200f90295000000001976a9142b4569203694fc997e13f2c0a1383b9e16c77a0d88ac0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000")).unwrap();

    let msgs = vec![
        NetworkMessage::Version(version_msg),
        NetworkMessage::Verack,
        NetworkMessage::Addr(vec![(
            45,
            Address::new(&([123, 255, 000, 100], 833).into(), ServiceFlags::NETWORK),
        )]),
        NetworkMessage::Inv(vec![Inventory::Block(hash([8u8; 32]).into())]),
        NetworkMessage::GetData(vec![Inventory::Transaction(hash([45u8; 32]).into())]),
        NetworkMessage::GetBlocks(GetBlocksMessage::new(
            vec![hash([1u8; 32]).into(), hash([4u8; 32]).into()],
            hash([5u8; 32]).into(),
        )),
        NetworkMessage::GetHeaders(GetHeadersMessage::new(
            vec![hash([10u8; 32]).into(), hash([40u8; 32]).into()],
            hash([50u8; 32]).into(),
        )),
        NetworkMessage::MemPool,
        NetworkMessage::Tx(tx),
        NetworkMessage::Block(block),
        NetworkMessage::Headers(vec![header]),
        NetworkMessage::SendHeaders,
        NetworkMessage::GetAddr,
        NetworkMessage::Ping(15),
        NetworkMessage::Pong(23),
        NetworkMessage::MerkleBlock(merkle_block),
        NetworkMessage::FilterLoad(FilterLoad {
            filter: hex!("03614e9b050000000000000001"),
            hash_funcs: 1,
            tweak: 2,
            flags: BloomFlags::All,
        }),
        NetworkMessage::FilterAdd(FilterAdd { data: script.as_bytes().to_vec() }),
        NetworkMessage::FilterAdd(FilterAdd {
            data: hash([29u8; 32]).as_byte_array().to_vec(),
        }),
        NetworkMessage::FilterClear,
        NetworkMessage::GetCFilters(GetCFilters {
            filter_type: 2,
            start_height: 52,
            stop_hash: hash([42u8; 32]).into(),
        }),
        NetworkMessage::CFilter(CFilter {
            filter_type: 7,
            block_hash: hash([25u8; 32]).into(),
            filter: vec![1, 2, 3],
        }),
        NetworkMessage::GetCFHeaders(GetCFHeaders {
            filter_type: 4,
            start_height: 102,
            stop_hash: hash([47u8; 32]).into(),
        }),
        NetworkMessage::CFHeaders(CFHeaders {
            filter_type: 13,
            stop_hash: hash([53u8; 32]).into(),
            previous_filter_header: hash([12u8; 32]).into(),
            filter_hashes: vec![hash([4u8; 32]).into(), hash([12u8; 32]).into()],
        }),
        NetworkMessage::GetCFCheckpt(GetCFCheckpt {
            filter_type: 17,
            stop_hash: hash([25u8; 32]).into(),
        }),
        NetworkMessage::CFCheckpt(CFCheckpt {
            filter_type: 27,
            stop_hash: hash([77u8; 32]).into(),
            filter_headers: vec![hash([3u8; 32]).into(), hash([99u8; 32]).into()],
        }),
        NetworkMessage::Alert(vec![45, 66, 3, 2, 6, 8, 9, 12, 3, 130]),
        NetworkMessage::Reject(Reject {
            message: "Test reject".into(),
            ccode: RejectReason::Duplicate,
            reason: "Cause".into(),
            hash: hash([255u8; 32]),
        }),
        NetworkMessage::FeeFilter(1000),
        NetworkMessage::WtxidRelay,
        NetworkMessage::AddrV2(vec![AddrV2Message {
            addr: AddrV2::Ipv4(Ipv4Addr::new(127, 0, 0, 1)),
            port: 0,
            services: ServiceFlags::NONE,
            time: 0,
        }]),
        NetworkMessage::SendAddrV2,
        NetworkMessage::CmpctBlock(cmptblock),
        NetworkMessage::GetBlockTxn(GetBlockTxn {
            txs_request: BlockTransactionsRequest {
                block_hash: hash([11u8; 32]).into(),
                indexes: vec![0, 1, 2, 3, 10, 3002],
            },
        }),
        NetworkMessage::BlockTxn(blocktxn),
        NetworkMessage::SendCmpct(SendCmpct { send_compact: true, version: 8333 }),
    ];

    for msg in msgs {
        let raw_msg = RawNetworkMessage::new(Magic::from_bytes([57, 0, 0, 0]), msg);
        assert_eq!(deserialize::<RawNetworkMessage>(&serialize(&raw_msg)).unwrap(), raw_msg);
    }
}
