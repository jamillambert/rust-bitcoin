// SPDX-License-Identifier: CC0-1.0

use std::str::FromStr;

use bitcoin::secp256k1;
use bitcoin::taproot::{ControlBlock, LeafVersion, TaprootBuilder};
use bitcoin::{Address, KnownHrp, ScriptBuf, TapLeafHash, TapNodeHash, TapTweakHash, XOnlyPublicKey};
use bitcoin::key::TapTweak;
use hex::FromHex;

extern crate serde_json;

#[test]
fn bip_341_tests() {
    fn process_script_trees(
        v: &serde_json::Value,
        mut builder: TaprootBuilder,
        leaves: &mut Vec<(ScriptBuf, LeafVersion)>,
        depth: u8,
    ) -> TaprootBuilder {
        if v.is_null() {
            // nothing to push
        } else if v.is_array() {
            for leaf in v.as_array().unwrap() {
                builder = process_script_trees(leaf, builder, leaves, depth + 1);
            }
        } else {
            let script = ScriptBuf::from_hex(v["script"].as_str().unwrap()).unwrap();
            let ver =
                LeafVersion::from_consensus(v["leafVersion"].as_u64().unwrap() as u8).unwrap();
            leaves.push((script.clone(), ver));
            builder = builder.add_leaf_with_ver(depth, script, ver).unwrap();
        }
        builder
    }

    let data = bip_341_read_json();
    // Check the version of data
    assert!(data["version"] == 1);
    let secp = &secp256k1::Secp256k1::verification_only();

    for arr in data["scriptPubKey"].as_array().unwrap() {
        let internal_key =
            XOnlyPublicKey::from_str(arr["given"]["internalPubkey"].as_str().unwrap()).unwrap();
        // process the tree
        let script_tree = &arr["given"]["scriptTree"];
        let mut merkle_root = None;
        if script_tree.is_null() {
            assert!(arr["intermediary"]["merkleRoot"].is_null());
        } else {
            merkle_root = Some(
                TapNodeHash::from_str(arr["intermediary"]["merkleRoot"].as_str().unwrap())
                    .unwrap(),
            );
            let leaf_hashes = arr["intermediary"]["leafHashes"].as_array().unwrap();
            let ctrl_blks = arr["expected"]["scriptPathControlBlocks"].as_array().unwrap();
            let mut builder = TaprootBuilder::new();
            let mut leaves = vec![];
            builder = process_script_trees(script_tree, builder, &mut leaves, 0);
            let spend_info = builder.finalize(secp, internal_key).unwrap();
            for (i, script_ver) in leaves.iter().enumerate() {
                let expected_leaf_hash = leaf_hashes[i].as_str().unwrap();
                let expected_ctrl_blk = ControlBlock::decode(
                    &Vec::<u8>::from_hex(ctrl_blks[i].as_str().unwrap()).unwrap(),
                )
                .unwrap();

                let leaf_hash = TapLeafHash::from_script(&script_ver.0, script_ver.1);
                let ctrl_blk = spend_info.control_block(script_ver).unwrap();
                assert_eq!(leaf_hash.to_string(), expected_leaf_hash);
                assert_eq!(ctrl_blk, expected_ctrl_blk);
            }
        }
        let expected_output_key =
            XOnlyPublicKey::from_str(arr["intermediary"]["tweakedPubkey"].as_str().unwrap())
                .unwrap();
        let expected_tweak =
            TapTweakHash::from_str(arr["intermediary"]["tweak"].as_str().unwrap()).unwrap();
        let expected_spk =
            ScriptBuf::from_hex(arr["expected"]["scriptPubKey"].as_str().unwrap()).unwrap();
        let expected_addr =
            Address::from_str(arr["expected"]["bip350Address"].as_str().unwrap())
                .unwrap()
                .assume_checked();

        let tweak = TapTweakHash::from_key_and_tweak(internal_key, merkle_root);
        let (output_key, _parity) = internal_key.tap_tweak(secp, merkle_root);
        let addr = Address::p2tr(secp, internal_key, merkle_root, KnownHrp::Mainnet);
        let spk = addr.script_pubkey();

        assert_eq!(expected_output_key, output_key.to_x_only_public_key());
        assert_eq!(expected_tweak, tweak);
        assert_eq!(expected_addr, addr);
        assert_eq!(expected_spk, spk);
    }
}

fn bip_341_read_json() -> serde_json::Value {
    let json_str = include_str!("data/bip341_tests.json");
    serde_json::from_str(json_str).expect("JSON was not well-formatted")
}
