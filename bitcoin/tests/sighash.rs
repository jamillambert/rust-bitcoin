// SPDX-License-Identifier: CC0-1.0

#![cfg(feature = "serde")]

extern crate serde;

use std::str::FromStr;

use bitcoin::blockdata::transaction::Transaction;
use bitcoin::consensus::encode::deserialize;
use bitcoin::consensus::serde as con_serde;
use bitcoin::hashes::sha256;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{self, SecretKey, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighash, TapSighashType};
use bitcoin::taproot::{TapNodeHash, TapTweakHash};
use bitcoin::{Amount, LegacySighash, ScriptBuf, TxOut};
use hex::{test_hex_unwrap as hex, DisplayHex, FromHex};

extern crate serde_json;

#[test]
fn legacy_sighash() {
    use serde_json::Value;

    fn run_test_sighash(
        tx: &str,
        script: &str,
        input_index: usize,
        hash_type: i64,
        expected_result: &str,
    ) {
        let tx: Transaction = deserialize(&Vec::from_hex(tx).unwrap()[..]).unwrap();
        let script = ScriptBuf::from(Vec::from_hex(script).unwrap());
        let mut raw_expected = Vec::from_hex(expected_result).unwrap();
        raw_expected.reverse();
        let want = LegacySighash::from_slice(&raw_expected[..]).unwrap();

        let cache = SighashCache::new(&tx);
        let got = cache.legacy_signature_hash(input_index, &script, hash_type as u32).unwrap();

        assert_eq!(got, want);
    }

    // These test vectors were stolen from libbtc, which is Copyright 2014 Jonas Schnelli MIT
    // They were transformed by replacing {...} with run_test_sighash(...), then the ones containing
    // OP_CODESEPARATOR in their pubkeys were removed
    let data = include_str!("data/legacy_sighash.json");

    let testdata = serde_json::from_str::<Value>(data).unwrap().as_array().unwrap().clone();
    for t in testdata.iter().skip(1) {
        let tx = t.get(0).unwrap().as_str().unwrap();
        let script = t.get(1).unwrap().as_str().unwrap_or("");
        let input_index = t.get(2).unwrap().as_u64().unwrap();
        let hash_type = t.get(3).unwrap().as_i64().unwrap();
        let expected_sighash = t.get(4).unwrap().as_str().unwrap();
        run_test_sighash(tx, script, input_index as usize, hash_type, expected_sighash);
    }
}

#[test]
fn bip_341_sighash_tests() {
    fn sighash_deser_numeric<'de, D>(deserializer: D) -> Result<TapSighashType, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{Deserialize, Error, Unexpected};

        let raw = u8::deserialize(deserializer)?;
        TapSighashType::from_consensus_u8(raw).map_err(|_| {
            D::Error::invalid_value(
                Unexpected::Unsigned(raw.into()),
                &"number in range 0-3 or 0x81-0x83",
            )
        })
    }

    #[derive(serde::Deserialize)]
    struct UtxoSpent {
        #[serde(rename = "scriptPubKey")]
        script_pubkey: ScriptBuf,
        #[serde(rename = "amountSats")]
        value: Amount,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct KpsGiven {
        #[serde(with = "con_serde::With::<con_serde::Hex>")]
        raw_unsigned_tx: Transaction,
        utxos_spent: Vec<UtxoSpent>,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct KpsIntermediary {
        hash_prevouts: sha256::Hash,
        hash_outputs: sha256::Hash,
        hash_sequences: sha256::Hash,
        hash_amounts: sha256::Hash,
        hash_script_pubkeys: sha256::Hash,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct KpsInputSpendingGiven {
        txin_index: usize,
        internal_privkey: SecretKey,
        merkle_root: Option<TapNodeHash>,
        #[serde(deserialize_with = "sighash_deser_numeric")]
        hash_type: TapSighashType,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct KpsInputSpendingIntermediary {
        internal_pubkey: XOnlyPublicKey,
        tweak: TapTweakHash,
        tweaked_privkey: SecretKey,
        sig_msg: String,
        sig_hash: TapSighash,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct KpsInputSpendingExpected {
        witness: Vec<String>,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct KpsInputSpending {
        given: KpsInputSpendingGiven,
        intermediary: KpsInputSpendingIntermediary,
        expected: KpsInputSpendingExpected,
        // auxiliary: KpsAuxiliary, //unused
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct KeyPathSpending {
        given: KpsGiven,
        intermediary: KpsIntermediary,
        input_spending: Vec<KpsInputSpending>,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct TestData {
        version: u64,
        key_path_spending: Vec<KeyPathSpending>,
        //script_pubkey: Vec<ScriptPubKey>, // unused
    }

    let json_str = include_str!("data/bip341_tests.json");
    let mut data =
        serde_json::from_str::<TestData>(json_str).expect("JSON was not well-formatted");

    assert_eq!(data.version, 1u64);
    let secp = &secp256k1::Secp256k1::new();
    let key_path = data.key_path_spending.remove(0);

    let raw_unsigned_tx = key_path.given.raw_unsigned_tx;
    let utxos = key_path
        .given
        .utxos_spent
        .into_iter()
        .map(|txo| TxOut { value: txo.value, script_pubkey: txo.script_pubkey })
        .collect::<Vec<_>>();

    // Test intermediary
    let mut cache = SighashCache::new(&raw_unsigned_tx);

    let expected = key_path.intermediary;
    // Compute all caches
    assert_eq!(expected.hash_amounts, cache.taproot_cache(&utxos).amounts);
    assert_eq!(expected.hash_outputs, cache.common_cache().outputs);
    assert_eq!(expected.hash_prevouts, cache.common_cache().prevouts);
    assert_eq!(expected.hash_script_pubkeys, cache.taproot_cache(&utxos).script_pubkeys);
    assert_eq!(expected.hash_sequences, cache.common_cache().sequences);

    for mut inp in key_path.input_spending {
        let tx_ind = inp.given.txin_index;
        let internal_priv_key = inp.given.internal_privkey;
        let merkle_root = inp.given.merkle_root;
        let hash_ty = inp.given.hash_type;

        let expected = inp.intermediary;
        let sig_str = inp.expected.witness.remove(0);
        let (expected_key_spend_sig, expected_hash_ty) = if sig_str.len() == 128 {
            (
                secp256k1::schnorr::Signature::from_str(&sig_str).unwrap(),
                TapSighashType::Default,
            )
        } else {
            let hash_ty = u8::from_str_radix(&sig_str[128..130], 16).unwrap();
            let hash_ty = TapSighashType::from_consensus_u8(hash_ty).unwrap();
            (secp256k1::schnorr::Signature::from_str(&sig_str[..128]).unwrap(), hash_ty)
        };

        // tests
        let keypair = secp256k1::Keypair::from_secret_key(secp, &internal_priv_key);
        let (internal_key, _parity) = XOnlyPublicKey::from_keypair(&keypair);
        let tweak = TapTweakHash::from_key_and_tweak(internal_key, merkle_root);
        let tweaked_keypair = keypair.add_xonly_tweak(secp, &tweak.to_scalar()).unwrap();
        let mut sig_msg = Vec::new();
        cache
            .taproot_encode_signing_data_to(
                &mut sig_msg,
                tx_ind,
                &Prevouts::All(&utxos),
                None,
                None,
                hash_ty,
            )
            .unwrap();
        let sighash = cache
            .taproot_signature_hash(tx_ind, &Prevouts::All(&utxos), None, None, hash_ty)
            .unwrap();

        let msg = secp256k1::Message::from(sighash);
        let key_spend_sig = secp.sign_schnorr_with_aux_rand(&msg, &tweaked_keypair, &[0u8; 32]);

        assert_eq!(expected.internal_pubkey, internal_key);
        assert_eq!(expected.tweak, tweak);
        assert_eq!(expected.sig_msg, sig_msg.to_lower_hex_string());
        assert_eq!(expected.sig_hash, sighash);
        assert_eq!(expected_hash_ty, hash_ty);
        assert_eq!(expected_key_spend_sig, key_spend_sig);

        let tweaked_priv_key = SecretKey::from_keypair(&tweaked_keypair);
        assert_eq!(expected.tweaked_privkey, tweaked_priv_key);
    }
}
