// SPDX-License-Identifier: CC0-1.0

use bitcoin::psbt::Error;
use bitcoin::Psbt;
use hex::FromHex;

fn hex_psbt(s: &str) -> Result<Psbt, Error> {
    let r = Vec::from_hex(s);
    match r {
        Err(_e) => panic!("unable to parse hex string {}", s),
        Ok(v) => Psbt::deserialize(&v),
    }
}

// PSBTs taken from BIP 174 test vectors.
#[test]
fn combine_psbts() {
    let mut psbt1 = hex_psbt(include_str!("data/psbt1.hex")).unwrap();
    let psbt2 = hex_psbt(include_str!("data/psbt2.hex")).unwrap();
    let psbt_combined = hex_psbt(include_str!("data/psbt2.hex")).unwrap();

    psbt1.combine(psbt2).expect("psbt combine to succeed");
    assert_eq!(psbt1, psbt_combined);
}

#[test]
fn combine_psbts_commutative() {
    let mut psbt1 = hex_psbt(include_str!("data/psbt1.hex")).unwrap();
    let mut psbt2 = hex_psbt(include_str!("data/psbt2.hex")).unwrap();

    let psbt1_clone = psbt1.clone();
    let psbt2_clone = psbt2.clone();

    psbt1.combine(psbt2_clone).expect("psbt1 combine to succeed");
    psbt2.combine(psbt1_clone).expect("psbt2 combine to succeed");

    assert_eq!(psbt1, psbt2);
}
