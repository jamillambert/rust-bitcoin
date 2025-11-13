// SPDX-License-Identifier: CC0-1.0

//! Bitcoin addresses (extension methods and re-exports).

use crate::crypto::key::{
    CompressedPublicKey, PublicKey as BtcPublicKey, XOnlyPublicKey as BtcXOnlyPublicKey,
};
use crate::network::{Network, NetworkKind};
use crate::script::witness_version::WitnessVersion as BtcWitnessVersion;
use crate::script::{
    self, PushBytesBuf, ScriptExt as _, ScriptPubKey, ScriptPubKeyBuf, ScriptPubKeyBufExt as _,
    ScriptPubKeyExt as _, WitnessScript, WitnessScriptExt as _, WitnessScriptSizeError,
};

#[rustfmt::skip]
#[doc(inline)]
pub use addresses::address::{
    Address,
    AddressData,
    AddressType,
    KnownHrp,
    NetworkChecked,
    NetworkUnchecked,
    NetworkValidation,
    NetworkValidationUnchecked,
    ToPubkeyHash,
    ToUntweakedPublicKey,
    ToWPubkeyHash,
};

/// Error types re-exported from the `addresses` crate.
pub mod error {
    pub use addresses::address::error::*;
}

#[doc(inline)]
pub use error::{FromScriptError, ParseError};

/// Extension methods for script-related address operations that depend on the `bitcoin` crate.
pub trait AddressScriptExt {
    /// Constructs an address from a `scriptPubKey` for the given network.
    fn from_script(
        script: &ScriptPubKey,
        network: Network,
    ) -> Result<Self, FromScriptError>
    where
        Self: Sized;

    /// Generates the script pubkey spending to this address.
    fn script_pubkey(&self) -> ScriptPubKeyBuf;

    /// Returns true if the address creates a particular script.
    fn matches_script_pubkey(&self, script: &ScriptPubKey) -> bool;

    /// Constructs a P2SH-P2WPKH address using a compressed public key.
    fn p2shwpkh(pk: CompressedPublicKey, network: impl Into<NetworkKind>) -> Self
    where
        Self: Sized;

    /// Constructs a P2SH-P2WSH address using a witness script.
    fn p2shwsh(
        witness_script: &WitnessScript,
        network: impl Into<NetworkKind>,
    ) -> Result<Self, WitnessScriptSizeError>
    where
        Self: Sized;
}

impl AddressScriptExt for Address {
    fn from_script(
        script: &ScriptPubKey,
        network: Network,
    ) -> Result<Self, FromScriptError> {
        if script.is_p2pkh() {
            let bytes: [u8; 20] =
                script.as_bytes()[3..23].try_into().expect("p2pkh script has a 20-byte hash");
            let hash = addresses::keys::PubkeyHash::from(bytes);
            Ok(Self::p2pkh(hash, NetworkKind::from(network)))
        } else if script.is_p2sh() {
            let bytes: [u8; 20] =
                script.as_bytes()[2..22].try_into().expect("p2sh script has a 20-byte hash");
            let hash = crate::script::ScriptHash::from_byte_array(bytes);
            Ok(Self::p2sh_from_hash(hash, NetworkKind::from(network)))
        } else if script.is_witness_program() {
            let version = script
                .witness_version()
                .expect("is_witness_program implies witness_version is Some");
            let prog = &script.as_bytes()[2..];
            // Build primitives witness program via addresses' public re-export.
            let v = addresses::primitives::script::witness_version::WitnessVersion::try_from(
                version.to_num(),
            )?;
            let program =
                addresses::primitives::script::witness_program::WitnessProgram::new(v, prog)?;
            Ok(Self::from_witness_program(program, KnownHrp::from(network)))
        } else {
            Err(FromScriptError::UnrecognizedScript)
        }
    }

    fn script_pubkey(&self) -> ScriptPubKeyBuf {
        if let Some(hash) = self.pubkey_hash() {
            let bytes = *hash.as_byte_array();
            let pkh = crate::key::PubkeyHash::from_byte_array(bytes);
            ScriptPubKeyBuf::new_p2pkh(pkh)
        } else if let Some(hash) = self.script_hash() {
            ScriptPubKeyBuf::new_p2sh(hash)
        } else if let Some(wp) = self.witness_program() {
            let ver_num = addresses::primitives::script::witness_version::WitnessVersion::to_num(
                wp.version(),
            );
            let version = BtcWitnessVersion::try_from(ver_num).expect("valid witness version");
            let prog_buf = PushBytesBuf::try_from(wp.program().to_vec())
                .expect("witness program fits pushbytes");
            script::new_witness_program_unchecked(version, prog_buf)
        } else {
            ScriptPubKeyBuf::new()
        }
    }

    fn matches_script_pubkey(&self, script: &ScriptPubKey) -> bool {
        if let Some(hash) = self.pubkey_hash() {
            return script.is_p2pkh() && &script.as_bytes()[3..23] == hash.as_byte_array();
        }
        if let Some(hash) = self.script_hash() {
            return script.is_p2sh() && &script.as_bytes()[2..22] == hash.as_byte_array();
        }
        if let Some(wp) = self.witness_program() {
            return script.is_witness_program() && &script.as_bytes()[2..] == wp.program();
        }
        false
    }

    fn p2shwpkh(pk: CompressedPublicKey, network: impl Into<NetworkKind>) -> Self {
        let builder = ScriptPubKey::builder().push_int_unchecked(0).push_slice(pk.wpubkey_hash());
        let script_hash = builder.as_script().script_hash().expect("script is less than 520 bytes");
        Self::p2sh_from_hash(script_hash, network)
    }

    fn p2shwsh(
        witness_script: &WitnessScript,
        network: impl Into<NetworkKind>,
    ) -> Result<Self, WitnessScriptSizeError> {
        let hash = witness_script.wscript_hash()?;
        let builder = ScriptPubKey::builder().push_int_unchecked(0).push_slice(hash);
        let script_hash = builder.as_script().script_hash().expect("script is less than 520 bytes");
        Ok(Self::p2sh_from_hash(script_hash, network))
    }
}

// Bridge traits so bitcoin's key types work with addresses constructors.
impl ToPubkeyHash for BtcPublicKey {
    fn to_pubkey_hash_bytes(&self) -> [u8; 20] { self.pubkey_hash().to_byte_array() }
}

impl ToWPubkeyHash for CompressedPublicKey {
    fn to_wpubkey_hash_bytes(&self) -> [u8; 20] { self.wpubkey_hash().to_byte_array() }
}

impl ToPubkeyHash for CompressedPublicKey {
    fn to_pubkey_hash_bytes(&self) -> [u8; 20] { self.wpubkey_hash().to_byte_array() }
}

impl ToUntweakedPublicKey for BtcXOnlyPublicKey {
    fn to_untweaked_public_key(self) -> addresses::keys::UntweakedPublicKey {
        let secp_x = self.into_inner();
        let keys_x = addresses::keys::XOnlyPublicKey::from(secp_x);
        addresses::keys::UntweakedPublicKey(keys_x)
    }
}
