// SPDX-License-Identifier: CC0-1.0

//! Taproot primitives.
//!
//! This module exposes low-level Taproot tagged hash types that are shared
//! across the rust-bitcoin ecosystem.

#[cfg(feature = "hex")]
use hashes::impl_hex_for_newtype;
use hashes::{hash_newtype, sha256t, sha256t_tag, HashEngine};

sha256t_tag! {
    /// Tagged hash domain for Taproot branch (node) hashes.
    pub struct TapBranchTag = hash_str("TapBranch");
}

hash_newtype! {
    /// Tagged hash used in Taproot trees.
    ///
    /// See BIP-0340 for tagging rules.
    #[repr(transparent)]
    pub struct TapNodeHash(sha256t::Hash<TapBranchTag>);
}

#[cfg(feature = "hex")]
impl_hex_for_newtype!(TapNodeHash);
#[cfg(feature = "serde")]
hashes::impl_serde_for_newtype!(TapNodeHash);

impl TapNodeHash {
    /// Computes branch hash given two hashes of the nodes underneath it.
    pub fn from_node_hashes(a: Self, b: Self) -> Self {
        let mut eng = sha256t::Hash::<TapBranchTag>::engine();
        if a < b {
            eng.input(a.as_ref());
            eng.input(b.as_ref());
        } else {
            eng.input(b.as_ref());
            eng.input(a.as_ref());
        }
        let inner = sha256t::Hash::<TapBranchTag>::from_engine(eng);
        Self::from_byte_array(inner.to_byte_array())
    }

    /// Assumes the given 32 byte array as hidden [`TapNodeHash`].
    pub fn assume_hidden(hash: [u8; 32]) -> Self { Self::from_byte_array(hash) }
}

sha256t_tag! {
    /// Tagged hash domain for Taproot tweak hashes used in key tweaking.
    pub struct TapTweakTag = hash_str("TapTweak");
}

hash_newtype! {
    /// Taproot-tagged hash with tag "TapTweak".
    ///
    /// This hash type is used while computing the tweaked public key as defined in BIP-0341.
    pub struct TapTweakHash(sha256t::Hash<TapTweakTag>);
}

#[cfg(feature = "hex")]
impl_hex_for_newtype!(TapTweakHash);
#[cfg(feature = "serde")]
hashes::impl_serde_for_newtype!(TapTweakHash);

/// Types that can be converted into the 32-byte input required for Taproot tweaks.
pub trait TapTweakKey {
    /// Returns the x-only public key bytes used when computing Taproot tweaks.
    fn tap_tweak_bytes(self) -> [u8; 32];
}

impl TapTweakKey for [u8; 32] {
    fn tap_tweak_bytes(self) -> [u8; 32] { self }
}

impl TapTweakKey for &[u8; 32] {
    fn tap_tweak_bytes(self) -> [u8; 32] { *self }
}

impl TapTweakHash {
    /// Constructs a new BIP-0341 `TapTweakHash` from a 32-byte x-only public key and optional Merkle root.
    ///
    /// Produces `H_taptweak(P || R)` where `P` is the 32-byte x-only public key and `R` is the Taproot Merkle root.
    pub fn from_bytes_and_merkle_root(
        xonly_pubkey: [u8; 32],
        merkle_root: Option<TapNodeHash>,
    ) -> Self {
        let mut eng = sha256t::Hash::<TapTweakTag>::engine();
        eng.input(&xonly_pubkey);
        if let Some(root) = merkle_root {
            eng.input(root.as_ref());
        }
        let inner = sha256t::Hash::<TapTweakTag>::from_engine(eng);
        Self::from_byte_array(inner.to_byte_array())
    }

    /// Constructs a new BIP-0341 `TapTweakHash` from any type that can supply the required x-only bytes.
    pub fn from_key_and_merkle_root<K: TapTweakKey>(
        key: K,
        merkle_root: Option<TapNodeHash>,
    ) -> Self {
        Self::from_bytes_and_merkle_root(key.tap_tweak_bytes(), merkle_root)
    }
}
