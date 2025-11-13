// SPDX-License-Identifier: CC0-1.0

//! Bitcoin keys for cross-crate use.
//!
//! Minimal subset to support `addresses` without depending on `bitcoin`.

#![cfg_attr(not(feature = "std"), no_std)]
#![doc(test(attr(warn(unused))))]
#![warn(deprecated_in_future)]
#![warn(missing_docs)]
#![allow(clippy::uninlined_format_args)]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use core::fmt;

use hashes::hash160;
pub use secp256k1::{
    constants, Keypair, Parity, PublicKey as SecpPublicKey, Secp256k1, Verification,
    XOnlyPublicKey as SecpXOnlyPublicKey,
};

/// 20-byte pubkey hash (HASH160)
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct PubkeyHash(hash160::Hash);

impl PubkeyHash {
    /// Returns inner bytes
    pub fn to_byte_array(self) -> [u8; 20] { self.0.to_byte_array() }
    /// Returns reference to inner bytes
    pub fn as_byte_array(&self) -> &[u8; 20] { self.0.as_byte_array() }
}

impl From<hash160::Hash> for PubkeyHash {
    fn from(h: hash160::Hash) -> Self { Self(h) }
}

impl From<[u8; 20]> for PubkeyHash {
    fn from(bytes: [u8; 20]) -> Self { Self(hash160::Hash::from_byte_array(bytes)) }
}

impl AsRef<[u8; 20]> for PubkeyHash {
    fn as_ref(&self) -> &[u8; 20] { self.0.as_byte_array() }
}

/// 20-byte witness pubkey hash (alias of PubkeyHash)
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct WPubkeyHash(hash160::Hash);

impl WPubkeyHash {
    /// Returns inner bytes
    pub fn to_byte_array(self) -> [u8; 20] { self.0.to_byte_array() }
}

impl From<hash160::Hash> for WPubkeyHash {
    fn from(h: hash160::Hash) -> Self { Self(h) }
}

impl AsRef<[u8; 20]> for WPubkeyHash {
    fn as_ref(&self) -> &[u8; 20] { self.0.as_byte_array() }
}

/// An x-only public key used for BIP-0340 signatures.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct XOnlyPublicKey(pub SecpXOnlyPublicKey);

impl XOnlyPublicKey {
    /// Serializes the x-only public key (32 bytes).
    pub fn serialize(&self) -> [u8; constants::SCHNORR_PUBLIC_KEY_SIZE] { self.0.serialize() }
}

impl From<SecpXOnlyPublicKey> for XOnlyPublicKey {
    fn from(pk: SecpXOnlyPublicKey) -> Self { Self(pk) }
}

impl From<SecpPublicKey> for XOnlyPublicKey {
    fn from(pk: SecpPublicKey) -> Self { Self(pk.into()) }
}

impl fmt::LowerHex for XOnlyPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::LowerHex::fmt(&self.0, f) }
}

/// An ECDSA public key; may be compressed or uncompressed.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey {
    /// Whether this public key should be serialized as compressed.
    pub compressed: bool,
    /// Inner secp256k1 key.
    pub inner: SecpPublicKey,
}

impl PublicKey {
    /// Constructs a compressed public key.
    pub fn new(key: impl Into<SecpPublicKey>) -> Self {
        Self { compressed: true, inner: key.into() }
    }
    /// Constructs an uncompressed public key.
    pub fn new_uncompressed(key: impl Into<SecpPublicKey>) -> Self {
        Self { compressed: false, inner: key.into() }
    }

    fn with_serialized<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        if self.compressed {
            f(&self.inner.serialize())
        } else {
            f(&self.inner.serialize_uncompressed())
        }
    }

    /// Returns HASH160 of the serialized public key.
    pub fn pubkey_hash(&self) -> PubkeyHash {
        PubkeyHash(self.with_serialized(hash160::Hash::hash))
    }

    /// Returns HASH160 of the compressed pubkey (error if uncompressed).
    pub fn wpubkey_hash(&self) -> Result<WPubkeyHash, UncompressedPublicKeyError> {
        if self.compressed {
            Ok(WPubkeyHash::from(hash160::Hash::hash(&self.inner.serialize())))
        } else {
            Err(UncompressedPublicKeyError)
        }
    }
}

/// Error returned when an operation requires a compressed public key but an uncompressed one was provided.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct UncompressedPublicKeyError;

/// A compressed public key wrapper.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CompressedPublicKey(pub SecpPublicKey);

impl TryFrom<PublicKey> for CompressedPublicKey {
    type Error = UncompressedPublicKeyError;
    fn try_from(pk: PublicKey) -> Result<Self, Self::Error> {
        if pk.compressed {
            Ok(Self(pk.inner))
        } else {
            Err(UncompressedPublicKeyError)
        }
    }
}

impl CompressedPublicKey {
    /// Returns HASH160 of the compressed pubkey.
    pub fn wpubkey_hash(&self) -> WPubkeyHash {
        WPubkeyHash::from(hash160::Hash::hash(&self.0.serialize()))
    }
}

/// A taproot untweaked key.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UntweakedPublicKey(pub XOnlyPublicKey);

/// A taproot tweaked output key.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TweakedPublicKey(pub XOnlyPublicKey);

impl TweakedPublicKey {
    /// Access as x-only pubkey.
    pub fn as_x_only_public_key(&self) -> XOnlyPublicKey { self.0 }
}

/// Trait to perform tap tweak operation on untweaked keys.
pub trait TapTweak {
    /// Tweaks the key with an optional merkle root; returns tweaked key and its parity.
    fn tap_tweak<C: Verification>(
        self,
        secp: &Secp256k1<C>,
        merkle_root: Option<primitives::taproot::TapNodeHash>,
    ) -> (TweakedPublicKey, Parity);
}

impl<K: Into<UntweakedPublicKey>> TapTweak for K {
    fn tap_tweak<C: Verification>(
        self,
        secp: &Secp256k1<C>,
        merkle_root: Option<primitives::taproot::TapNodeHash>,
    ) -> (TweakedPublicKey, Parity) {
        let internal: UntweakedPublicKey = self.into();
        let xonly = internal.0 .0;
        let t = primitives::taproot::TapTweakHash::from_bytes_and_merkle_root(
            xonly.serialize(),
            merkle_root,
        );
        let tweak = secp256k1::Scalar::from_be_bytes(t.to_byte_array())
            .expect("hash value greater than curve order");
        let (tweaked, parity) = xonly.add_tweak(secp, &tweak).expect("valid tap tweak");
        (TweakedPublicKey(XOnlyPublicKey(tweaked)), parity)
    }
}
