// SPDX-License-Identifier: CC0-1.0

//! Bitcoin addresses (core, no script construction helpers).
//!
//! This module defines the `Address` type, parsing/formatting, network validation,
//! and constructors that don't require Bitcoin-specific script builders.

pub mod error;

use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::String;
use core::fmt;
use core::marker::PhantomData;
use core::str::FromStr;

use bech32::primitives::gf32::Fe32;
use bech32::primitives::hrp::Hrp;
use hashes::{hash160, HashEngine};
use internals::array::ArrayExt;
use keys::{PublicKey, TweakedPublicKey, XOnlyPublicKey};
use bitcoin_network::{Network, NetworkKind};
use primitives::script::witness_program::WitnessProgram;
use primitives::script::witness_version::WitnessVersion;
use primitives::script::{
    RedeemScriptSizeError, Script, ScriptHash, ScriptHashableTag, WScriptHash, WitnessScript,
    WitnessScriptSizeError,
};
use primitives::taproot::TapNodeHash;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::error::{
    Base58Error, Bech32Error, FromScriptError, InvalidBase58PayloadLengthError,
    InvalidLegacyPrefixError, LegacyAddressTooLongError, NetworkValidationError, ParseBech32Error,
    ParseError, UnknownAddressTypeError, UnknownHrpError,
};

/// The different types of addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum AddressType {
    /// Pay to pubkey hash.
    P2pkh,
    /// Pay to script hash.
    P2sh,
    /// Pay to witness pubkey hash.
    P2wpkh,
    /// Pay to witness script hash.
    P2wsh,
    /// Pay to Taproot.
    P2tr,
    /// Pay to anchor.
    P2a,
}

impl fmt::Display for AddressType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match *self {
            Self::P2pkh => "p2pkh",
            Self::P2sh => "p2sh",
            Self::P2wpkh => "p2wpkh",
            Self::P2wsh => "p2wsh",
            Self::P2tr => "p2tr",
            Self::P2a => "p2a",
        })
    }
}

impl FromStr for AddressType {
    type Err = UnknownAddressTypeError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "p2pkh" => Ok(Self::P2pkh),
            "p2sh" => Ok(Self::P2sh),
            "p2wpkh" => Ok(Self::P2wpkh),
            "p2wsh" => Ok(Self::P2wsh),
            "p2tr" => Ok(Self::P2tr),
            "p2a" => Ok(Self::P2a),
            _ => Err(UnknownAddressTypeError(s.to_owned())),
        }
    }
}

mod sealed {
    pub trait NetworkValidation {}
    impl NetworkValidation for super::NetworkChecked {}
    impl NetworkValidation for super::NetworkUnchecked {}

    pub trait NetworkValidationUnchecked {}
    impl NetworkValidationUnchecked for super::NetworkUnchecked {}
}

/// Marker of status of address's network validation.
pub trait NetworkValidation:
    sealed::NetworkValidation + Sync + Send + Sized + Unpin + Copy
{
    /// Indicates whether this `NetworkValidation` is `NetworkChecked` or not.
    const IS_CHECKED: bool;
}

/// Marker trait for `FromStr` and `serde::Deserialize`.
pub trait NetworkValidationUnchecked:
    NetworkValidation + sealed::NetworkValidationUnchecked + Sync + Send + Sized + Unpin
{
}

/// Marker that address's network has been successfully validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum NetworkChecked {}

/// Marker that address's network has not yet been validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum NetworkUnchecked {}

impl NetworkValidation for NetworkChecked {
    const IS_CHECKED: bool = true;
}
impl NetworkValidation for NetworkUnchecked {
    const IS_CHECKED: bool = false;
}

impl NetworkValidationUnchecked for NetworkUnchecked {}

/// The inner representation of an address, without the network validation tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum AddressInner {
    P2pkh { hash: keys::PubkeyHash, network: NetworkKind },
    P2sh { hash: ScriptHash, network: NetworkKind },
    Segwit { program: WitnessProgram, hrp: KnownHrp },
}

/// Formats bech32 as upper case if alternate formatting is chosen (`{:#}`).
impl fmt::Display for AddressInner {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        use AddressInner::*;
        match self {
            P2pkh { hash, network } => {
                let mut prefixed = [0; 21];
                prefixed[0] = match network {
                    NetworkKind::Main => crate::constants::PUBKEY_ADDRESS_PREFIX_MAIN,
                    NetworkKind::Test => crate::constants::PUBKEY_ADDRESS_PREFIX_TEST,
                };
                prefixed[1..].copy_from_slice(hash.as_byte_array());
                base58::encode_check_to_fmt(fmt, &prefixed[..])
            }
            P2sh { hash, network } => {
                let mut prefixed = [0; 21];
                prefixed[0] = match network {
                    NetworkKind::Main => crate::constants::SCRIPT_ADDRESS_PREFIX_MAIN,
                    NetworkKind::Test => crate::constants::SCRIPT_ADDRESS_PREFIX_TEST,
                };
                prefixed[1..].copy_from_slice(hash.as_byte_array());
                base58::encode_check_to_fmt(fmt, &prefixed[..])
            }
            Segwit { program, hrp } => {
                let hrp = hrp.to_hrp();
                let version = Fe32::try_from(program.version().to_num())
                    .expect("version nums 0-16 are valid fe32 values");
                let program = program.program();

                if fmt.alternate() {
                    bech32::segwit::encode_upper_to_fmt_unchecked(fmt, hrp, version, program)
                } else {
                    bech32::segwit::encode_lower_to_fmt_unchecked(fmt, hrp, version, program)
                }
            }
        }
    }
}

/// Known bech32 human-readable parts.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum KnownHrp {
    /// The main Bitcoin network.
    Mainnet,
    /// The test networks, testnet (testnet3), testnet4, and signet.
    Testnets,
    /// The regtest network.
    Regtest,
}

impl KnownHrp {
    /// Constructs a new [`KnownHrp`] from [`Network`].
    fn from_network(network: Network) -> Self {
        match network {
            Network::Bitcoin => Self::Mainnet,
            Network::Testnet(_) | Network::Signet => Self::Testnets,
            Network::Regtest => Self::Regtest,
        }
    }

    /// Constructs a new [`KnownHrp`] from a [`bech32::Hrp`].
    fn from_hrp(hrp: Hrp) -> Result<Self, UnknownHrpError> {
        if hrp == bech32::hrp::BC {
            Ok(Self::Mainnet)
        } else if hrp.is_valid_on_testnet() || hrp.is_valid_on_signet() {
            Ok(Self::Testnets)
        } else if hrp == bech32::hrp::BCRT {
            Ok(Self::Regtest)
        } else {
            Err(UnknownHrpError(hrp.to_lowercase()))
        }
    }

    /// Converts, infallibly a known HRP to a [`bech32::Hrp`].
    fn to_hrp(self) -> Hrp {
        match self {
            Self::Mainnet => bech32::hrp::BC,
            Self::Testnets => bech32::hrp::TB,
            Self::Regtest => bech32::hrp::BCRT,
        }
    }
}

impl From<Network> for KnownHrp {
    fn from(n: Network) -> Self { Self::from_network(n) }
}

impl From<KnownHrp> for NetworkKind {
    fn from(hrp: KnownHrp) -> Self {
        match hrp {
            KnownHrp::Mainnet => Self::Main,
            KnownHrp::Testnets => Self::Test,
            KnownHrp::Regtest => Self::Test,
        }
    }
}

/// The data encoded by an `Address`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum AddressData {
    /// Data encoded by a P2PKH address.
    P2pkh {
        /// The 20-byte HASH160 of the compressed public key.
        pubkey_hash: keys::PubkeyHash,
    },
    /// Data encoded by a P2SH address.
    P2sh {
        /// The 20-byte HASH160 of the redeem script.
        script_hash: ScriptHash,
    },
    /// Data encoded by a SegWit address.
    Segwit {
        /// The witness program (version and pushed program bytes).
        witness_program: WitnessProgram,
    },
}

/// Trait for types that can produce a P2PKH (HASH160) of a public key.
pub trait ToPubkeyHash {
    /// Returns the 20-byte HASH160(pubkey) for this input.
    fn to_pubkey_hash_bytes(&self) -> [u8; 20];
}

impl ToPubkeyHash for keys::PubkeyHash {
    fn to_pubkey_hash_bytes(&self) -> [u8; 20] { self.to_byte_array() }
}

impl ToPubkeyHash for [u8; 20] {
    fn to_pubkey_hash_bytes(&self) -> [u8; 20] { *self }
}

impl ToPubkeyHash for hashes::hash160::Hash {
    fn to_pubkey_hash_bytes(&self) -> [u8; 20] { self.to_byte_array() }
}

impl ToPubkeyHash for PublicKey {
    fn to_pubkey_hash_bytes(&self) -> [u8; 20] { self.pubkey_hash().to_byte_array() }
}

/// Trait for types that can produce a P2WPKH 20-byte witness pubkey hash.
pub trait ToWPubkeyHash {
    /// Returns the 20-byte HASH160(compressed_pubkey) for this input.
    fn to_wpubkey_hash_bytes(&self) -> [u8; 20];
}

impl ToWPubkeyHash for keys::WPubkeyHash {
    fn to_wpubkey_hash_bytes(&self) -> [u8; 20] { *self.as_ref() }
}

impl ToWPubkeyHash for [u8; 20] {
    fn to_wpubkey_hash_bytes(&self) -> [u8; 20] { *self }
}

impl ToWPubkeyHash for hashes::hash160::Hash {
    fn to_wpubkey_hash_bytes(&self) -> [u8; 20] { self.to_byte_array() }
}

impl ToWPubkeyHash for keys::CompressedPublicKey {
    fn to_wpubkey_hash_bytes(&self) -> [u8; 20] { self.wpubkey_hash().to_byte_array() }
}

/// Trait for types convertible to an untweaked x-only public key.
pub trait ToUntweakedPublicKey {
    /// Converts into `keys::UntweakedPublicKey`.
    fn to_untweaked_public_key(self) -> keys::UntweakedPublicKey;
}

impl ToUntweakedPublicKey for keys::UntweakedPublicKey {
    fn to_untweaked_public_key(self) -> keys::UntweakedPublicKey { self }
}

impl ToUntweakedPublicKey for keys::XOnlyPublicKey {
    fn to_untweaked_public_key(self) -> keys::UntweakedPublicKey { keys::UntweakedPublicKey(self) }
}

internals::transparent_newtype! {
    /// A Bitcoin address.
    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Address<V = NetworkChecked>(PhantomData<V>, AddressInner)
    where
        V: NetworkValidation;

    impl<V> Address<V> { fn from_inner_ref(inner: &_) -> &Self; }
}

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "serde")]
struct DisplayUnchecked<'a, N: NetworkValidation>(&'a Address<N>);

#[cfg(feature = "serde")]
impl<N: NetworkValidation> fmt::Display for DisplayUnchecked<'_, N> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0.inner(), fmt)
    }
}

#[cfg(feature = "serde")]
impl<'de, U: NetworkValidationUnchecked> serde::Deserialize<'de> for Address<U> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        use core::fmt::Formatter;

        struct Visitor<U>(PhantomData<U>);
        impl<U> serde::de::Visitor<'_> for Visitor<U>
        where
            U: NetworkValidationUnchecked + NetworkValidation,
            Address<U>: FromStr,
        {
            type Value = Address<U>;

            fn expecting(&self, f: &mut Formatter) -> core::fmt::Result {
                f.write_str("A Bitcoin address")
            }

            fn visit_str<E>(self, v: &str) -> core::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let address = v.parse::<Address<NetworkUnchecked>>().map_err(E::custom)?;
                Ok(Address::from_inner(address.to_inner()))
            }
        }

        deserializer.deserialize_str(Visitor(PhantomData::<U>))
    }
}

#[cfg(feature = "serde")]
impl<V: NetworkValidation> serde::Serialize for Address<V> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(&DisplayUnchecked(self))
    }
}

/// Methods on `Address` that can be called on both checked and unchecked variants.
impl<V: NetworkValidation> Address<V> {
    fn from_inner(inner: AddressInner) -> Self { Self(PhantomData, inner) }
    fn to_inner(self) -> AddressInner { self.1 }
    fn inner(&self) -> &AddressInner { &self.1 }

    /// Returns a reference to the address as if it was unchecked.
    pub fn as_unchecked(&self) -> &Address<NetworkUnchecked> {
        Address::from_inner_ref(self.inner())
    }
    /// Marks the network of this address as unchecked.
    pub fn to_unchecked(self) -> Address<NetworkUnchecked> { Address::from_inner(self.to_inner()) }

    /// Returns the `NetworkKind` of this address.
    pub fn network_kind(&self) -> NetworkKind {
        use AddressInner::*;
        match *self.inner() {
            P2pkh { network, .. } | P2sh { network, .. } => network,
            Segwit { hrp, .. } => NetworkKind::from(hrp),
        }
    }
}

/// Methods and functions that can be called only on `Address<NetworkChecked>`.
impl Address {
    /// Constructs a new pay-to-public-key-hash (P2PKH) address from a public key hash.
    #[inline]
    pub fn p2pkh(pk: impl ToPubkeyHash, network: impl Into<NetworkKind>) -> Self {
        let hash = keys::PubkeyHash::from(pk.to_pubkey_hash_bytes());
        Self::from_inner(AddressInner::P2pkh { hash, network: network.into() })
    }

    /// Constructs a new pay-to-script-hash (P2SH) address from a script.
    #[inline]
    pub fn p2sh<T: ScriptHashableTag>(
        redeem_script: &Script<T>,
        network: impl Into<NetworkKind>,
    ) -> Result<Self, RedeemScriptSizeError> {
        let hash = ScriptHash::from_script(redeem_script)?;
        Ok(Self::p2sh_from_hash(hash, network))
    }

    /// Constructs a new pay-to-script-hash (P2SH) address from a script hash.
    pub fn p2sh_from_hash(hash: ScriptHash, network: impl Into<NetworkKind>) -> Self {
        Self::from_inner(AddressInner::P2sh { hash, network: network.into() })
    }

    /// Constructs a new pay-to-witness-public-key-hash (P2WPKH) address from a compressed public key.
    pub fn p2wpkh(pk: impl ToWPubkeyHash, hrp: impl Into<KnownHrp>) -> Self {
        let program = WitnessProgram::p2wpkh_from_hash(pk.to_wpubkey_hash_bytes());
        Self::from_witness_program(program, hrp)
    }

    /// Constructs a new pay-to-witness-script-hash (P2WSH) address from a witness script.
    pub fn p2wsh(
        witness_script: &WitnessScript,
        hrp: impl Into<KnownHrp>,
    ) -> Result<Self, WitnessScriptSizeError> {
        let program = WitnessProgram::p2wsh(witness_script)?;
        Ok(Self::from_witness_program(program, hrp))
    }

    /// Constructs a new pay-to-witness-script-hash (P2WSH) address from a witness script hash.
    pub fn p2wsh_from_hash(hash: WScriptHash, hrp: impl Into<KnownHrp>) -> Self {
        let program = WitnessProgram::p2wsh_from_hash(hash.to_byte_array());
        Self::from_witness_program(program, hrp)
    }

    /// Constructs a new pay-to-Taproot (P2TR) address from an untweaked key.
    pub fn p2tr<C: keys::Verification, K: ToUntweakedPublicKey>(
        secp: &keys::Secp256k1<C>,
        internal_key: K,
        merkle_root: Option<TapNodeHash>,
        hrp: impl Into<KnownHrp>,
    ) -> Self {
        let internal_key = internal_key.to_untweaked_public_key();
        let (output_key, _parity) = keys::TapTweak::tap_tweak(internal_key, secp, merkle_root);
        let pubkey = output_key.as_x_only_public_key().serialize();
        let program = WitnessProgram::new(WitnessVersion::V1, &pubkey).expect("valid v1 program");
        Self::from_witness_program(program, hrp)
    }

    /// Constructs a new pay-to-Taproot (P2TR) address from a pre-tweaked output key.
    pub fn p2tr_tweaked(output_key: TweakedPublicKey, hrp: impl Into<KnownHrp>) -> Self {
        let pubkey = output_key.as_x_only_public_key().serialize();
        let program = WitnessProgram::new(WitnessVersion::V1, &pubkey).expect("valid v1 program");
        Self::from_witness_program(program, hrp)
    }

    /// Constructs a new address from an arbitrary `WitnessProgram`.
    pub fn from_witness_program(program: WitnessProgram, hrp: impl Into<KnownHrp>) -> Self {
        let inner = AddressInner::Segwit { program, hrp: hrp.into() };
        Self::from_inner(inner)
    }

    /// Gets the address type of the address.
    #[inline]
    pub fn address_type(&self) -> Option<AddressType> {
        match *self.inner() {
            AddressInner::P2pkh { .. } => Some(AddressType::P2pkh),
            AddressInner::P2sh { .. } => Some(AddressType::P2sh),
            AddressInner::Segwit { ref program, .. } =>
                if program.is_p2wpkh() {
                    Some(AddressType::P2wpkh)
                } else if program.is_p2wsh() {
                    Some(AddressType::P2wsh)
                } else if program.is_p2tr() {
                    Some(AddressType::P2tr)
                } else if program.is_p2a() {
                    Some(AddressType::P2a)
                } else {
                    None
                },
        }
    }

    /// Gets the address data from this address.
    pub fn to_address_data(self) -> AddressData {
        use AddressData::*;
        match *self.inner() {
            AddressInner::P2pkh { hash, .. } => P2pkh { pubkey_hash: hash },
            AddressInner::P2sh { hash, .. } => P2sh { script_hash: hash },
            AddressInner::Segwit { program, .. } => Segwit { witness_program: program },
        }
    }

    /// Gets the pubkey hash for this address if this is a P2PKH address.
    pub fn pubkey_hash(&self) -> Option<keys::PubkeyHash> {
        match *self.inner() {
            AddressInner::P2pkh { hash, .. } => Some(hash),
            _ => None,
        }
    }

    /// Gets the script hash for this address if this is a P2SH address.
    pub fn script_hash(&self) -> Option<ScriptHash> {
        match *self.inner() {
            AddressInner::P2sh { hash, .. } => Some(hash),
            _ => None,
        }
    }

    /// Gets the witness program for this address if this is a SegWit address.
    pub fn witness_program(&self) -> Option<WitnessProgram> {
        match *self.inner() {
            AddressInner::Segwit { program, .. } => Some(program),
            _ => None,
        }
    }

    /// Checks if the address is standard to spend from (not for senders).
    pub fn is_spend_standard(&self) -> bool { self.address_type().is_some() }

    /// Constructs a new URI string `bitcoin:ADDRESS` optimized for QR codes.
    pub fn to_qr_uri(self) -> String { format!("bitcoin:{:#}", self) }

    /// Returns true if the given pubkey is directly related to the address payload.
    pub fn is_related_to_pubkey(&self, pubkey: PublicKey) -> bool {
        let pubkey_hash = pubkey.pubkey_hash();
        let payload = self.payload_as_bytes();
        let xonly_pubkey = XOnlyPublicKey::from(pubkey.inner);

        (*pubkey_hash.as_byte_array() == *payload)
            || (xonly_pubkey.serialize() == *payload)
            || (*segwit_redeem_hash(pubkey_hash).as_byte_array() == *payload)
    }

    /// Returns true if the supplied xonly public key can be used to derive the address.
    pub fn is_related_to_xonly_pubkey(&self, xonly_pubkey: XOnlyPublicKey) -> bool {
        xonly_pubkey.serialize() == *self.payload_as_bytes()
    }

    /// Returns the payload for this address (hash or witness program bytes).
    fn payload_as_bytes(&self) -> &[u8] {
        match *self.inner() {
            AddressInner::P2sh { ref hash, .. } => hash.as_ref(),
            AddressInner::P2pkh { ref hash, .. } => hash.as_byte_array(),
            AddressInner::Segwit { ref program, .. } => program.program(),
        }
    }
}

/// Methods that can be called only on `Address<NetworkUnchecked>`.
impl Address<NetworkUnchecked> {
    /// Returns a reference to the checked address. Dangerous if not actually valid.
    pub fn assume_checked_ref(&self) -> &Address { Address::from_inner_ref(self.inner()) }

    /// Is this address valid for the given network.
    pub fn is_valid_for_network(&self, n: Network) -> bool {
        use AddressInner::*;
        match *self.inner() {
            P2pkh { ref network, .. } | P2sh { ref network, .. } =>
                *network == NetworkKind::from(n),
            Segwit { ref hrp, .. } => *hrp == KnownHrp::from_network(n),
        }
    }

    /// Checks whether network of this address is as required.
    pub fn require_network(self, required: Network) -> Result<Address, ParseError> {
        if self.is_valid_for_network(required) {
            Ok(self.assume_checked())
        } else {
            Err(NetworkValidationError { required, address: self }.into())
        }
    }

    /// Marks, without any additional checks, network of this address as checked.
    pub fn assume_checked(self) -> Address { Address::from_inner(self.to_inner()) }

    /// Parses a bech32 Address string.
    pub fn from_bech32_str(s: &str) -> Result<Self, Bech32Error> {
        let (hrp, witness_version, data) =
            bech32::segwit::decode(s).map_err(|e| Bech32Error::ParseBech32(ParseBech32Error(e)))?;
        let version = WitnessVersion::try_from(witness_version.to_u8())?;
        let program = WitnessProgram::new(version, &data)
            .expect("bech32 guarantees valid program length for witness");
        let hrp = KnownHrp::from_hrp(hrp)?;
        Ok(Self::from_inner(AddressInner::Segwit { program, hrp }))
    }

    /// Parses a base58 Address string.
    pub fn from_base58_str(s: &str) -> Result<Self, Base58Error> {
        if s.len() > 50 {
            return Err(LegacyAddressTooLongError { length: s.len() }.into());
        }
        let data = base58::decode_check(s)?;
        let data: &[u8; 21] = (&*data)
            .try_into()
            .map_err(|_| InvalidBase58PayloadLengthError { length: data.len() })?;

        let (prefix, &data) = data.split_first();

        let inner = match *prefix {
            crate::constants::PUBKEY_ADDRESS_PREFIX_MAIN => {
                let hash = keys::PubkeyHash::from(data);
                AddressInner::P2pkh { hash, network: NetworkKind::Main }
            }
            crate::constants::PUBKEY_ADDRESS_PREFIX_TEST => {
                let hash = keys::PubkeyHash::from(data);
                AddressInner::P2pkh { hash, network: NetworkKind::Test }
            }
            crate::constants::SCRIPT_ADDRESS_PREFIX_MAIN => {
                let hash = ScriptHash::from_byte_array(data);
                AddressInner::P2sh { hash, network: NetworkKind::Main }
            }
            crate::constants::SCRIPT_ADDRESS_PREFIX_TEST => {
                let hash = ScriptHash::from_byte_array(data);
                AddressInner::P2sh { hash, network: NetworkKind::Test }
            }
            invalid => return Err(InvalidLegacyPrefixError { invalid }.into()),
        };

        Ok(Self::from_inner(inner))
    }
}

// Alternate formatting `{:#}` returns an uppercase version of bech32 addresses for QR codes.
impl fmt::Display for Address {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self.inner(), fmt) }
}

impl<V: NetworkValidation> fmt::Debug for Address<V> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if V::IS_CHECKED {
            fmt::Display::fmt(&self.inner(), f)
        } else {
            write!(f, "Address<NetworkUnchecked>(")?;
            fmt::Display::fmt(&self.inner(), f)?;
            write!(f, ")")
        }
    }
}

impl<U: NetworkValidationUnchecked> FromStr for Address<U> {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, ParseError> {
        if ["bc1", "bcrt1", "tb1"].iter().any(|&prefix| s.to_lowercase().starts_with(prefix)) {
            let address = Address::from_bech32_str(s)?;
            Ok(Self::from_inner(address.to_inner()))
        } else if ["1", "2", "3", "m", "n"].iter().any(|&prefix| s.starts_with(prefix)) {
            let address = Address::from_base58_str(s)?;
            Ok(Self::from_inner(address.to_inner()))
        } else {
            let hrp = match s.rfind('1') {
                Some(pos) => &s[..pos],
                None => s,
            };
            Err(UnknownHrpError(hrp.to_owned()).into())
        }
    }
}

/// Convert a byte array of a pubkey hash into a SegWit redeem hash
fn segwit_redeem_hash(pubkey_hash: keys::PubkeyHash) -> hash160::Hash {
    let mut sha_engine = hash160::Hash::engine();
    sha_engine.input(&[0, 20]);
    sha_engine.input(pubkey_hash.as_byte_array());
    hash160::Hash::from_engine(sha_engine)
}
