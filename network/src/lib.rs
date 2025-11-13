// SPDX-License-Identifier: CC0-1.0

//! Bitcoin network identifiers and helpers.
//!
//! These primitives are shared across the `rust-bitcoin` stack. Most users
//! should access them via the `bitcoin` crate instead of depending on this
//! crate directly.

#![no_std]
#![warn(missing_docs)]
#![warn(deprecated_in_future)]
#![doc(test(attr(warn(unused))))]
#![allow(clippy::uninlined_format_args)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use core::fmt;

#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use core::str::FromStr;

#[cfg(feature = "serde")]
use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};

/// What kind of network we are on.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NetworkKind {
    /// The Bitcoin mainnet network.
    Main,
    /// Some kind of testnet network.
    Test,
}

impl NetworkKind {
    /// Returns true if this is real mainnet bitcoin.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn is_mainnet(&self) -> bool { *self == Self::Main }
}

impl From<Network> for NetworkKind {
    fn from(n: Network) -> Self {
        match n {
            Network::Bitcoin => Self::Main,
            Network::Testnet(_) | Network::Signet | Network::Regtest => Self::Test,
        }
    }
}

/// The testnet version to act on.
#[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Debug)]
#[non_exhaustive]
pub enum TestnetVersion {
    /// Testnet version 3.
    V3,
    /// Testnet version 4.
    V4,
}

/// The cryptocurrency network to act on.
#[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Clone, Hash, Debug)]
pub enum Network {
    /// Mainnet Bitcoin.
    Bitcoin,
    /// Bitcoin's testnet network.
    Testnet(TestnetVersion),
    /// Bitcoin's signet network.
    Signet,
    /// Bitcoin's regtest network.
    Regtest,
}

#[cfg(feature = "serde")]
impl Serialize for Network {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_display_str())
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Network {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct NetworkVisitor;

        impl Visitor<'_> for NetworkVisitor {
            type Value = Network;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a valid network identifier")
            }

            fn visit_str<E>(self, value: &str) -> Result<Network, E>
            where
                E: serde::de::Error,
            {
                Network::from_str(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(NetworkVisitor)
    }
}

impl Network {
    /// Converts a `Network` to its equivalent `bitcoind -chain` argument name.
    pub fn to_core_arg(self) -> &'static str {
        match self {
            Self::Bitcoin => "bitcoin",
            Self::Testnet(TestnetVersion::V3) => "testnet",
            Self::Testnet(TestnetVersion::V4) => "testnet4",
            Self::Signet => "signet",
            Self::Regtest => "regtest",
        }
    }

    /// Returns a string representation of the `Network` enum variant.
    const fn as_display_str(self) -> &'static str {
        match self {
            Self::Bitcoin => "bitcoin",
            Self::Testnet(TestnetVersion::V3) => "testnet",
            Self::Testnet(TestnetVersion::V4) => "testnet4",
            Self::Signet => "signet",
            Self::Regtest => "regtest",
        }
    }
}

#[cfg(feature = "serde")]
pub mod as_core_arg {
    //! Module for serialization/deserialization of network variants into/from Bitcoin Core values.
    #![allow(missing_docs)]

    use super::Network;

    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn serialize<S>(network: &Network, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(network.to_core_arg())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Network, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct NetworkVisitor;

        impl serde::de::Visitor<'_> for NetworkVisitor {
            type Value = Network;

            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
                Network::from_core_arg(s).map_err(|_| {
                    E::invalid_value(
                        serde::de::Unexpected::Str(s),
                        &"bitcoin network encoded as a string (either bitcoin, testnet, testnet4, signet or regtest)",
                    )
                })
            }

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(
                    formatter,
                    "bitcoin network encoded as a string (either bitcoin, testnet, testnet4, signet or regtest)"
                )
            }
        }

        deserializer.deserialize_str(NetworkVisitor)
    }
}

/// An error in parsing network string.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ParseNetworkError(String);

#[cfg(feature = "alloc")]
impl fmt::Display for ParseNetworkError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "failed to parse {} as network", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseNetworkError {}

#[cfg(feature = "alloc")]
impl FromStr for Network {
    type Err = ParseNetworkError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "bitcoin" => Ok(Self::Bitcoin),
            "testnet" => Ok(Self::Testnet(TestnetVersion::V3)),
            "testnet4" => Ok(Self::Testnet(TestnetVersion::V4)),
            "signet" => Ok(Self::Signet),
            "regtest" => Ok(Self::Regtest),
            _ => Err(ParseNetworkError(String::from(s))),
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_display_str())
    }
}

impl Network {
    /// Converts a `bitcoind -chain` argument name to its equivalent `Network`.
    #[cfg(feature = "alloc")]
    pub fn from_core_arg(core_arg: &str) -> Result<Self, ParseNetworkError> {
        let network = match core_arg {
            "bitcoin" => Self::Bitcoin,
            "testnet" => Self::Testnet(TestnetVersion::V3),
            "testnet4" => Self::Testnet(TestnetVersion::V4),
            "signet" => Self::Signet,
            "regtest" => Self::Regtest,
            _ => return Err(ParseNetworkError(String::from(core_arg))),
        };
        Ok(network)
    }
}
