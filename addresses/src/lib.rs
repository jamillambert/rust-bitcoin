// SPDX-License-Identifier: CC0-1.0

//! Bitcoin Addresses
//!
//! Bitcoin addresses do not appear on chain; rather, they are conventions used by Bitcoin (wallet)
//! software to communicate where coins should be sent and are based on the output type e.g., P2WPKH.
//!
//! This crate can be used in a no-std environment but requires an allocator.
//!
//! ref: <https://sprovoost.nl/2022/11/10/what-is-a-bitcoin-address/>

// NB: This crate is empty if `alloc` is not enabled.
#![cfg(feature = "alloc")]
#![no_std]
// Experimental features we need.
#![doc(test(attr(warn(unused))))]
// Coding conventions.
#![warn(deprecated_in_future)]
#![warn(missing_docs)]
// Exclude lints we don't think are valuable.
#![allow(clippy::needless_question_mark)] // https://github.com/rust-bitcoin/rust-bitcoin/pull/2134
#![allow(clippy::manual_range_contains)] // More readable than clippy's format.
#![allow(clippy::uninlined_format_args)] // Allow `format!("{}", x)` instead of enforcing `format!("{x}")`

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

/// Address-related constants.
pub mod constants {
    /// Legacy Base58 address version byte for mainnet P2PKH (0x00).
    pub const PUBKEY_ADDRESS_PREFIX_MAIN: u8 = 0;
    /// Legacy Base58 address version byte for mainnet P2SH (0x05).
    pub const SCRIPT_ADDRESS_PREFIX_MAIN: u8 = 5;
    /// Legacy Base58 address version byte for testnets P2PKH (0x6f).
    pub const PUBKEY_ADDRESS_PREFIX_TEST: u8 = 111;
    /// Legacy Base58 address version byte for testnets P2SH (0xc4).
    pub const SCRIPT_ADDRESS_PREFIX_TEST: u8 = 196;
}

pub mod address;

#[rustfmt::skip]
pub use {
	keys,
	primitives,
};

#[doc(inline)]
pub use address::error::*;
#[doc(inline)]
pub use address::{Address, AddressType, KnownHrp};
