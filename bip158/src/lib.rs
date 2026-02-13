// SPDX-License-Identifier: CC0-1.0

//! Compact Block Filters for Light Clients (BIP-0158)
//!
//! This module implements [BIP-0158] compact block filters, which allow light clients to
//! efficiently determine whether a block is potentially relevant to their wallet without
//! downloading the entire block.
//!
//! # Overview
//!
//! Compact block filters use Golomb-Rice coding to create a compact, probabilistic data
//! structure that can test set membership. Each filter represents all the scriptPubKeys
//! and outpoints spent in a block.
//!
//! # Examples
//!
//! ```
//! # #[cfg(feature = "std")] {
//! use bitcoin_bip158::BlockFilter;
//! # }
//! ```
//!
//! [BIP-0158]: <https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki>

// Coding conventions.
#![warn(missing_docs)]
#![warn(deprecated_in_future)]
#![doc(test(attr(warn(unused))))]
// Pedantic lints that we enforce.
#![warn(clippy::return_self_not_must_use)]
// Exclude lints we don't think are valuable.
#![allow(clippy::needless_question_mark)] // https://github.com/rust-bitcoin/rust-bitcoin/pull/2134
#![allow(clippy::manual_range_contains)] // More readable than clippy's format.
#![allow(clippy::uninlined_format_args)] // Allow `format!("{}", x)`instead of enforcing `format!("{x}")`
