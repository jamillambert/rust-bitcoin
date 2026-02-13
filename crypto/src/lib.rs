// SPDX-License-Identifier: CC0-1.0

//! Cryptography Support for Bitcoin
//!
//! This crate provides cryptographic primitives and utilities used throughout the
//! rust-bitcoin ecosystem. It serves as a lightweight wrapper around `secp256k1` and
//! provides Bitcoin-specific cryptographic operations.
//!
//! # Features
//!
//! - Signature creation and verification (ECDSA and Schnorr)
//! - Public and private key management
//! - Key derivation functions (KDFs)
//! - Encryption schemes (ChaCha20-Poly1305)
//!
//! This crate can be used in a no-std environment but requires an allocator.

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
