// SPDX-License-Identifier: CC0-1.0

//! PSBT key-value map implementations.
//!
//! This module contains the key-value map structures used in Partially Signed Bitcoin
//! Transactions (PSBTs) as defined in [BIP-0174].
//!
//! A PSBT is composed of three types of maps:
//! - Global map: Contains transaction-wide data
//! - Input maps: One per input, contains input-specific signing data
//! - Output maps: One per output, contains output-specific data
//!
//! Each map follows the serialization format: `<keypair>* 0x00`, where the 0x00 byte
//! serves as a separator.
//!
//! [BIP-0174]: <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>

mod global;
mod input;
mod output;

use crate::prelude::Vec;
use crate::psbt::raw;
use crate::psbt::serialize::Serialize;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::{
    input::{Input, PsbtSighashType},
    output::Output,
};

/// A trait that describes a PSBT key-value map.
pub(super) trait Map {
    /// Attempt to get all key-value pairs.
    fn get_pairs(&self) -> Vec<raw::Pair>;

    /// Serialize Psbt binary map data according to BIP-0174 specification.
    ///
    /// <map> := <keypair>* 0x00
    ///
    /// Why is the separator here 0x00 instead of 0xff? The separator here is used to distinguish
    /// between each chunk of data.
    ///
    /// A separator of 0x00 would mean that the deserializer can read it as a key length of 0,
    /// which would never occur with actual keys. It can thus be used as a separator and allow for
    /// easier deserializer implementation.
    fn serialize_map(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for pair in Map::get_pairs(self) {
            buf.extend(&pair.serialize());
        }
        buf.push(0x00_u8);
        buf
    }
}
