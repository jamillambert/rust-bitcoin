// SPDX-License-Identifier: CC0-1.0

// This module was largely copied from https://github.com/rust-bitcoin/murmel/blob/master/src/blockfilter.rs
// on 11. June 2019 which is licensed under Apache, that file specifically
// was written entirely by Tamas Blummer, who is re-licensing its contents here as CC0.

//! BIP 158 Compact Block Filters for Light Clients.
//!
//! This module implements a structure for compact filters on block data, for
//! use in the BIP 157 light client protocol. The filter construction proposed
//! is an alternative to Bloom filters, as used in BIP 37, that minimizes filter
//! size by using Golomb-Rice coding for compression.
//!
//! # Relevant BIPS
//!
//! * [BIP 157 - Client Side Block Filtering](https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki)
//! * [BIP 158 - Compact Block Filters for Light Clients](https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki)
//!
//! # Examples
//!
//! ```ignore
//! fn get_script_for_coin(coin: &OutPoint) -> Result<ScriptBuf, BlockFilterError> {
//!   // get utxo ...
//! }
//!
//! // create a block filter for a block (server side)
//! let filter = BlockFilter::new_script_filter(&block, get_script_for_coin)?;
//!
//! // or create a filter from known raw data
//! let filter = BlockFilter::new(content);
//!
//! // read and evaluate a filter
//!
//! let query: Iterator<Item=ScriptBuf> = // .. some scripts you care about
//! if filter.match_any(&block_hash, &mut query.map(|s| s.as_bytes())) {
//!   // get this block
//! }
//!  ```

use core::cmp::{self, Ordering};
use core::convert::Infallible;
use core::fmt;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use hashes::{sha256d, siphash24, HashEngine as _};
use internals::array::ArrayExt as _;
use internals::{write_err, ToU64 as _};
use io::{BufRead, Write};

use crate::block::{Block, BlockHash, Checked};
use crate::consensus::{ReadExt, WriteExt};
use crate::internal_macros::impl_hashencode;
use crate::prelude::{BTreeSet, Borrow, Vec};
use crate::script::{Script, ScriptExt as _};
use crate::transaction::OutPoint;

/// Golomb encoding parameter as in BIP-158, see also https://gist.github.com/sipa/576d5f09c3b86c3b1b75598d799fc845
const P: u8 = 19;
const M: u64 = 784931;

hashes::hash_newtype! {
    /// Filter hash, as defined in BIP-157.
    pub struct FilterHash(sha256d::Hash);
    /// Filter header, as defined in BIP-157.
    pub struct FilterHeader(sha256d::Hash);
}

hashes::impl_hex_for_newtype!(FilterHash, FilterHeader);
#[cfg(feature = "serde")]
hashes::impl_serde_for_newtype!(FilterHash, FilterHeader);

impl_hashencode!(FilterHash);
impl_hashencode!(FilterHeader);

/// Errors for blockfilter.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Missing UTXO, cannot calculate script filter.
    UtxoMissing(OutPoint),
    /// I/O error reading or writing binary serialization of the filter.
    Io(io::Error),
}

impl From<Infallible> for Error {
    fn from(never: Infallible) -> Self { match never {} }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        use Error::*;

        match *self {
            UtxoMissing(ref coin) => write!(f, "unresolved UTXO {}", coin),
            Io(ref e) => write_err!(f, "I/O error"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match *self {
            UtxoMissing(_) => None,
            Io(ref e) => Some(e),
        }
    }
}

impl From<io::Error> for Error {
    fn from(io: io::Error) -> Self { Error::Io(io) }
}

/// A block filter, as described by BIP 158.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockFilter {
    /// Golomb encoded filter
    pub content: Vec<u8>,
}

impl FilterHash {
    /// Computes the filter header from a filter hash and previous filter header.
    pub fn filter_header(&self, previous_filter_header: FilterHeader) -> FilterHeader {
        let mut engine = sha256d::Hash::engine();
        engine.input(self.as_ref());
        engine.input(previous_filter_header.as_ref());
        FilterHeader(sha256d::Hash::from_engine(engine))
    }
}

impl BlockFilter {
    /// Constructs a new filter from pre-computed data.
    pub fn new(content: &[u8]) -> BlockFilter { BlockFilter { content: content.to_vec() } }

    /// Computes a SCRIPT_FILTER that contains spent and output scripts.
    pub fn new_script_filter<M, S>(
        block: &Block<Checked>,
        script_for_coin: M,
    ) -> Result<BlockFilter, Error>
    where
        M: Fn(&OutPoint) -> Result<S, Error>,
        S: Borrow<Script>,
    {
        let mut out = Vec::new();
        let mut writer = BlockFilterWriter::new(&mut out, block);

        writer.add_output_scripts();
        writer.add_input_scripts(script_for_coin)?;
        writer.finish()?;

        Ok(BlockFilter { content: out })
    }

    /// Computes this filter's ID in a chain of filters (see [BIP 157]).
    ///
    /// [BIP 157]: <https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki#Filter_Headers>
    pub fn filter_header(&self, previous_filter_header: FilterHeader) -> FilterHeader {
        FilterHash(sha256d::Hash::hash(&self.content)).filter_header(previous_filter_header)
    }

    /// Computes the canonical hash for the given filter.
    pub fn filter_hash(&self) -> FilterHash {
        let hash = sha256d::Hash::hash(&self.content);
        FilterHash(hash)
    }

    /// Returns true if any query matches against this [`BlockFilter`].
    pub fn match_any<I>(&self, block_hash: BlockHash, query: I) -> Result<bool, Error>
    where
        I: Iterator,
        I::Item: Borrow<[u8]>,
    {
        let filter_reader = BlockFilterReader::new(block_hash);
        filter_reader.match_any(&mut self.content.as_slice(), query)
    }

    /// Returns true if all queries match against this [`BlockFilter`].
    pub fn match_all<I>(&self, block_hash: BlockHash, query: I) -> Result<bool, Error>
    where
        I: Iterator,
        I::Item: Borrow<[u8]>,
    {
        let filter_reader = BlockFilterReader::new(block_hash);
        filter_reader.match_all(&mut self.content.as_slice(), query)
    }
}

/// Compiles and writes a block filter.
pub struct BlockFilterWriter<'a, W> {
    block: &'a Block<Checked>,
    writer: GcsFilterWriter<'a, W>,
}

impl<'a, W: Write> BlockFilterWriter<'a, W> {
    /// Constructs a new [`BlockFilterWriter`] from `block`.
    pub fn new(writer: &'a mut W, block: &'a Block<Checked>) -> BlockFilterWriter<'a, W> {
        let block_hash_as_int = block.block_hash().to_byte_array();
        let k0 = u64::from_le_bytes(*block_hash_as_int.sub_array::<0, 8>());
        let k1 = u64::from_le_bytes(*block_hash_as_int.sub_array::<8, 8>());
        let writer = GcsFilterWriter::new(writer, k0, k1, M, P);
        BlockFilterWriter { block, writer }
    }

    /// Adds output scripts of the block to filter (excluding OP_RETURN scripts).
    pub fn add_output_scripts(&mut self) {
        for transaction in self.block.transactions() {
            for output in &transaction.output {
                if !output.script_pubkey.is_op_return() {
                    self.add_element(output.script_pubkey.as_bytes());
                }
            }
        }
    }

    /// Adds consumed output scripts of a block to filter.
    pub fn add_input_scripts<M, S>(&mut self, script_for_coin: M) -> Result<(), Error>
    where
        M: Fn(&OutPoint) -> Result<S, Error>,
        S: Borrow<Script>,
    {
        for script in self
            .block
            .transactions()
            .iter()
            .skip(1) // skip coinbase
            .flat_map(|t| t.input.iter().map(|i| &i.previous_output))
            .map(script_for_coin)
        {
            match script {
                Ok(script) => self.add_element(script.borrow().as_bytes()),
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Adds an arbitrary element to filter.
    pub fn add_element(&mut self, data: &[u8]) { self.writer.add_element(data); }

    /// Writes the block filter.
    pub fn finish(&mut self) -> Result<usize, io::Error> { self.writer.finish() }
}

/// Reads and interprets a block filter.
pub struct BlockFilterReader {
    reader: GcsFilterReader,
}

impl BlockFilterReader {
    /// Constructs a new [`BlockFilterReader`] from `block_hash`.
    pub fn new(block_hash: BlockHash) -> BlockFilterReader {
        let block_hash_as_int = block_hash.to_byte_array();
        let k0 = u64::from_le_bytes(*block_hash_as_int.sub_array::<0, 8>());
        let k1 = u64::from_le_bytes(*block_hash_as_int.sub_array::<8, 8>());
        BlockFilterReader { reader: GcsFilterReader::new(k0, k1, M, P) }
    }

    /// Returns true if any query matches against this [`BlockFilterReader`].
    pub fn match_any<I, R>(&self, reader: &mut R, query: I) -> Result<bool, Error>
    where
        I: Iterator,
        I::Item: Borrow<[u8]>,
        R: BufRead + ?Sized,
    {
        self.reader.match_any(reader, query)
    }

    /// Returns true if all queries match against this [`BlockFilterReader`].
    pub fn match_all<I, R>(&self, reader: &mut R, query: I) -> Result<bool, Error>
    where
        I: Iterator,
        I::Item: Borrow<[u8]>,
        R: BufRead + ?Sized,
    {
        self.reader.match_all(reader, query)
    }
}

/// Golomb-Rice encoded filter reader.
pub struct GcsFilterReader {
    filter: GcsFilter,
    m: u64,
}

impl GcsFilterReader {
    /// Constructs a new [`GcsFilterReader`] with specific seed to siphash.
    pub fn new(k0: u64, k1: u64, m: u64, p: u8) -> GcsFilterReader {
        GcsFilterReader { filter: GcsFilter::new(k0, k1, p), m }
    }

    /// Returns true if any query matches against this [`GcsFilterReader`].
    pub fn match_any<I, R>(&self, reader: &mut R, query: I) -> Result<bool, Error>
    where
        I: Iterator,
        I::Item: Borrow<[u8]>,
        R: BufRead + ?Sized,
    {
        let n_elements = reader.read_compact_size().unwrap_or(0);
        // map hashes to [0, n_elements << grp]
        let nm = n_elements * self.m;
        let mut mapped =
            query.map(|e| map_to_range(self.filter.hash(e.borrow()), nm)).collect::<Vec<_>>();
        // sort
        mapped.sort_unstable();
        if mapped.is_empty() {
            return Ok(true);
        }
        if n_elements == 0 {
            return Ok(false);
        }

        // find first match in two sorted arrays in one read pass
        let mut reader = BitStreamReader::new(reader);
        let mut data = self.filter.golomb_rice_decode(&mut reader)?;
        let mut remaining = n_elements - 1;
        for p in mapped {
            loop {
                match data.cmp(&p) {
                    Ordering::Equal => return Ok(true),
                    Ordering::Less =>
                        if remaining > 0 {
                            data += self.filter.golomb_rice_decode(&mut reader)?;
                            remaining -= 1;
                        } else {
                            return Ok(false);
                        },
                    Ordering::Greater => break,
                }
            }
        }
        Ok(false)
    }

    /// Returns true if all queries match against this [`GcsFilterReader`].
    pub fn match_all<I, R>(&self, reader: &mut R, query: I) -> Result<bool, Error>
    where
        I: Iterator,
        I::Item: Borrow<[u8]>,
        R: BufRead + ?Sized,
    {
        let n_elements = reader.read_compact_size().unwrap_or(0);
        // map hashes to [0, n_elements << grp]
        let nm = n_elements * self.m;
        let mut mapped =
            query.map(|e| map_to_range(self.filter.hash(e.borrow()), nm)).collect::<Vec<_>>();
        // sort
        mapped.sort_unstable();
        mapped.dedup();
        if mapped.is_empty() {
            return Ok(true);
        }
        if n_elements == 0 {
            return Ok(false);
        }

        // figure if all mapped are there in one read pass
        let mut reader = BitStreamReader::new(reader);
        let mut data = self.filter.golomb_rice_decode(&mut reader)?;
        let mut remaining = n_elements - 1;
        for p in mapped {
            loop {
                match data.cmp(&p) {
                    Ordering::Equal => break,
                    Ordering::Less =>
                        if remaining > 0 {
                            data += self.filter.golomb_rice_decode(&mut reader)?;
                            remaining -= 1;
                        } else {
                            return Ok(false);
                        },
                    Ordering::Greater => return Ok(false),
                }
            }
        }
        Ok(true)
    }
}

/// Fast reduction of hash to [0, nm) range.
fn map_to_range(hash: u64, nm: u64) -> u64 { ((u128::from(hash) * u128::from(nm)) >> 64) as u64 }

/// Golomb-Rice encoded filter writer.
pub struct GcsFilterWriter<'a, W> {
    filter: GcsFilter,
    writer: &'a mut W,
    elements: BTreeSet<Vec<u8>>,
    m: u64,
}

impl<'a, W: Write> GcsFilterWriter<'a, W> {
    /// Constructs a new [`GcsFilterWriter`] wrapping a generic writer, with specific seed to siphash.
    pub fn new(writer: &'a mut W, k0: u64, k1: u64, m: u64, p: u8) -> GcsFilterWriter<'a, W> {
        GcsFilterWriter { filter: GcsFilter::new(k0, k1, p), writer, elements: BTreeSet::new(), m }
    }

    /// Adds data to the filter.
    pub fn add_element(&mut self, element: &[u8]) {
        if !element.is_empty() {
            self.elements.insert(element.to_vec());
        }
    }

    /// Writes the filter to the wrapped writer.
    pub fn finish(&mut self) -> Result<usize, io::Error> {
        let nm = self.elements.len().to_u64() * self.m;

        // map hashes to [0, n_elements * M)
        let mut mapped: Vec<_> = self
            .elements
            .iter()
            .map(|e| map_to_range(self.filter.hash(e.as_slice()), nm))
            .collect();
        mapped.sort_unstable();

        // write number of elements as varint
        let mut wrote = self.writer.emit_compact_size(mapped.len())?;

        // write out deltas of sorted values into a Golomb-Rice coded bit stream
        let mut writer = BitStreamWriter::new(self.writer);
        let mut last = 0;
        for data in mapped {
            wrote += self.filter.golomb_rice_encode(&mut writer, data - last)?;
            last = data;
        }
        wrote += writer.flush()?;
        Ok(wrote)
    }
}

/// Golomb Coded Set Filter.
struct GcsFilter {
    k0: u64, // sip hash key
    k1: u64, // sip hash key
    p: u8,
}

impl GcsFilter {
    /// Constructs a new [`GcsFilter`].
    fn new(k0: u64, k1: u64, p: u8) -> GcsFilter { GcsFilter { k0, k1, p } }

    /// Golomb-Rice encodes a number `n` to a bit stream (parameter 2^k).
    fn golomb_rice_encode<W>(
        &self,
        writer: &mut BitStreamWriter<'_, W>,
        n: u64,
    ) -> Result<usize, io::Error>
    where
        W: Write,
    {
        let mut wrote = 0;
        let mut q = n >> self.p;
        while q > 0 {
            let nbits = cmp::min(q, 64) as u8; // cast ok, 64 fits into a `u8`
            wrote += writer.write(!0u64, nbits)?;
            q -= u64::from(nbits);
        }
        wrote += writer.write(0, 1)?;
        wrote += writer.write(n, self.p)?;
        Ok(wrote)
    }

    /// Golomb-Rice decodes a number from a bit stream (parameter 2^k).
    fn golomb_rice_decode<R>(&self, reader: &mut BitStreamReader<R>) -> Result<u64, io::Error>
    where
        R: BufRead + ?Sized,
    {
        let mut q = 0u64;
        while reader.read(1)? == 1 {
            q += 1;
        }
        let r = reader.read(self.p)?;
        Ok((q << self.p) + r)
    }

    /// Hashes an arbitrary slice with siphash using parameters of this filter.
    fn hash(&self, element: &[u8]) -> u64 {
        siphash24::Hash::hash_to_u64_with_keys(self.k0, self.k1, element)
    }
}

/// Bitwise stream reader.
pub struct BitStreamReader<'a, R: ?Sized> {
    buffer: [u8; 1],
    offset: u8,
    reader: &'a mut R,
}

impl<'a, R: BufRead + ?Sized> BitStreamReader<'a, R> {
    /// Constructs a new [`BitStreamReader`] that reads bitwise from a given `reader`.
    pub fn new(reader: &'a mut R) -> BitStreamReader<'a, R> {
        BitStreamReader { buffer: [0u8], reader, offset: 8 }
    }

    /// Reads nbit bits, returning the bits in a `u64` starting with the rightmost bit.
    ///
    /// # Examples
    ///
    /// ```
    /// # use bitcoin::bip158::BitStreamReader;
    /// # let data = [0xff];
    /// # let mut input = data.as_slice();
    /// let mut reader = BitStreamReader::new(&mut input); // input contains all 1's
    /// let res = reader.read(1).expect("read failed");
    /// assert_eq!(res, 1_u64);
    /// ```
    pub fn read(&mut self, mut nbits: u8) -> Result<u64, io::Error> {
        if nbits > 64 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "can not read more than 64 bits at once",
            ));
        }
        let mut data = 0u64;
        while nbits > 0 {
            if self.offset == 8 {
                self.reader.read_exact(&mut self.buffer)?;
                self.offset = 0;
            }
            let bits = cmp::min(8 - self.offset, nbits);
            data <<= bits;
            data |= ((self.buffer[0] << self.offset) >> (8 - bits)) as u64;
            self.offset += bits;
            nbits -= bits;
        }
        Ok(data)
    }
}

/// Bitwise stream writer.
pub struct BitStreamWriter<'a, W> {
    buffer: [u8; 1],
    offset: u8,
    writer: &'a mut W,
}

impl<'a, W: Write> BitStreamWriter<'a, W> {
    /// Constructs a new [`BitStreamWriter`] that writes bitwise to a given `writer`.
    pub fn new(writer: &'a mut W) -> BitStreamWriter<'a, W> {
        BitStreamWriter { buffer: [0u8], writer, offset: 0 }
    }

    /// Writes nbits bits from data.
    pub fn write(&mut self, data: u64, mut nbits: u8) -> Result<usize, io::Error> {
        if nbits > 64 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "can not write more than 64 bits at once",
            ));
        }
        let mut wrote = 0;
        while nbits > 0 {
            let bits = cmp::min(8 - self.offset, nbits);
            self.buffer[0] |= ((data << (64 - nbits)) >> (64 - 8 + self.offset)) as u8;
            self.offset += bits;
            nbits -= bits;
            if self.offset == 8 {
                wrote += self.flush()?;
            }
        }
        Ok(wrote)
    }

    /// flush bits not yet written.
    pub fn flush(&mut self) -> Result<usize, io::Error> {
        if self.offset > 0 {
            self.writer.write_all(&self.buffer)?;
            self.buffer[0] = 0u8;
            self.offset = 0;
            Ok(1)
        } else {
            Ok(0)
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for FilterHash {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(FilterHash::from_byte_array(u.arbitrary()?))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for FilterHeader {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(FilterHeader::from_byte_array(u.arbitrary()?))
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use hex_lit::hex;
    use serde_json::Value;

    use super::*;
    use crate::consensus::encode::deserialize;
    use crate::ScriptBuf;

    #[test]
    fn blockfilters() {
        let hex = |b| <Vec<u8> as hex::FromHex>::from_hex(b).unwrap();

        // test vectors from: https://github.com/jimpo/bitcoin/blob/c7efb652f3543b001b4dd22186a354605b14f47e/src/test/data/blockfilters.json
        let data = include_str!("../tests/data/blockfilters.json");

        let testdata = serde_json::from_str::<Value>(data).unwrap().as_array().unwrap().clone();
        for t in testdata.iter().skip(1) {
            let block_hash = t.get(1).unwrap().as_str().unwrap().parse::<BlockHash>().unwrap();
            let block: Block = deserialize(&hex(t.get(2).unwrap().as_str().unwrap())).unwrap();
            let block = block.assume_checked(None);
            assert_eq!(block.block_hash(), block_hash);
            let scripts = t.get(3).unwrap().as_array().unwrap();
            let previous_filter_header =
                t.get(4).unwrap().as_str().unwrap().parse::<FilterHeader>().unwrap();
            let filter_content = hex(t.get(5).unwrap().as_str().unwrap());
            let filter_header =
                t.get(6).unwrap().as_str().unwrap().parse::<FilterHeader>().unwrap();

            let mut txmap = HashMap::new();
            let mut si = scripts.iter();
            for tx in block.transactions().iter().skip(1) {
                for input in tx.input.iter() {
                    txmap.insert(
                        input.previous_output,
                        ScriptBuf::from(hex(si.next().unwrap().as_str().unwrap())),
                    );
                }
            }

            let filter = BlockFilter::new_script_filter(&block, |o| {
                if let Some(s) = txmap.get(o) {
                    Ok(s.clone())
                } else {
                    Err(Error::UtxoMissing(*o))
                }
            })
            .unwrap();

            let test_filter = BlockFilter::new(filter_content.as_slice());

            assert_eq!(test_filter.content, filter.content);

            let block_hash = &block.block_hash();
            assert!(filter
                .match_all(
                    *block_hash,
                    &mut txmap.iter().filter_map(|(_, s)| if !s.is_empty() {
                        Some(s.as_bytes())
                    } else {
                        None
                    })
                )
                .unwrap());

            for script in txmap.values() {
                let query = [script];
                if !script.is_empty() {
                    assert!(filter
                        .match_any(*block_hash, &mut query.iter().map(|s| s.as_bytes()))
                        .unwrap());
                }
            }

            assert_eq!(filter_header, filter.filter_header(previous_filter_header));
        }
    }

    #[test]
    fn filter() {
        let mut patterns = BTreeSet::new();

        patterns.insert(hex!("000000"));
        patterns.insert(hex!("111111"));
        patterns.insert(hex!("222222"));
        patterns.insert(hex!("333333"));
        patterns.insert(hex!("444444"));
        patterns.insert(hex!("555555"));
        patterns.insert(hex!("666666"));
        patterns.insert(hex!("777777"));
        patterns.insert(hex!("888888"));
        patterns.insert(hex!("999999"));
        patterns.insert(hex!("aaaaaa"));
        patterns.insert(hex!("bbbbbb"));
        patterns.insert(hex!("cccccc"));
        patterns.insert(hex!("dddddd"));
        patterns.insert(hex!("eeeeee"));
        patterns.insert(hex!("ffffff"));

        let mut out = Vec::new();
        {
            let mut writer = GcsFilterWriter::new(&mut out, 0, 0, M, P);
            for p in &patterns {
                writer.add_element(p.as_slice());
            }
            writer.finish().unwrap();
        }

        let bytes = out;

        {
            let query = [hex!("abcdef"), hex!("eeeeee")];
            let reader = GcsFilterReader::new(0, 0, M, P);
            assert!(reader
                .match_any(&mut bytes.as_slice(), &mut query.iter().map(|v| v.as_slice()))
                .unwrap());
        }
        {
            let query = [hex!("abcdef"), hex!("123456")];
            let reader = GcsFilterReader::new(0, 0, M, P);
            assert!(!reader
                .match_any(&mut bytes.as_slice(), &mut query.iter().map(|v| v.as_slice()))
                .unwrap());
        }
        {
            let reader = GcsFilterReader::new(0, 0, M, P);
            let mut query = Vec::new();
            for p in &patterns {
                query.push(p);
            }
            assert!(reader
                .match_all(&mut bytes.as_slice(), &mut query.iter().map(|v| v.as_slice()))
                .unwrap());
        }
        {
            let reader = GcsFilterReader::new(0, 0, M, P);
            let mut query = Vec::new();
            for p in &patterns {
                query.push(p);
            }
            query.push(&hex!("abcdef"));
            assert!(!reader
                .match_all(&mut bytes.as_slice(), &mut query.iter().map(|v| v.as_slice()))
                .unwrap());
        }
    }

    #[test]
    fn bit_stream() {
        let mut out = Vec::new();
        {
            let mut writer = BitStreamWriter::new(&mut out);
            writer.write(0, 1).unwrap(); // 0
            writer.write(2, 2).unwrap(); // 10
            writer.write(6, 3).unwrap(); // 110
            writer.write(11, 4).unwrap(); // 1011
            writer.write(1, 5).unwrap(); // 00001
            writer.write(32, 6).unwrap(); // 100000
            writer.write(7, 7).unwrap(); // 0000111
            writer.flush().unwrap();
        }
        let bytes = out;
        assert_eq!(
            "01011010110000110000000001110000",
            format!("{:08b}{:08b}{:08b}{:08b}", bytes[0], bytes[1], bytes[2], bytes[3])
        );
        {
            let mut input = bytes.as_slice();
            let mut reader = BitStreamReader::new(&mut input);
            assert_eq!(reader.read(1).unwrap(), 0);
            assert_eq!(reader.read(2).unwrap(), 2);
            assert_eq!(reader.read(3).unwrap(), 6);
            assert_eq!(reader.read(4).unwrap(), 11);
            assert_eq!(reader.read(5).unwrap(), 1);
            assert_eq!(reader.read(6).unwrap(), 32);
            assert_eq!(reader.read(7).unwrap(), 7);
            // 4 bits remained
            assert!(reader.read(5).is_err());
        }
    }
}
