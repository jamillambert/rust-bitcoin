// SPDX-License-Identifier: CC0-1.0

//! Test the API surface of `units`.
//!
//! The point of these tests is to check the API surface as opposed to test the API functionality.
//!
//! ref: <https://rust-lang.github.io/api-guidelines/about.html>

#![allow(dead_code)]
#![allow(unused_imports)]

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
// These imports test "typical" usage by user code.
use bitcoin_units::locktime::{absolute, relative}; // Typical usage is `absolute::Height`.
use bitcoin_units::{
    amount, block, fee_rate, locktime, parse, weight, Amount, BlockHeight, BlockInterval, BlockMtp,
    BlockMtpInterval, BlockTime, CheckedSum, FeeRate, SignedAmount, Weight,
};

/// A struct that includes all public non-error enums.
#[derive(Debug)] // All public types implement Debug (C-DEBUG).
struct Enums {
    a: amount::Denomination,
}

impl Enums {
    fn new() -> Self { Self { a: amount::Denomination::Bitcoin } }
}

/// A struct that includes all public non-error structs.
#[derive(Debug)] // All public types implement Debug (C-DEBUG).
struct Structs {
    a: Amount,
    b: amount::Display,
    c: SignedAmount,
    d: BlockHeight,
    e: BlockInterval,
    f: FeeRate,
    g: absolute::Height,
    h: absolute::MedianTimePast,
    i: relative::Height,
    j: relative::Time,
    k: Weight,
    l: BlockTime,
    m: BlockMtp,
    n: BlockMtpInterval,
}

impl Structs {
    fn max() -> Self {
        Self {
            a: Amount::MAX,
            b: Amount::MAX.display_in(amount::Denomination::Bitcoin),
            c: SignedAmount::MAX,
            d: BlockHeight::MAX,
            e: BlockInterval::MAX,
            f: FeeRate::MAX,
            g: absolute::Height::MAX,
            h: absolute::MedianTimePast::MAX,
            i: relative::Height::MAX,
            j: relative::Time::MAX,
            k: Weight::MAX,
            l: BlockTime::from_u32(u32::MAX),
            m: BlockMtp::MAX,
            n: BlockMtpInterval::MAX,
        }
    }
}

/// A struct that includes all public non-error types.
#[derive(Debug)] // All public types implement Debug (C-DEBUG).
struct Types {
    a: Enums,
    b: Structs,
}

impl Types {
    fn new() -> Self { Self { a: Enums::new(), b: Structs::max() } }
}

/// A struct that includes all public non-error non-helper structs.
// C-COMMON-TRAITS excluding `Default` and `Display`. `Display` is done in `./str.rs`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct CommonTraits {
    a: Amount,
    c: SignedAmount,
    d: BlockHeight,
    e: BlockInterval,
    f: FeeRate,
    g: absolute::Height,
    h: absolute::MedianTimePast,
    i: relative::Height,
    j: relative::Time,
    k: Weight,
    l: BlockTime,
    m: BlockMtp,
    n: BlockMtpInterval,
}

/// A struct that includes all types that implement `Default`.
#[derive(Debug, Default, PartialEq, Eq)] // C-COMMON-TRAITS: `Default`
struct Default {
    a: Amount,
    b: SignedAmount,
    c: BlockInterval,
    d: relative::Height,
    e: relative::Time,
    f: BlockMtpInterval,
}

/// A struct that includes all public error types.
// These derives are the policy of `rust-bitcoin` not Rust API guidelines.
#[derive(Debug, Clone, PartialEq, Eq)] // All public types implement Debug (C-DEBUG).
struct Errors {
    a: amount::InputTooLargeError,
    b: amount::InvalidCharacterError,
    c: amount::MissingDenominationError,
    d: amount::MissingDigitsError,
    e: amount::OutOfRangeError,
    f: amount::ParseAmountError,
    g: amount::ParseDenominationError,
    h: amount::ParseError,
    i: amount::PossiblyConfusingDenominationError,
    j: amount::TooPreciseError,
    k: amount::UnknownDenominationError,
    l: amount::InputTooLargeError,
    m: amount::InvalidCharacterError,
    n: amount::MissingDenominationError,
    o: amount::MissingDigitsError,
    p: amount::OutOfRangeError,
    q: amount::ParseAmountError,
    r: amount::ParseDenominationError,
    s: amount::ParseError,
    t: amount::PossiblyConfusingDenominationError,
    u: amount::TooPreciseError,
    v: amount::UnknownDenominationError,
    w: block::TooBigForRelativeHeightError,
    x: locktime::absolute::ConversionError,
    y: locktime::absolute::Height,
    z: locktime::absolute::ParseHeightError,
    aa: locktime::absolute::ParseTimeError,
    ab: locktime::relative::TimeOverflowError,
    ac: locktime::relative::InvalidHeightError,
    ad: locktime::relative::InvalidTimeError,
    ae: parse::ParseIntError,
    af: parse::PrefixedHexError,
    ag: parse::UnprefixedHexError,
}

#[test]
fn api_can_use_modules_from_crate_root() {
    use bitcoin_units::{amount, block, fee_rate, locktime, parse, time, weight};
}

#[test]
fn api_can_use_types_from_crate_root() {
    use bitcoin_units::{
        Amount, BlockHeight, BlockInterval, BlockMtp, BlockMtpInterval, BlockTime, FeeRate,
        SignedAmount, Weight,
    };
}

#[test]
fn api_can_use_all_types_from_module_amount() {
    use bitcoin_units::amount::{
        Amount, Denomination, Display, InputTooLargeError, InvalidCharacterError,
        MissingDenominationError, MissingDigitsError, OutOfRangeError, ParseAmountError,
        ParseDenominationError, ParseError, PossiblyConfusingDenominationError, SignedAmount,
        TooPreciseError, UnknownDenominationError,
    };
}

#[test]
fn api_can_use_all_types_from_module_block() {
    use bitcoin_units::block::{BlockHeight, BlockHeightInterval, TooBigForRelativeHeightError};
}

#[test]
fn api_can_use_all_types_from_module_fee_rate() {
    use bitcoin_units::fee_rate::FeeRate;
}

#[test]
fn api_can_use_all_types_from_module_locktime_absolute() {
    use bitcoin_units::locktime::absolute::{
        ConversionError, Height, MedianTimePast, ParseHeightError, ParseTimeError,
    };
}

#[test]
fn api_can_use_all_types_from_module_locktime_relative() {
    use bitcoin_units::locktime::relative::{Height, Time, TimeOverflowError};
}

#[test]
fn api_can_use_all_types_from_module_parse() {
    use bitcoin_units::parse::{ParseIntError, PrefixedHexError, UnprefixedHexError};
}

#[test]
fn api_can_use_all_types_from_module_time() {
    use bitcoin_units::time::BlockTime;
}

#[test]
fn api_can_use_all_types_from_module_weight() {
    use bitcoin_units::weight::Weight;
}

// `Debug` representation is never empty (C-DEBUG-NONEMPTY).
#[test]
fn api_all_non_error_types_have_non_empty_debug() {
    let t = Types::new();

    let debug = format!("{:?}", t.a.a);
    assert!(!debug.is_empty());

    let debug = format!("{:?}", t.b.a);
    assert!(!debug.is_empty());
    let debug = format!("{:?}", t.b.b);
    assert!(!debug.is_empty());
    let debug = format!("{:?}", t.b.c);
    assert!(!debug.is_empty());
    let debug = format!("{:?}", t.b.d);
    assert!(!debug.is_empty());
    let debug = format!("{:?}", t.b.e);
    assert!(!debug.is_empty());
    let debug = format!("{:?}", t.b.f);
    assert!(!debug.is_empty());
    let debug = format!("{:?}", t.b.g);
    assert!(!debug.is_empty());
    let debug = format!("{:?}", t.b.h);
    assert!(!debug.is_empty());
    let debug = format!("{:?}", t.b.i);
    assert!(!debug.is_empty());
    let debug = format!("{:?}", t.b.j);
    assert!(!debug.is_empty());
    let debug = format!("{:?}", t.b.k);
    assert!(!debug.is_empty());
    let debug = format!("{:?}", t.b.l);
    assert!(!debug.is_empty());
}

#[test]
fn all_types_implement_send_sync() {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    //  Types are `Send` and `Sync` where possible (C-SEND-SYNC).
    assert_send::<Types>();
    assert_sync::<Types>();

    // Error types should implement the Send and Sync traits (C-GOOD-ERR).
    assert_send::<Errors>();
    assert_sync::<Errors>();
}

#[test]
fn regression_default() {
    let got: Default = Default::default();
    let want = Default {
        a: Amount::ZERO,
        b: SignedAmount::ZERO,
        c: BlockInterval::ZERO,
        d: relative::Height::ZERO,
        e: relative::Time::ZERO,
        f: BlockMtpInterval::ZERO,
    };
    assert_eq!(got, want);
}

#[test]
fn dyn_compatible() {
    // If this builds then traits are dyn compatible.
    struct Traits {
        a: Box<dyn CheckedSum<Amount>>,
        b: Box<dyn CheckedSum<Weight>>,
        // These traits are explicitly not dyn compatible.
        // b: Box<dyn amount::serde::SerdeAmount>,
        // c: Box<dyn amount::serde::SerdeAmountForOpt>,
        // d: Box<dyn parse::Integer>,
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Types {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let a = Types { a: Enums::arbitrary(u)?, b: Structs::arbitrary(u)? };
        Ok(a)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Structs {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let a = Structs {
            a: Amount::arbitrary(u)?,
            // Skip the `Display` type.
            b: Amount::MAX.display_in(amount::Denomination::Bitcoin),
            c: SignedAmount::arbitrary(u)?,
            d: BlockHeight::arbitrary(u)?,
            e: BlockInterval::arbitrary(u)?,
            f: FeeRate::arbitrary(u)?,
            g: absolute::Height::arbitrary(u)?,
            h: absolute::MedianTimePast::arbitrary(u)?,
            i: relative::Height::arbitrary(u)?,
            j: relative::Time::arbitrary(u)?,
            k: Weight::arbitrary(u)?,
            l: BlockTime::arbitrary(u)?,
            m: BlockMtp::arbitrary(u)?,
            n: BlockMtpInterval::arbitrary(u)?,
        };
        Ok(a)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Enums {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let a = Enums { a: amount::Denomination::arbitrary(u)? };
        Ok(a)
    }
}
