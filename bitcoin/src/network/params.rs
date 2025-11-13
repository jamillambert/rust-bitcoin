// SPDX-License-Identifier: CC0-1.0

//! Bitcoin consensus parameters for each network.

use super::{Network, TestnetVersion};
use crate::pow::Target;
use crate::{BlockHeight, BlockHeightInterval};

/// Parameters that influence chain consensus.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct Params {
    /// Network for which parameters are valid.
    pub network: Network,
    /// Time when BIP-0016 becomes active.
    pub bip16_time: u32,
    /// Block height at which BIP-0034 becomes active.
    pub bip34_height: BlockHeight,
    /// Block height at which BIP-0065 becomes active.
    pub bip65_height: BlockHeight,
    /// Block height at which BIP-0066 becomes active.
    pub bip66_height: BlockHeight,
    /// Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
    /// (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP-0009 deployments.
    /// Examples: 1916 for 95%, 1512 for testchains.
    pub rule_change_activation_threshold: BlockHeightInterval,
    /// Number of blocks with the same set of rules.
    pub miner_confirmation_window: BlockHeightInterval,
    /// Proof of work limit value. It contains the lowest possible difficulty.
    #[deprecated(since = "0.32.0", note = "use `max_attainable_target` instead")]
    pub pow_limit: Target,
    /// The maximum attainable target value for these params.
    pub max_attainable_target: Target,
    /// Expected amount of time to mine one block.
    pub pow_target_spacing: u64,
    /// Difficulty recalculation interval.
    pub pow_target_timespan: u32,
    /// Determines whether minimal difficulty may be used for blocks or not.
    pub allow_min_difficulty_blocks: bool,
    /// Determines whether retargeting is disabled for this network or not.
    pub no_pow_retargeting: bool,
}

/// The mainnet parameters.
pub static MAINNET: Params = Params::MAINNET;
/// The testnet3 parameters.
#[deprecated(since = "TBD", note = "use `TESTNET3` instead")]
pub static TESTNET: Params = Params::TESTNET3;
/// The testnet3 parameters.
pub static TESTNET3: Params = Params::TESTNET3;
/// The testnet4 parameters.
pub static TESTNET4: Params = Params::TESTNET4;
/// The signet parameters.
pub static SIGNET: Params = Params::SIGNET;
/// The regtest parameters.
pub static REGTEST: Params = Params::REGTEST;

#[allow(deprecated)] // For `pow_limit`.
impl Params {
    /// The mainnet parameters (alias for `Params::MAINNET`).
    pub const BITCOIN: Self = Self::MAINNET;

    /// The mainnet parameters.
    pub const MAINNET: Self = Self {
        network: Network::Bitcoin,
        bip16_time: 1333238400,                      // Apr 1 2012
        bip34_height: BlockHeight::from_u32(227931), // 000000000000024b...
        bip65_height: BlockHeight::from_u32(388381),
        bip66_height: BlockHeight::from_u32(363725),
        rule_change_activation_threshold: BlockHeightInterval::from_u32(1916), // 95%
        miner_confirmation_window: BlockHeightInterval::from_u32(2016),
        pow_limit: Target::MAX_ATTAINABLE_MAINNET,
        max_attainable_target: Target::MAX_ATTAINABLE_MAINNET,
        pow_target_spacing: 10 * 60,            // 10 minutes.
        pow_target_timespan: 14 * 24 * 60 * 60, // 2 weeks.
        allow_min_difficulty_blocks: false,
        no_pow_retargeting: false,
    };

    /// The testnet3 parameters.
    #[deprecated(since = "TBD", note = "use `TESTNET3` instead")]
    pub const TESTNET: Self = Self {
        network: Network::Testnet(TestnetVersion::V3),
        bip16_time: 1333238400, // Apr 1 2012
        bip34_height: BlockHeight::from_u32(21111),
        bip65_height: BlockHeight::from_u32(581885),
        bip66_height: BlockHeight::from_u32(330776),
        rule_change_activation_threshold: BlockHeightInterval::from_u32(1512), // 75%
        miner_confirmation_window: BlockHeightInterval::from_u32(2016),
        pow_limit: Target::MAX_ATTAINABLE_TESTNET,
        max_attainable_target: Target::MAX_ATTAINABLE_TESTNET,
        pow_target_spacing: 10 * 60,
        pow_target_timespan: 14 * 24 * 60 * 60,
        allow_min_difficulty_blocks: true,
        no_pow_retargeting: false,
    };

    /// The testnet3 parameters.
    pub const TESTNET3: Self = Self {
        network: Network::Testnet(TestnetVersion::V3),
        bip16_time: 1333238400, // Apr 1 2012
        bip34_height: BlockHeight::from_u32(21111),
        bip65_height: BlockHeight::from_u32(581885),
        bip66_height: BlockHeight::from_u32(330776),
        rule_change_activation_threshold: BlockHeightInterval::from_u32(1512), // 75%
        miner_confirmation_window: BlockHeightInterval::from_u32(2016),
        pow_limit: Target::MAX_ATTAINABLE_TESTNET,
        max_attainable_target: Target::MAX_ATTAINABLE_TESTNET,
        pow_target_spacing: 10 * 60,
        pow_target_timespan: 14 * 24 * 60 * 60,
        allow_min_difficulty_blocks: true,
        no_pow_retargeting: false,
    };

    /// The testnet4 parameters.
    pub const TESTNET4: Self = Self {
        network: Network::Testnet(TestnetVersion::V4),
        bip16_time: 1333238400, // Apr 1 2012
        bip34_height: BlockHeight::from_u32(1),
        bip65_height: BlockHeight::from_u32(1),
        bip66_height: BlockHeight::from_u32(1),
        rule_change_activation_threshold: BlockHeightInterval::from_u32(1512), // 75%
        miner_confirmation_window: BlockHeightInterval::from_u32(2016),
        pow_limit: Target::MAX_ATTAINABLE_TESTNET,
        max_attainable_target: Target::MAX_ATTAINABLE_TESTNET,
        pow_target_spacing: 10 * 60,
        pow_target_timespan: 14 * 24 * 60 * 60,
        allow_min_difficulty_blocks: true,
        no_pow_retargeting: false,
    };

    /// The signet parameters.
    pub const SIGNET: Self = Self {
        network: Network::Signet,
        bip16_time: 1333238400, // Apr 1 2012
        bip34_height: BlockHeight::from_u32(1),
        bip65_height: BlockHeight::from_u32(1),
        bip66_height: BlockHeight::from_u32(1),
        rule_change_activation_threshold: BlockHeightInterval::from_u32(1916), // 95%
        miner_confirmation_window: BlockHeightInterval::from_u32(2016),
        pow_limit: Target::MAX_ATTAINABLE_SIGNET,
        max_attainable_target: Target::MAX_ATTAINABLE_SIGNET,
        pow_target_spacing: 10 * 60,
        pow_target_timespan: 14 * 24 * 60 * 60,
        allow_min_difficulty_blocks: false,
        no_pow_retargeting: false,
    };

    /// The regtest parameters.
    pub const REGTEST: Self = Self {
        network: Network::Regtest,
        bip16_time: 1333238400,                         // Apr 1 2012
        bip34_height: BlockHeight::from_u32(100000000), // not activated on regtest
        bip65_height: BlockHeight::from_u32(1351),
        bip66_height: BlockHeight::from_u32(1251),
        rule_change_activation_threshold: BlockHeightInterval::from_u32(108), // 75%
        miner_confirmation_window: BlockHeightInterval::from_u32(144),
        pow_limit: Target::MAX_ATTAINABLE_REGTEST,
        max_attainable_target: Target::MAX_ATTAINABLE_REGTEST,
        pow_target_spacing: 10 * 60,
        pow_target_timespan: 14 * 24 * 60 * 60,
        allow_min_difficulty_blocks: true,
        no_pow_retargeting: true,
    };

    /// Constructs parameters set for the given network.
    pub const fn new(network: Network) -> Self {
        match network {
            Network::Bitcoin => Self::MAINNET,
            Network::Testnet(tv) => match tv {
                TestnetVersion::V3 => Self::TESTNET3,
                TestnetVersion::V4 => Self::TESTNET4,
                _ => Self::TESTNET4,
            },
            Network::Signet => Self::SIGNET,
            Network::Regtest => Self::REGTEST,
        }
    }

    /// Calculates the number of blocks between difficulty adjustments.
    pub fn difficulty_adjustment_interval(&self) -> u64 {
        u64::from(self.pow_target_timespan) / self.pow_target_spacing
    }
}

impl From<Network> for Params {
    fn from(value: Network) -> Self { Self::new(value) }
}

impl From<&Network> for Params {
    fn from(value: &Network) -> Self { Self::new(*value) }
}

impl AsRef<Self> for Params {
    fn as_ref(&self) -> &Self { self }
}

impl AsRef<Params> for Network {
    fn as_ref(&self) -> &Params {
        match self {
            Self::Bitcoin => &MAINNET,
            Self::Testnet(tv) => match tv {
                TestnetVersion::V3 => &TESTNET3,
                TestnetVersion::V4 => &TESTNET4,
                _ => &TESTNET4,
            },
            Self::Signet => &SIGNET,
            Self::Regtest => &REGTEST,
        }
    }
}
