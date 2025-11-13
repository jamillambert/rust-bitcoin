// SPDX-License-Identifier: CC0-1.0

//! Bitcoin network.
//!
//! This module re-exports network types and contains network params.

#[cfg(feature = "serde")]
#[doc(inline)]
pub use bitcoin_network::as_core_arg;
#[doc(inline)]
pub use bitcoin_network::{Network, NetworkKind, ParseNetworkError, TestnetVersion};

pub mod params;

#[rustfmt::skip]                // Keep public re-exports separate.
#[doc(inline)]
pub use self::params::Params;

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use super::{Network, TestnetVersion};

    #[test]
    fn string() {
        assert_eq!(Network::Bitcoin.to_string(), "bitcoin");
        assert_eq!(Network::Testnet(TestnetVersion::V3).to_string(), "testnet");
        assert_eq!(Network::Testnet(TestnetVersion::V4).to_string(), "testnet4");
        assert_eq!(Network::Regtest.to_string(), "regtest");
        assert_eq!(Network::Signet.to_string(), "signet");

        assert_eq!("bitcoin".parse::<Network>().unwrap(), Network::Bitcoin);
        assert_eq!("testnet".parse::<Network>().unwrap(), Network::Testnet(TestnetVersion::V3));
        assert_eq!("testnet4".parse::<Network>().unwrap(), Network::Testnet(TestnetVersion::V4));
        assert_eq!("regtest".parse::<Network>().unwrap(), Network::Regtest);
        assert_eq!("signet".parse::<Network>().unwrap(), Network::Signet);
        assert!("fakenet".parse::<Network>().is_err());
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serde_roundtrip() {
        use Network::*;
        let tests = vec![
            (Bitcoin, "bitcoin"),
            (Testnet(TestnetVersion::V3), "testnet"),
            (Testnet(TestnetVersion::V4), "testnet4"),
            (Signet, "signet"),
            (Regtest, "regtest"),
        ];

        for tc in tests {
            let network = tc.0;

            let want = format!("\"{}\"", tc.1);
            let got = serde_json::to_string(&tc.0).expect("failed to serialize network");
            assert_eq!(got, want);

            let back: Network = serde_json::from_str(&got).expect("failed to deserialize network");
            assert_eq!(back, network);
        }
    }

    #[test]
    fn from_to_core_arg() {
        let expected_pairs = [
            (Network::Bitcoin, "bitcoin"),
            (Network::Testnet(TestnetVersion::V3), "testnet"),
            (Network::Testnet(TestnetVersion::V4), "testnet4"),
            (Network::Regtest, "regtest"),
            (Network::Signet, "signet"),
        ];

        for (net, core_arg) in &expected_pairs {
            assert_eq!(Network::from_str(core_arg), Ok(*net));
            assert_eq!(net.to_core_arg(), *core_arg);
        }
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serde_as_core_arg() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct T {
            #[serde(with = "crate::network::as_core_arg")]
            pub network: Network,
        }

        serde_test::assert_tokens(
            &T { network: Network::Bitcoin },
            &[
                serde_test::Token::Struct { name: "T", len: 1 },
                serde_test::Token::Str("network"),
                serde_test::Token::Str("bitcoin"),
                serde_test::Token::StructEnd,
            ],
        );
    }
}
