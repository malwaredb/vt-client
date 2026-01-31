// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[cfg(feature = "chrono")]
use chrono::{NaiveDateTime, ParseResult};

/// Information about a certificate
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SSLCertificate {
    /// Certificate version, probably `V3`
    #[serde(default)]
    pub version: String,

    /// Serial number
    #[serde(default)]
    pub serial_number: String,

    /// Public key information
    #[serde(default)]
    pub public_key: PublicKey,

    /// Certificate signature information
    #[serde(default)]
    pub cert_signature: CertSignature,

    /// Certificate subject
    #[serde(default)]
    pub subject: HashMap<String, serde_json::Value>,

    /// Signature algorithm
    #[serde(default)]
    pub signature_algorithm: Option<String>,

    /// Issuer information
    #[serde(default)]
    pub issuer: Issuer,

    /// Certificate extensions
    #[serde(default)]
    pub extensions: HashMap<String, serde_json::Value>,

    /// Certificate size
    #[serde(default)]
    pub size: u16,

    /// Date the certificate was first seen by Virus Total
    #[serde(default)]
    pub first_seen_date: String,

    /// SHA-1 hash
    #[serde(default)]
    pub thumbprint: String,

    /// SHA-256 hash
    #[serde(default)]
    pub thumbprint_sha256: String,

    /// Certificate validity range
    #[serde(default)]
    pub validity: Validity,

    /// Anything else not captured by this struct
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Certificate signature
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CertSignature {
    /// Signature algorithm of the certificate
    #[serde(default)]
    pub signature_algorithm: String,

    /// Signature of the certificate
    #[serde(default)]
    pub signature: String,
}

/// Issuer information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Issuer {
    /// Country name
    #[serde(alias = "C", default)]
    pub c: Option<String>,

    /// Common name
    #[serde(alias = "CN", default)]
    pub cn: Option<String>,

    /// Locality name
    #[serde(alias = "L", default)]
    pub l: Option<String>,

    /// Organization
    #[serde(alias = "O", default)]
    pub o: Option<String>,

    /// Organizational unit
    #[serde(alias = "OU", default)]
    pub ou: Option<String>,

    /// State or province
    #[serde(alias = "ST", default)]
    pub st: Option<String>,
}

/// Public key
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PublicKey {
    /// Algorithm
    #[serde(default)]
    pub algorithm: Option<PublicKeyAlgorithm>,

    /// RSA
    #[serde(default)]
    pub rsa: Option<RSA>,

    /// DSA
    #[serde(default)]
    pub dsa: Option<DSA>,

    /// EC
    #[serde(default)]
    pub ec: Option<EC>,
}

/// Public key algorithm
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum PublicKeyAlgorithm {
    /// RSA key
    #[default]
    #[serde(alias = "rsa")]
    RSA,

    /// DSA key
    #[serde(alias = "dsa")]
    DSA,

    /// Elliptic curve key
    #[serde(alias = "ec")]
    EC,
}

/// RSA key information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RSA {
    /// Key size
    #[serde(default)]
    pub key_size: u16,

    /// RSA modulus
    #[serde(default)]
    pub modulus: String,

    /// RSA exponent
    #[serde(default)]
    pub exponent: String,
}

/// DSA key information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DSA {
    /// DSA p term
    #[serde(default)]
    pub p: String,

    /// DSA q term
    #[serde(default)]
    pub q: String,

    /// DSA g term
    #[serde(default)]
    pub g: String,

    /// DSA key
    #[serde(rename = "pub", default)]
    pub key: String,
}

/// Elliptic curve key
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EC {
    /// EC OID
    #[serde(default)]
    pub oid: String,

    /// EC Key
    #[serde(rename = "pub", default)]
    pub key: String,
}

/// Certificate validity range
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Validity {
    /// End date of the certificate
    #[serde(default)]
    pub not_after: String,

    /// Start date of the certificate
    #[serde(default)]
    pub not_before: String,
}

impl Validity {
    #[cfg(feature = "chrono")]
    const FORMAT: &'static str = "%Y-%m-%d %H:%M:%S";

    /// Convert the `not_before` date to `NaiveDateTime`
    ///
    /// # Errors
    ///
    /// Returns an error if the data wasn't in the correct format
    #[cfg(feature = "chrono")]
    pub fn not_before_to_chrono(&self) -> ParseResult<NaiveDateTime> {
        NaiveDateTime::parse_from_str(&self.not_before, Self::FORMAT)
    }

    /// Convert the `not_after` date to `NaiveDateTime`
    ///
    /// # Errors
    ///
    /// Returns an error if the data wasn't in the correct format
    #[cfg(feature = "chrono")]
    pub fn not_after_to_chrono(&self) -> ParseResult<NaiveDateTime> {
        NaiveDateTime::parse_from_str(&self.not_after, Self::FORMAT)
    }
}

#[cfg(test)]
mod tests {

    const CERT_INFO: &str = r#"
    {
        "cert_signature": {
          "signature_algorithm": "sha256RSA",
          "signature": "5fdea0e7a0cd75fbc66bc387b39c7d43ac826e033be8c964ec44f7ee3786a74c45516f8430acbbbba5a6928b840d3418b03173b781137bbef5f9a4e4a9c06ecc603ffcd3eacb37f35b6990f0af2b7bbb3820348c41ff9e6a728bb693a642912e7a692285d569e7eb68dcb4cbc12a6119298eca4edee42138c818a2664d88b796723cfed5ce1e22c595a76a61d8fe493b4b98e466051b436b88b71d8ff793b9c5ad95e45fa0566b796148fa94f666926217520c68d9175a95a4bab7030680e46e0ea7b82e3c58ba0653db671bee8c91ba29ff32e32c4ec497192a581feaa0b71d34199b897a8bce68d2e4ba279d38d023661064bbbad02647213affe0ba9ab56c"
        },
        "extensions": {
          "key_usage": [
            "digitalSignature",
            "keyEncipherment"
          ],
          "extended_key_usage": [
            "serverAuth",
            "clientAuth"
          ],
          "CA": false,
          "subject_key_identifier": "187a03f3d04157ec00f7b3d180d78368d5ec9856",
          "authority_key_identifier": {
            "keyid": "c5cf46a4eaf4c3c07a6c95c42db05e922f26e3b9"
          },
          "ca_information_access": {
            "CA Issuers": "http://r11.i.lencr.org/"
          },
          "subject_alternative_name": [
            "haiku-os.org"
          ],
          "certificate_policies": [
            "2.23.140.1.2.1"
          ],
          "crl_distribution_points": [
            "http://r11.c.lencr.org/30.crl"
          ],
          "1.3.6.1.4.1.11129.2.4.2": "0481f300f10077000de1f2302bd30dc140621209ea552efc47747cb1d7e930ef"
        },
        "validity": {
          "not_after": "2025-09-11 00:50:34",
          "not_before": "2025-06-13 00:50:35"
        },
        "size": 1273,
        "version": "V3",
        "public_key": {
          "algorithm": "RSA",
          "rsa": {
            "modulus": "edae9007eae81cbaa2de72b459cde40115a133b437298258be57d5b766e964e646d65556f7325deda80360a88debf397a801ff9bea9438425559df95312878915c357cfd8335f75a6609ced9fb77f3c60ab968278d046e0ea713986f16e354f8b0738b5ec8d5e5066f883ae367e57a4c1b535c92bc9809c9b758db555063b47c59ecc948d9465707ac7fc42b1a34ed8fbe0e1edf622c9169b3ebe04bbe1ba23472544e8c8f2dd5b7eb3cf110afceaeceb8ba441493b29f8eb515f368281edc838d2fe750a1f67f5b54388049ac1c42a17c67badd9f2a74a71965033e21c7301cafa7dae50a1d6a151e7bbb33682ff59bfca1640a0ee10959dbf76c3383b8977f",
            "exponent": "10001",
            "key_size": 2048
          }
        },
        "thumbprint_sha256": "f597439a0ed9b30152caf1bd4d3b36d2c35cffbbd3052b6ffdbee2ea01de1259",
        "thumbprint": "c9d065b5aa7c571b45eab5244481af2a30d7b634",
        "serial_number": "5bc0c1d95d852f3936114257e6e917ffa1d",
        "issuer": {
          "C": "US",
          "O": "Let's Encrypt",
          "CN": "R11"
        },
        "subject": {
          "CN": "haiku-os.org"
        }
    }"#;

    #[test]
    fn cert() {
        let cert: super::SSLCertificate = serde_json::from_str(CERT_INFO).unwrap();
        assert_eq!(cert.size, 1273);
        #[cfg(feature = "chrono")]
        assert!(cert.validity.not_before_to_chrono().is_ok());
        assert!(cert.extra.is_empty());
    }
}
