// SPDX-License-Identifier: Apache-2.0

use crate::common::{AnalysisResult, LastAnalysisStats, Votes};

use std::collections::HashMap;

#[cfg(feature = "chrono")]
use chrono::{
    serde::{ts_seconds, ts_seconds_option},
    DateTime, Utc,
};
use serde::{Deserialize, Serialize};

/// Report for an IP address
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IPAttributes {
    /// Owner of the Autonomous System (AS)
    pub as_owner: Option<String>,

    /// Autonomous System Number
    pub asn: Option<u32>,

    /// Continent where the IP might be located
    pub continent: Option<String>,

    /// Country where the IP might be located
    pub country: Option<String>,

    /// IP Address' [JARM hash](https://engineering.salesforce.com/easily-identify-malicious-servers-on-the-internet-with-jarm-e095edac525a)
    pub jarm: Option<String>,

    /// When the IP address was last analyzed by Virus Total
    #[cfg(feature = "chrono")]
    #[serde(with = "ts_seconds")]
    pub last_analysis_date: DateTime<Utc>,

    /// When the IP address was last analyzed by Virus Total
    #[cfg(not(feature = "chrono"))]
    pub last_analysis_date: u64,

    /// Antivirus results, where the key is the name of the antivirus software product
    /// More info: <https://docs.virustotal.com/reference/analyses-object>
    #[serde(default)]
    pub last_analysis_results: HashMap<String, AnalysisResult>,

    /// Antivirus results summary
    pub last_analysis_stats: LastAnalysisStats,

    /// SSL information for the https certificate
    #[serde(default)]
    pub last_https_certificate: Option<crate::common::certs::SSLCertificate>,

    /// Date of the https certificate
    #[cfg(feature = "chrono")]
    #[serde(with = "ts_seconds_option", default)]
    pub last_https_certificate_date: Option<DateTime<Utc>>,

    /// Date of the https certificate
    #[cfg(not(feature = "chrono"))]
    #[serde(default)]
    pub last_https_certificate_date: Option<u64>,

    /// WHOIS date
    #[cfg(feature = "chrono")]
    #[serde(with = "ts_seconds")]
    pub whois_date: DateTime<Utc>,

    /// WHOIS date
    #[cfg(not(feature = "chrono"))]
    pub whois_date: u64,

    /// WHOIS information
    pub whois: String,

    /// When the report was created
    #[cfg(feature = "chrono")]
    #[serde(with = "ts_seconds")]
    pub last_modification_date: DateTime<Utc>,

    /// When the report was created
    #[cfg(not(feature = "chrono"))]
    pub last_modification_date: u64,

    /// The IP network's range of addresses
    pub network: String,

    /// IP address registry for this address
    pub regional_internet_registry: String,

    /// VT's reputation of the IP
    pub reputation: u64,

    /// Votes from the Virus Total user community whether the IP address is dangerous
    pub total_votes: Votes,

    /// Tags
    #[serde(default)]
    pub tags: Vec<String>,

    /// Registration Domain Access Protocol data, see <https://about.rdap.org>
    #[serde(default)]
    pub rdap: HashMap<String, serde_json::Value>,

    /// Anything else not captured by this struct
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}
