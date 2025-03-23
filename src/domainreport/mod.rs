// SPDX-License-Identifier: Apache-2.0

use crate::common::{AnalysisResult, LastAnalysisStats, Votes};

use std::collections::HashMap;

#[cfg(feature = "chrono")]
use chrono::serde::{ts_seconds, ts_seconds_option};
#[cfg(feature = "chrono")]
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Successful domain report request response contents
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DomainReportData {
    /// Link to the Domain report
    #[serde(default)]
    pub links: HashMap<String, String>,

    /// Report type, probably "domain"
    #[serde(rename = "type")]
    pub record_type: String,

    /// Report ID, also the domain name
    pub id: String,

    /// The file report details, the interesting part
    pub attributes: DomainAttributes,
}

/// All scan results
/// [https://virustotal.readme.io/reference/files]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DomainAttributes {
    /// When the report was created
    #[cfg(feature = "chrono")]
    #[serde(with = "ts_seconds")]
    pub last_modification_date: DateTime<Utc>,

    /// When the report was created
    #[cfg(not(feature = "chrono"))]
    pub last_modification_date: u64,

    /// Date of the https certificate
    #[cfg(feature = "chrono")]
    #[serde(with = "ts_seconds_option", default)]
    pub last_https_certificate_date: Option<DateTime<Utc>>,

    /// Date of the https certificate
    #[cfg(not(feature = "chrono"))]
    #[serde(default)]
    pub last_https_certificate_date: Option<u64>,

    /// Domain creation date
    #[cfg(feature = "chrono")]
    #[serde(with = "ts_seconds")]
    pub creation_date: DateTime<Utc>,

    /// Domain creation date
    #[cfg(not(feature = "chrono"))]
    pub creation_date: u64,

    /// WHOIS date
    #[cfg(feature = "chrono")]
    #[serde(with = "ts_seconds")]
    pub whois_date: DateTime<Utc>,

    /// WHOIS date
    #[cfg(not(feature = "chrono"))]
    pub whois_date: u64,

    /// WHOIS information
    pub whois: String,

    /// Last DNS record update
    #[cfg(feature = "chrono")]
    #[serde(with = "ts_seconds_option", default)]
    pub last_dns_records_date: Option<DateTime<Utc>>,

    /// Last DNS record update
    #[cfg(not(feature = "chrono"))]
    #[serde(default)]
    pub last_dns_records_date: Option<u64>,

    /// Last update date
    #[cfg(feature = "chrono")]
    #[serde(with = "ts_seconds_option", default)]
    pub last_update_date: Option<DateTime<Utc>>,

    /// Last update date
    #[cfg(not(feature = "chrono"))]
    #[serde(default)]
    pub last_update_date: Option<u64>,

    /// Domain's JARM hash [https://engineering.salesforce.com/easily-identify-malicious-servers-on-the-internet-with-jarm-e095edac525a]
    pub jarm: String,

    /// Top Level domain
    pub tld: String,

    /// Domain registrar used by this domain
    pub registrar: String,

    /// Known DNS records for this domain
    #[serde(default)]
    pub last_dns_records: Vec<DnsRecord>,

    /// Votes from the VirusTotal user community whether the domain is dangerous
    pub total_votes: Votes,

    /// Antivirus results summary
    pub last_analysis_stats: LastAnalysisStats,

    /// Antivirus results, where the key is the name of the antivirus software product
    /// More info: [https://docs.virustotal.com/reference/analyses-object]
    #[serde(default)]
    pub last_analysis_results: HashMap<String, AnalysisResult>,

    /// When the file was last analyzed by VirusTotal
    #[cfg(feature = "chrono")]
    #[serde(with = "ts_seconds")]
    pub last_analysis_date: DateTime<Utc>,

    /// When the file was last analyzed by VirusTotal
    #[cfg(not(feature = "chrono"))]
    pub last_analysis_date: u64,

    /// VT's reputation of the domain
    pub reputation: u64,

    /// Tags
    #[serde(default)]
    pub tags: Vec<String>,

    /// Popularity info
    #[serde(default)]
    pub popularity_ranks: HashMap<String, PopularityRankEntry>,

    /// SSL information for the https domain
    #[serde(default)]
    pub last_https_certificate: HashMap<String, serde_json::Value>,

    /// Mapping services & categories
    #[serde(default)]
    pub categories: HashMap<String, serde_json::Value>,

    /// When the domain expires
    #[cfg(feature = "chrono")]
    #[serde(with = "ts_seconds_option", default)]
    pub expiration_date: Option<DateTime<Utc>>,

    /// When the domain expires
    #[cfg(not(feature = "chrono"))]
    pub expiration_date: Option<u64>,

    /// Anything else not capture by this struct
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// DNS record entry
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnsRecord {
    /// Expire
    #[serde(default)]
    pub expire: Option<u64>,

    /// Minimum
    #[serde(default)]
    pub minimum: Option<u64>,

    /// The type of DNS record
    #[serde(rename = "type")]
    pub record_type: DnsRecordType,

    /// Refresh
    #[serde(default)]
    pub refresh: Option<u64>,

    /// Retry
    #[serde(default)]
    pub retry: Option<u64>,

    /// Serial
    #[serde(default)]
    pub serial: Option<u64>,

    /// Tag
    #[serde(default)]
    pub tag: Option<String>,

    /// DNS time to live
    pub ttl: u64,

    /// Value of the DNS record
    pub value: String,
}

/// DNS Record type
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DnsRecordType {
    /// IPv4 record
    #[serde(alias = "a")]
    A,

    /// IPv6 record
    #[serde(alias = "aaaa")]
    AAAA,

    /// (Andrew File System) AFS database record
    #[serde(alias = "afsdb")]
    AFSDB,

    /// Address Prefix List
    #[serde(alias = "apl")]
    APL,

    /// Certification Authority Authorization
    #[serde(alias = "caa")]
    CAA,

    /// Child copy of DNSKEY record,
    #[serde(alias = "cdnskey")]
    CDNSKEY,

    /// Child DS
    #[serde(alias = "cds")]
    CDS,

    /// Certificate record
    #[serde(alias = "cert")]
    CERT,

    /// Alias record
    #[serde(alias = "cname")]
    CNAME,

    /// Child-to-Parent Synchronization
    #[serde(alias = "csync")]
    CSYNC,

    /// DHCP identifier
    #[serde(alias = "dhcid")]
    DHCID,

    /// DNSSEC Lookaside Validation record
    #[serde(alias = "dlv")]
    DLV,

    /// Delegation name record
    #[serde(alias = "dname")]
    DNAME,

    /// DNS Key record
    #[serde(alias = "dnskey")]
    DNSKEY,

    /// Delegation signer
    #[serde(alias = "ds")]
    DS,

    /// MAC Address 48-bit
    #[serde(alias = "eui48")]
    EUI48,

    /// MAC Address 64-bit
    #[serde(alias = "eui64")]
    EUI64,

    /// Host information
    #[serde(alias = "hinfo")]
    HINFO,

    /// Host Identity Protocol
    #[serde(alias = "hip")]
    HIP,

    /// HTTPS Binding
    #[serde(alias = "https")]
    HTTPS,

    /// IPSec key
    #[serde(alias = "ipseckey")]
    IPSECKEY,

    /// Key record
    #[serde(alias = "key")]
    KEY,

    /// Key Exchanger record
    #[serde(alias = "kx")]
    KX,

    /// Location record
    #[serde(alias = "loc")]
    LOC,

    /// Mail server record
    #[serde(alias = "mx")]
    MX,

    /// Naming Authority Pointer
    #[serde(alias = "naptr")]
    NAPTR,

    /// Authoritative name server record for the domain
    #[serde(alias = "ns")]
    NS,

    /// Next Secure record
    #[serde(alias = "nsec")]
    NSEC,

    /// Next Secure record version 3
    #[serde(alias = "nsec3param")]
    NSEC3PARAM,

    /// OpenPGP public key record
    #[serde(alias = "openpgpkey")]
    OPENPGPKEY,

    /// Pointer record
    #[serde(alias = "ptr")]
    PTR,

    /// Responsible Person for the domain
    #[serde(alias = "rp")]
    RP,

    /// DNSSEC signature
    #[serde(alias = "rrsig")]
    RRSIG,

    /// Signature record
    #[serde(alias = "sig")]
    SIG,

    /// S/MIME certificate association
    #[serde(alias = "smimea")]
    SMIMEA,

    /// Start of authoritative record
    #[serde(alias = "soa")]
    SOA,

    /// Service locator
    #[serde(alias = "srv")]
    SRV,

    /// SSH Public Key fingerprint
    #[serde(alias = "sshfp")]
    SSHFP,

    /// Service binding
    #[serde(alias = "svcb")]
    SVCB,

    /// DNSSEC trust authorities
    #[serde(alias = "ta")]
    TA,

    /// Transaction key record
    #[serde(alias = "tkey")]
    TKEY,

    /// Public key for main name
    #[serde(alias = "tlsa")]
    TLSA,

    /// Transaction Signature for authenticating dynamic updates
    #[serde(alias = "tsig")]
    TSIG,

    /// Text record
    #[serde(alias = "txt")]
    TXT,

    /// Uniform Resource Locator for mapping from hostnames
    #[serde(alias = "uri")]
    URI,

    /// Message digests for DNS zones
    #[serde(alias = "zonemd")]
    ZONEMD,
}

/// Popularity Entry info
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PopularityRankEntry {
    /// Timestamp
    #[cfg(feature = "chrono")]
    #[serde(with = "ts_seconds")]
    pub timestamp: DateTime<Utc>,

    /// Timestamp
    #[cfg(not(feature = "chrono"))]
    pub timestamp: u64,

    /// Rank
    pub rank: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::ReportRequestResponse;

    #[test]
    fn haiku_org() {
        const DOMAIN_REPORT: &str = include_str!("../../testdata/haikuorg.json");

        let report: ReportRequestResponse<DomainReportData> =
            serde_json::from_str(DOMAIN_REPORT).expect("failed to deserialize VT report");

        let report = if let ReportRequestResponse::Data(data) = report {
            data
        } else {
            panic!("expected data");
        };

        eprintln!("Remaining fields: {}", report.attributes.extra.len());
        eprintln!("{:?}", report.attributes.extra);
        assert!(report.attributes.extra.is_empty());
    }
}
