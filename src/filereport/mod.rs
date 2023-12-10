use crate::VirusTotalError;

use chrono::serde::{ts_seconds, ts_seconds_option};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Serialize, Deserialize)]
pub enum FileReportRequestResponse {
    #[serde(rename = "data")]
    Data(FileReportData),
    #[serde(rename = "error")]
    Error(VirusTotalError),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileReportData {
    pub attributes: ScanResultAttributes,

    #[serde(rename = "type")]
    pub record_type: String,
    pub id: String,
    pub links: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResultAttributes {
    /// When the file was created, often spoofed by malware
    #[serde(default, with = "ts_seconds_option")]
    pub creation_date: Option<DateTime<Utc>>,

    /// List of tags related to the file's capabilities
    /// Requires VirusTotal Premium
    pub capabilities_tags: Option<Vec<String>>,

    /// A description of the file type
    pub type_description: String,

    /// Trend Micro's Locality Sensitive Hash: https://tlsh.org/
    pub tlsh: Option<String>,

    /// VirusTotal's custom algorithm for clustering similar files
    pub vhash: Option<String>,

    /// Tags which may show further details of the file type
    pub type_tags: Vec<String>,

    /// File names this sample has had when submitted to VirusTotal
    pub names: Vec<String>,

    /// When when the file was last modified
    #[serde(with = "ts_seconds")]
    pub last_modification_date: DateTime<Utc>,

    /// Type tags which can be used with VirusTotal Intelligence
    pub type_tag: String,

    /// The number of times the file has been submitted to VirusTotal
    pub times_submitted: u32,

    /// Votes from the VirusTotal user community as to whether or not the file is dangerous
    pub total_votes: Votes,

    /// Size of the file, in bytes
    pub size: u64,

    /// Community votes as to the nature of the thread of this file
    pub popular_threat_classification: Option<PopularThreatClassification>,

    /// When the file was last submitted to VirusTotal
    #[serde(with = "ts_seconds")]
    pub last_submission_date: DateTime<Utc>,

    /// Anti-virus results, where the key is the name of the anti-virus software product
    pub last_analysis_results: HashMap<String, AnalysisResult>,

    /// Results from TrID, an attempt to identify the file type
    /// See https://mark0.net/soft-trid-e.html
    pub trid: Option<Vec<TrID>>,

    /// SHA-256 hash of the file
    pub sha256: String,

    /// File extension for this file type
    pub type_extension: String,

    /// When the file was last analyzed by VirusTotal
    #[serde(with = "ts_seconds")]
    pub last_analysis_date: DateTime<Utc>,

    /// The number of unique sources which have submitted this file
    pub unique_sources: u32,

    /// When the file was first submitted to VirusTotal
    #[serde(with = "ts_seconds")]
    pub first_submission_date: DateTime<Utc>,

    /// MD-5 hash of the file
    pub md5: String,

    /// SSDeep fuzzy hash of the file
    /// See https://ssdeep-project.github.io/ssdeep/index.html
    pub ssdeep: String,

    /// SHA-1 of the file
    pub sha1: String,

    /// The output from libmagic, the `file` command for this file
    pub magic: String,

    /// Anti-virus summary
    pub last_analysis_stats: LastAnalysisStats,

    /// The most interesting name of all the file names used with this file
    pub meaningful_name: String,

    /// The file's reputation from all votes,
    /// see https://support.virustotal.com/hc/en-us/articles/115002146769-Vote-comment
    pub reputation: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Votes {
    /// Votes that the file is harmless
    pub harmless: u32,

    /// Votes that the file is malicious
    pub malicious: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PopularThreatClassification {
    pub suggested_threat_label: String,
    pub popular_threat_category: Vec<PopularThreatClassificationInner>,
    pub popular_threat_name: Vec<PopularThreatClassificationInner>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PopularThreatClassificationInner {
    /// Votes for this threat type
    pub count: u32,

    /// Type of threat
    pub value: String,
}

/// Result per each anti-virus product
#[derive(Debug, Serialize, Deserialize)]
pub struct AnalysisResult {
    /// Type of file or threat
    pub category: String,

    /// Anti-virus engine
    pub engine_name: String,

    /// Version of the anti-virus engine
    pub engine_version: Option<String>,

    /// Name of the malware identified
    pub result: Option<String>,

    /// Method for identifying the malware
    pub method: String,

    /// The date of the anti-virus engine
    pub engine_update: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrID {
    /// Detected file type
    pub file_type: String,

    /// Probability the file is of this type
    pub probability: f32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LastAnalysisStats {
    /// Anti-virus products which indicate this file is harmless
    pub harmless: u32,

    /// Anti-virus products which don't support this file type
    #[serde(rename = "type-unsupported")]
    pub type_unsupported: u32,

    /// Anti-virus products which indicate the file is suspicious
    pub suspicious: u32,

    /// Anti-virus products which timed out trying to evaluate the file
    #[serde(rename = "confirmed-timeout")]
    pub confirmed_timeout: u32,

    /// Anti-virus products which timed out trying to evaluate the file
    pub timeout: u32,

    /// Anti-virus products which failed to analyze the file
    pub failure: u32,

    /// Anti-virus products which indicate the file is malicious
    pub malicious: u32,

    /// Anti-virus products which didn't detect a known malware type
    pub undetected: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;
    use rstest::rstest;

    #[rstest]
    #[case(include_str!("../../testdata/fff40032c3dc062147c530e3a0a5c7e6acda4d1f1369fbc994cddd3c19a2de88.json"), "Rich Text Format")]
    #[case(include_str!("../../testdata/0001a1252300b4732e4a010a5dd13a291dcb8b0ebee6febedb5152dfb0bcd488.json"), "DOS COM")]
    #[case(include_str!("../../testdata/001015aafcae8a6942366cbb0e7d39c0738752a7800c41ea1c655d47b0a4d04c.json"), "MS Word Document")]
    fn deserialize_valid_report(#[case] report: &str, #[case] file_type: &str) {
        let report: FileReportRequestResponse = serde_json::from_str(report)
            .context("failed to deserialize VT report")
            .unwrap();

        if let FileReportRequestResponse::Data(data) = report {
            println!("{data:?}");
            assert_eq!(data.attributes.type_description, file_type);
            assert_eq!(data.record_type, "file");
        } else {
            panic!("File wasn't a report!");
        }
    }

    #[rstest]
    #[case(include_str!("../../testdata/not_found.json"))]
    #[case(include_str!("../../testdata/wrong_key.json"))]
    fn deserialize_errors(#[case] contents: &str) {
        let report: FileReportRequestResponse = serde_json::from_str(contents)
            .context("failed to deserialize VT error response")
            .unwrap();

        match report {
            FileReportRequestResponse::Data(_) => panic!("Should have been an error type!"),
            FileReportRequestResponse::Error(_) => {}
        }
    }
}
