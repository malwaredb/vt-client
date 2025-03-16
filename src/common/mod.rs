// SPDX-License-Identifier: Apache-2.0

use crate::VirusTotalError;

use serde::{Deserialize, Serialize};

/// Report response, which could return data (success confirmation) or an error message
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ReportRequestResponse<R> {
    /// Information about the report request
    #[serde(rename = "data")]
    Data(R),

    /// Error message, report request not successful
    #[serde(rename = "error")]
    Error(VirusTotalError),
}

/// Result per each anti-virus product
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnalysisResult {
    /// Type of file or threat
    pub category: String,

    /// Anti-virus engine
    pub engine_name: String,

    /// Version of the antivirus engine
    pub engine_version: Option<String>,

    /// Name of the malware identified
    pub result: Option<String>,

    /// Method for identifying the malware
    pub method: String,

    /// The date of the antivirus engine
    pub engine_update: Option<String>,
}

/// Last Analysis Stats
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LastAnalysisStats {
    /// Antivirus products which indicate this file is harmless
    pub harmless: u32,

    /// Antivirus products which don't support this file type
    #[serde(rename = "type-unsupported", default)]
    pub type_unsupported: Option<u32>,

    /// Antivirus products which indicate the file is suspicious
    pub suspicious: u32,

    /// Antivirus products which timed out trying to evaluate the file
    #[serde(rename = "confirmed-timeout", default)]
    pub confirmed_timeout: Option<u32>,

    /// Antivirus products which timed out trying to evaluate the file
    pub timeout: u32,

    /// Antivirus products which failed to analyze the file
    #[serde(default)]
    pub failure: Option<u32>,

    /// Antivirus products which indicate the file is malicious
    pub malicious: u32,

    /// Antivirus products which didn't detect a known malware type
    pub undetected: u32,
}

impl LastAnalysisStats {
    /// Return the number of antivirus products which could have evaluated this file,
    /// and exclude errors, including unsupported file type.
    pub fn av_count(&self) -> u32 {
        self.harmless + self.suspicious + self.malicious + self.undetected
    }

    /// Return the number of antivirus products which think the file is benign,
    /// which is harmless and undetected
    pub fn safe_count(&self) -> u32 {
        self.harmless + self.undetected
    }

    /// Return the number of antivirus products which had errors for this file
    pub fn error_count(&self) -> u32 {
        self.type_unsupported.unwrap_or_default()
            + self.confirmed_timeout.unwrap_or_default()
            + self.timeout
            + self.failure.unwrap_or_default()
    }

    /// In an effort to error on the side of caution, call a file benign is no antivirus products
    /// call it malicious or suspicious
    pub fn is_benign(&self) -> bool {
        self.malicious == 0 && self.suspicious == 0
    }
}

/// Community votes whether a file is benign or malicious
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Votes {
    /// Votes that the file is harmless
    pub harmless: u32,

    /// Votes that the file is malicious
    pub malicious: u32,
}
