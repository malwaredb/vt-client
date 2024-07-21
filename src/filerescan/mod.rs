use crate::VirusTotalError;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// File rescan response, which could return data (success confirmation) or an error message
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FileRescanRequestResponse {
    /// Information about the rescan request
    #[serde(rename = "data")]
    Data(FileRescanRequestData),

    /// Error message, file rescan not successful
    #[serde(rename = "error")]
    Error(VirusTotalError),
}

/// Successful file rescan response contents
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileRescanRequestData {
    /// Rescan type, probably "analysis"
    #[serde(rename = "type")]
    pub rescan_type: String,

    /// Rescan ID, likely not useful
    pub id: String,

    /// Links to the file analysis
    pub links: HashMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_valid_response() {
        const RESPONSE: &str = include_str!("../../testdata/rescan.json");

        let rescan: FileRescanRequestResponse =
            serde_json::from_str(RESPONSE).expect("failed to deserialize VT rescan");

        if let FileRescanRequestResponse::Data(data) = rescan {
            assert_eq!(data.rescan_type, "analysis");
        } else {
            panic!("Rescan report shouldn't be an error type");
        }
    }
}
