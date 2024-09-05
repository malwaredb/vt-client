/// Flags for an easier way of specifying what's being sought in VirusTotal, enabling the use
/// of Rust objects to build out the syntax expected by VirusTotal.
pub mod flags;

use serde::{Deserialize, Serialize};

/// Response from VirusTotal for a file search
/// [https://virustotal.readme.io/v2.0/reference/file-search]
#[derive(Debug, Deserialize, Serialize)]
pub struct FileSearchResponse {
    /// Response status code
    pub response_code: u32,

    /// Offset, used for paginating search results, if more results are available
    pub offset: Option<String>,

    /// Hashes of files which match the search criteria. Maximum of 300 results.
    pub hashes: Vec<String>,

    /// Original query
    #[serde(default)]
    pub query: String,

    /// Message from VirusTotal about the search results
    pub verbose_msg: Option<String>,
}
