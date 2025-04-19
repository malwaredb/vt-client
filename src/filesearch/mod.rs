// SPDX-License-Identifier: Apache-2.0

/// Flags for an easier way of specifying what's being sought in Virus Total, enabling the use
/// of Rust objects to build out the syntax expected by Virus Total.
pub mod flags;

use serde::{Deserialize, Serialize};

/// File search results
/// <https://virustotal.readme.io/v2.0/reference/file-search>
#[derive(Debug, Deserialize, Serialize)]
pub struct FileSearchResponse {
    /// Response status code
    pub response_code: u32,

    /// Offset, used for paginating search results if more results are available
    pub offset: Option<String>,

    /// Hashes of files which match the search criteria, if any. Maximum of 300 results.
    #[serde(default)]
    pub hashes: Vec<String>,

    /// Original query
    #[serde(default)]
    pub query: String,

    /// Message from Virus Total about the search results
    pub verbose_msg: Option<String>,
}
