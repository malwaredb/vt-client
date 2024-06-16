pub mod errors;
pub mod filereport;
pub mod filerescan;
pub mod filesearch;

use crate::filereport::{FileReportData, FileReportRequestResponse};
use crate::filerescan::{FileRescanRequestData, FileRescanRequestResponse};
use crate::filesearch::FileSearchResponse;

use std::borrow::Cow;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use std::string::FromUtf8Error;

use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::multipart::Form;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Capture the error from VirusTotal, plus parsing or networking errors along the way
#[derive(Clone, Debug, Eq, Serialize, Deserialize)]
pub struct VirusTotalError {
    /// Message describing the error
    pub message: String,

    /// Short version of the error
    pub code: String,
}

impl PartialEq for VirusTotalError {
    fn eq(&self, other: &VirusTotalError) -> bool {
        // Only check the code, since the VT error messages don't always match their documentation.
        self.code.to_lowercase() == other.code.to_lowercase()
    }
}

impl Display for VirusTotalError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for VirusTotalError {}

impl From<reqwest::Error> for VirusTotalError {
    fn from(err: reqwest::Error) -> Self {
        let url = if let Some(url) = err.url() {
            format!(" loading {url}")
        } else {
            "".into()
        };
        Self {
            message: "Http error".into(),
            code: format!("Error{url} {err}"),
        }
    }
}

impl From<serde_json::Error> for VirusTotalError {
    fn from(err: serde_json::Error) -> Self {
        Self {
            message: "Json error".into(),
            code: format!("Json error at line {}: {err}", err.line()),
        }
    }
}

impl From<FromUtf8Error> for VirusTotalError {
    fn from(err: FromUtf8Error) -> Self {
        Self {
            message: "UTF-8 decoding error".into(),
            code: err.to_string(),
        }
    }
}

/// VirusTotal client object
#[derive(Clone)]
pub struct VirusTotalClient {
    /// The API key used to interact with VirusTotal
    key: Zeroizing<String>,
}

impl VirusTotalClient {
    /// Header used to send the API key to VirusTotal
    pub const API_KEY: &'static str = "x-apikey";

    /// Length of the API key
    pub const KEY_LEN: usize = 64;

    /// New VirusTotal client given an API key which is assumed to be valid.
    pub fn new(key: String) -> Self {
        Self {
            key: Zeroizing::new(key),
        }
    }

    fn header(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            VirusTotalClient::API_KEY,
            HeaderValue::from_str(&self.key).unwrap(),
        );
        headers
    }

    /// Get a file report from VirusTotal for an MD5, SHA-1, or SHA-256 hash, which is assumed to be valid.
    pub async fn get_report(&self, file_hash: &str) -> Result<FileReportData, VirusTotalError> {
        let client = reqwest::Client::new();
        let body = client
            .get(format!(
                "https://www.virustotal.com/api/v3/files/{file_hash}"
            ))
            .headers(self.header())
            .send()
            .await?
            .bytes()
            .await?;

        let json_response = String::from_utf8(body.to_ascii_lowercase())?;
        let report: FileReportRequestResponse = serde_json::from_str(&json_response)?;

        match report {
            FileReportRequestResponse::Data(data) => Ok(data),
            FileReportRequestResponse::Error(error) => Err(error),
        }
    }

    /// Request VirusTotal rescan a file for an MD5, SHA-1, or SHA-256 hash, which is assumed to be valid.
    pub async fn request_rescan(
        &self,
        file_hash: &str,
    ) -> Result<FileRescanRequestData, VirusTotalError> {
        let client = reqwest::Client::new();
        let body = client
            .post(format!(
                "https://www.virustotal.com/api/v3/files/{file_hash}/analyse"
            ))
            .headers(self.header())
            .header("content-length", "0")
            .send()
            .await?
            .bytes()
            .await?;

        let json_response = String::from_utf8(body.to_ascii_lowercase())?;
        let report: FileRescanRequestResponse = serde_json::from_str(&json_response)?;

        match report {
            FileRescanRequestResponse::Data(data) => Ok(data),
            FileRescanRequestResponse::Error(error) => Err(error),
        }
    }

    /// Submit a file to VirusTotal.
    pub async fn submit<D, N>(
        &self,
        data: D,
        name: Option<N>,
    ) -> Result<FileRescanRequestData, VirusTotalError>
    where
        D: Into<Cow<'static, [u8]>>,
        N: Into<Cow<'static, str>>,
    {
        let client = reqwest::Client::new();
        let form = if let Some(file_name) = name {
            Form::new().part(
                "file",
                reqwest::multipart::Part::bytes(data)
                    .file_name(file_name)
                    .mime_str("application/octet-stream")?,
            )
        } else {
            Form::new().part(
                "file",
                reqwest::multipart::Part::bytes(data).mime_str("application/octet-stream")?,
            )
        };

        let body = client
            .post("https://www.virustotal.com/api/v3/files")
            .headers(self.header())
            .header("accept", "application/json")
            .header("content-type", "multipart/form-data")
            .multipart(form)
            .send()
            .await?
            .bytes()
            .await?;
        let json_response = String::from_utf8(body.to_ascii_lowercase())?;
        let report: FileRescanRequestResponse = serde_json::from_str(&json_response)?;

        match report {
            FileRescanRequestResponse::Data(data) => Ok(data),
            FileRescanRequestResponse::Error(error) => Err(error),
        }
    }

    /// Download a file from VirusTotal, requires VirusTotal Premium!
    pub async fn download(&self, file_hash: &str) -> Result<Vec<u8>, VirusTotalError> {
        let client = reqwest::Client::new();
        let response = client
            .get(format!(
                "https://www.virustotal.com/api/v3/files/{file_hash}/download"
            ))
            .headers(self.header())
            .send()
            .await?;

        if !response.status().is_success() {
            let body = response.bytes().await?;
            let json_response = String::from_utf8(body.to_ascii_lowercase())?;

            // Just borrowing the `FileRescanResponseRequest` type get get it's error handling
            let error: FileRescanRequestResponse = serde_json::from_str(&json_response)?;
            return if let FileRescanRequestResponse::Error(error) = error {
                Err(error)
            } else {
                // Should never happen, since we're only here if some error occurred.
                Err(VirusTotalError {
                    message: json_response,
                    code: "VTError".into(),
                })
            };
        }

        let body = response.bytes().await?;

        Ok(body.to_vec())
    }

    /// Search VirusTotal for files matching some search parameters. Requires VT Premium!
    /// For more information see https://virustotal.readme.io/v2.0/reference/file-search.
    /// Note: This uses the V2 API.
    pub async fn search(&self, query: &str) -> Result<FileSearchResponse, VirusTotalError> {
        let url = format!(
            "https://www.virustotal.com/vtapi/v2/file/search?apikey={}&query={query}",
            self.key.as_str()
        );

        let body = reqwest::get(url).await?.bytes().await?;
        let json_response = String::from_utf8(body.to_ascii_lowercase())?;
        let response: FileSearchResponse = serde_json::from_str(&json_response)?;

        let response = FileSearchResponse {
            response_code: response.response_code,
            offset: response.offset,
            hashes: response.hashes,
            query: query.to_string(),
        };
        Ok(response)
    }

    /// Search VirusTotal for files matching some search parameters. Requires VT Premium!
    /// Use this to continue from a prior search for the next 300 results.
    pub async fn search_offset(
        &self,
        prior: &FileSearchResponse,
    ) -> Result<FileSearchResponse, VirusTotalError> {
        let url = format!(
            "https://www.virustotal.com/vtapi/v2/file/search?apikey={}&query={}&offset={}",
            self.key.as_str(),
            prior.query,
            prior.offset
        );

        let body = reqwest::get(url).await?.bytes().await?;
        let json_response = String::from_utf8(body.to_ascii_lowercase())?;
        let response: FileSearchResponse = serde_json::from_str(&json_response)?;

        let response = FileSearchResponse {
            response_code: response.response_code,
            offset: response.offset,
            hashes: response.hashes,
            query: prior.query.clone(),
        };
        Ok(response)
    }
}

/// Get a VirusTotal client from a key, checking that the key is the expected length.
impl FromStr for VirusTotalClient {
    type Err = &'static str;

    fn from_str(key: &str) -> Result<Self, Self::Err> {
        if key.len() != VirusTotalClient::KEY_LEN {
            Err("Invalid API key length")
        } else {
            Ok(Self {
                key: Zeroizing::new(key.to_string()),
            })
        }
    }
}

impl From<String> for VirusTotalClient {
    fn from(value: String) -> Self {
        VirusTotalClient::new(value)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    #[ignore]
    async fn api() {
        if let Ok(api_key) = std::env::var("VT_API_KEY") {
            const HASH: &str = "fff40032c3dc062147c530e3a0a5c7e6acda4d1f1369fbc994cddd3c19a2de88";

            let client = VirusTotalClient::new(api_key);

            let report = client
                .get_report(HASH)
                .await
                .expect("failed to get or parse VT scan report");
            assert!(report.attributes.last_analysis_results.len() > 10);

            let rescan = client
                .request_rescan(HASH)
                .await
                .expect("failed to get or parse VT rescan response");
            assert_eq!(rescan.rescan_type, "analysis");

            const ELF: &[u8] = include_bytes!("../testdata/elf_haiku_x86");
            client
                .submit(Vec::from(ELF), Some("elf_haiku_x86".to_string()))
                .await
                .unwrap();

            match client.get_report("AABBCCDD").await {
                Ok(_) => {
                    unreachable!("No way this should work");
                }
                Err(err) => {
                    assert_eq!(err, *crate::errors::NOT_FOUND_ERROR);
                }
            }

            let response = client
                .download("abc91ba39ea3220d23458f8049ed900c16ce1023")
                .await;
            match response {
                Ok(_) => {
                    unreachable!("This shouldn't work, unless you have VT Premium")
                }
                Err(e) => {
                    assert_eq!(e, *crate::errors::FORBIDDEN_ERROR);
                }
            }
        } else {
            panic!("`VT_API_KEY` not set!")
        }
    }
}
