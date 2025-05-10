// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![forbid(unsafe_code)]

/// Data types common to a few data types
pub mod common;
/// Logic for parsing the domain report data from Virus Total
pub mod domainreport;
/// Pre-defined error types for Virus Total allowing for error comparison.
/// <https://virustotal.readme.io/reference/errors>
pub mod errors;
/// Logic for parsing the file report data from Virus Total
pub mod filereport;
/// Logic for searching for files based on types, submission, and attributes
pub mod filesearch;
/// Logic for parsing the IP report data from Virus Total
pub mod ipreport;

use crate::common::{RecordType, ReportRequestResponse, ReportResponseHeader, RescanRequestData};
use crate::domainreport::DomainAttributes;
use crate::errors::VirusTotalError;
use crate::filereport::ScanResultAttributes;
use crate::filesearch::FileSearchResponse;
use crate::ipreport::IPAttributes;

use std::borrow::Cow;
use std::fmt::{Debug, Display, Formatter};
use std::path::Path;
use std::str::FromStr;

use bytes::Bytes;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::multipart::{Form, Part};
use serde::{Deserialize, Serialize, Serializer};
use zeroize::{Zeroize, ZeroizeOnDrop};

const THIRTY_TWO_MEGABYTES: u64 = 32 * 1024 * 1024;

/// Virus Total client object
#[derive(Clone, Deserialize, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(feature = "clap", derive(clap::Args))]
pub struct VirusTotalClient {
    /// The API key used to interact with Virus Total
    #[cfg_attr(feature = "clap", arg(long, env = "VT_API_KEY"))]
    #[serde(alias = "vt_api_key")]
    key: String,
}

impl Debug for VirusTotalClient {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "VirusTotal Client v{}", env!("CARGO_PKG_VERSION"))
    }
}

impl Serialize for VirusTotalClient {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[cfg(feature = "unsafe-serialization")]
        return serializer.serialize_str(&self.key);

        #[cfg(not(feature = "unsafe-serialization"))]
        serializer.serialize_str("your-api-key-here")
    }
}

impl VirusTotalClient {
    /// Header used to send the API key to Virus Total
    const API_KEY: &'static str = "x-apikey";

    /// Length of the API key
    pub const KEY_LEN: usize = 64;

    /// New Virus Total client given an API key which is assumed to be valid.
    #[must_use]
    pub fn new(key: String) -> Self {
        Self { key }
    }

    /// Generate a client which already knows to send the API key, and asks for gzip responses.
    #[inline]
    fn client(&self) -> Result<reqwest::Client, VirusTotalError> {
        let mut headers = HeaderMap::new();
        headers.insert(
            VirusTotalClient::API_KEY,
            HeaderValue::from_str(&self.key).unwrap(),
        );

        reqwest::ClientBuilder::new()
            .gzip(true)
            .default_headers(headers)
            .build()
            .map_err(|e| {
                #[cfg(feature = "tracing")]
                tracing::error!("Error creating VirusTotal client: {e}");
                e.into()
            })
    }

    /// Get the unparsed report from Virus Total for a known type.
    ///
    /// File: report given an MD5, SHA-1, or SHA-256 hash
    /// Domain: a fully qualified domain name
    /// IP address: an ip address
    ///
    /// # Errors
    ///
    /// Will return an error if there is a networking problem.
    #[inline]
    pub async fn get_report_raw(
        &self,
        record_type: RecordType,
        resource: &str,
    ) -> Result<Bytes, VirusTotalError> {
        self.other(&format!("{record_type}/{resource}")).await
    }

    /// Get a parsed file report from Virus Total for an MD5, SHA-1, or SHA-256 hash, which is assumed to be valid.
    ///
    /// # Errors
    ///
    /// Will return an error if there is a networking problem or if the response wasn't expected.
    pub async fn get_file_report(
        &self,
        file_hash: &str,
    ) -> Result<ReportResponseHeader<ScanResultAttributes>, VirusTotalError> {
        let body = self.get_report_raw(RecordType::File, file_hash).await?;
        let json_response = String::from_utf8(body.to_ascii_lowercase())
            .map_err(|_e| VirusTotalError::UTF8Error(body.to_vec()))?;
        let report: ReportRequestResponse<ReportResponseHeader<ScanResultAttributes>> =
            VirusTotalError::parse_json(&json_response)?;

        match report {
            ReportRequestResponse::Data(data) => Ok(data),
            ReportRequestResponse::Error(error) => Err(error),
        }
    }

    /// Request Virus Total rescan a file for an MD5, SHA-1, or SHA-256 hash, and receive the unparsed response
    ///
    /// # Errors
    ///
    /// Will return an error if there is a networking problem.
    #[inline]
    pub async fn request_file_rescan_raw(&self, file_hash: &str) -> Result<Bytes, VirusTotalError> {
        self.request_rescan_raw(RecordType::File, file_hash).await
    }

    /// Request Virus Total rescan a file for an MD5, SHA-1, or SHA-256 hash, which is assumed to be valid.
    ///
    /// ```rust,no_run
    /// use malwaredb_virustotal::VirusTotalClient;
    ///
    /// // Use of `.unwrap()` for demonstration, don't actually do this.
    /// let client = VirusTotalClient::new(std::env::var("VT_API_KEY").unwrap());
    /// # tokio_test::block_on(async {
    /// let response = client.request_file_rescan("abc91ba39ea3220d23458f8049ed900c16ce1023").await.unwrap();
    /// assert_eq!(response.rescan_type, "analysis");
    /// # })
    /// ```
    ///
    /// # Errors
    ///
    /// Will return an error if there is a networking problem or if the response wasn't expected.
    pub async fn request_file_rescan(
        &self,
        file_hash: &str,
    ) -> Result<RescanRequestData, VirusTotalError> {
        let body = self.request_file_rescan_raw(file_hash).await?;
        let json_response = String::from_utf8(body.to_ascii_lowercase())
            .map_err(|_e| VirusTotalError::UTF8Error(body.to_vec()))?;
        let report: ReportRequestResponse<RescanRequestData> =
            VirusTotalError::parse_json(&json_response)?;

        match report {
            ReportRequestResponse::Data(data) => Ok(data),
            ReportRequestResponse::Error(error) => Err(error),
        }
    }

    /// Submit a file by path to Virus Total and receive the unparsed response.
    ///
    /// # Errors
    ///
    /// Will return an error if there is a networking problem.
    #[inline]
    pub async fn submit_file_path_raw<P>(&self, path: P) -> Result<Bytes, VirusTotalError>
    where
        P: AsRef<Path>,
    {
        let client = self.client()?;

        #[cfg(feature = "tokio")]
        let file = tokio::fs::File::open(&path).await.map_err(|e| {
            #[cfg(feature = "tracing")]
            tracing::error!("Error opening file for VirusTotal submission: {e}");
            VirusTotalError::IOError(e.to_string())
        })?;

        #[cfg(not(feature = "tokio"))]
        let file = std::fs::File::open(&path).map_err(|e| {
            #[cfg(feature = "tracing")]
            tracing::error!("Error opening file for VirusTotal submission: {e}");
            VirusTotalError::IOError(e.to_string())
        })?;

        #[cfg(feature = "tokio")]
        let size = file
            .metadata()
            .await
            .map_err(|e| {
                #[cfg(feature = "tracing")]
                tracing::error!("Error getting file size: {e}");
                VirusTotalError::IOError(e.to_string())
            })?
            .len();

        #[cfg(not(feature = "tokio"))]
        let size = file
            .metadata()
            .map_err(|e| {
                #[cfg(feature = "tracing")]
                tracing::error!("Error getting file size: {e}");
                VirusTotalError::IOError(e.to_string())
            })?
            .len();

        let url = if size >= THIRTY_TWO_MEGABYTES {
            self.get_upload_url().await?
        } else {
            "https://www.virustotal.com/api/v3/files".to_string()
        };

        let form = Form::new()
            .file("file", path)
            .await
            .map_err(|e| VirusTotalError::IOError(e.to_string()))?;

        client
            .post(url)
            .header("accept", "application/json")
            .multipart(form)
            .send()
            .await
            .map_err(|e| {
                #[cfg(feature = "tracing")]
                tracing::error!("Error submitting VirusTotal file: {e}");
                e
            })?
            .bytes()
            .await
            .map_err(|e| {
                #[cfg(feature = "tracing")]
                tracing::error!("Error parsing VirusTotal file submission response: {e}");
                e.into()
            })
    }

    /// Submit a file by path to Virus Total and receive a parsed response.
    ///
    /// # Errors
    ///
    /// Will return an error if there is a networking problem or if the response wasn't expected.
    pub async fn submit_file_path<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<RescanRequestData, VirusTotalError> {
        let body = self.submit_file_path_raw(path).await?;
        let json_response = String::from_utf8(body.to_ascii_lowercase())
            .map_err(|_e| VirusTotalError::UTF8Error(body.to_vec()))?;
        let report: ReportRequestResponse<RescanRequestData> =
            VirusTotalError::parse_json(&json_response)?;

        match report {
            ReportRequestResponse::Data(data) => Ok(data),
            ReportRequestResponse::Error(error) => Err(error),
        }
    }

    /// Submit bytes to Virus Total and receive the unparsed response.
    ///
    /// # Errors
    ///
    /// Will return an error if there is a networking problem.
    #[inline]
    pub async fn submit_bytes_raw<N: Into<Cow<'static, str>>>(
        &self,
        data: Vec<u8>,
        name: N,
    ) -> Result<Bytes, VirusTotalError> {
        let client = self.client()?;

        // It's unfortunate that we had to take ownership of the bytes. This is because `Path::new()`
        // is private in `reqwest`. There is no other way to get the size.
        let url = if data.len() as u64 >= THIRTY_TWO_MEGABYTES {
            self.get_upload_url().await?
        } else {
            "https://www.virustotal.com/api/v3/files".to_string()
        };

        let form = Form::new().part(
            "file",
            Part::bytes(data)
                .file_name(name)
                .mime_str("application/octet-stream")?,
        );

        client
            .post(url)
            .header("accept", "application/json")
            .multipart(form)
            .send()
            .await
            .map_err(|e| {
                #[cfg(feature = "tracing")]
                tracing::error!("Error submitting VirusTotal bytes: {e}");
                e
            })?
            .bytes()
            .await
            .map_err(|e| {
                #[cfg(feature = "tracing")]
                tracing::error!("Error parsing VirusTotal bytes submission response: {e}");
                e.into()
            })
    }

    /// Submit bytes to Virus Total and receive a parsed response.
    ///
    /// # Errors
    ///
    /// Will return an error if there is a networking problem or if the response wasn't expected.
    pub async fn submit_bytes<N: Into<Cow<'static, str>>>(
        &self,
        data: Vec<u8>,
        name: N,
    ) -> Result<RescanRequestData, VirusTotalError> {
        let body = self.submit_bytes_raw(data, name).await?;
        let json_response = String::from_utf8(body.to_ascii_lowercase())
            .map_err(|_e| VirusTotalError::UTF8Error(body.to_vec()))?;
        let report: ReportRequestResponse<RescanRequestData> =
            VirusTotalError::parse_json(&json_response)?;

        match report {
            ReportRequestResponse::Data(data) => Ok(data),
            ReportRequestResponse::Error(error) => Err(error),
        }
    }

    /// Get a special one-time URL endpoint for submitting files larger than 32 MB
    ///
    /// # Errors
    ///
    /// Will return an error if there is a networking problem or if the response wasn't expected.
    #[inline]
    pub async fn get_upload_url(&self) -> Result<String, VirusTotalError> {
        let response = self.other("files/upload_url").await?;
        let response = String::from_utf8(response.to_vec())
            .map_err(|_e| VirusTotalError::UTF8Error(response.to_vec()))?;
        let response = serde_json::from_str::<serde_json::Value>(&response)
            .map_err(|_e| VirusTotalError::JsonError(response))?;
        let url = response["data"]
            .as_str()
            .ok_or(VirusTotalError::NoURLReturned)?;
        Ok(url.to_string())
    }

    /// Download a file from Virus Total, requires Virus Total Premium!
    ///
    /// ```rust,no_run
    /// use malwaredb_virustotal::VirusTotalClient;
    ///
    /// // Use of `.unwrap()` for demonstration, don't actually do this.
    /// let client = VirusTotalClient::new(std::env::var("VT_API_KEY").unwrap());
    /// # tokio_test::block_on(async {
    /// let file_contents = client.download("abc91ba39ea3220d23458f8049ed900c16ce1023").await.unwrap();
    /// # })
    /// ```
    ///
    /// # Errors
    ///
    /// Will return an error if there is a networking problem.
    pub async fn download(&self, file_hash: &str) -> Result<Vec<u8>, VirusTotalError> {
        let client = self.client()?;
        let response = client
            .get(format!(
                "https://www.virustotal.com/api/v3/files/{file_hash}/download"
            ))
            .send()
            .await?;

        if !response.status().is_success() {
            let body = response.bytes().await?;
            let json_response = String::from_utf8(body.to_ascii_lowercase())
                .map_err(|_e| VirusTotalError::UTF8Error(body.to_vec()))?;

            let error: ReportRequestResponse<RescanRequestData> =
                VirusTotalError::parse_json(&json_response)?;
            return if let ReportRequestResponse::Error(error) = error {
                Err(error)
            } else {
                // Should never happen, since we're only here if some error occurred.
                Err(VirusTotalError::UnknownError)
            };
        }

        Ok(response
            .bytes()
            .await
            .map_err(|e| {
                #[cfg(feature = "tracing")]
                tracing::error!("Error parsing VirusTotal file response: {e}");
                e
            })?
            .to_vec())
    }

    /// Search Virus Total for files matching some search parameters, receive unparsed response.
    /// Requires VT Premium!
    ///
    /// # Errors
    ///
    /// Will return an error if there is a networking problem.
    #[inline]
    pub async fn search_raw<Q: Display>(&self, query: Q) -> Result<Bytes, VirusTotalError> {
        let url = format!(
            "https://www.virustotal.com/vtapi/v2/file/search?apikey={}&query={query}",
            self.key.as_str()
        );

        self.client()?
            .get(url)
            .send()
            .await?
            .bytes()
            .await
            .map_err(|e| {
                #[cfg(feature = "tracing")]
                tracing::error!("Error parsing VirusTotal search result: {e}");
                e.into()
            })
    }

    /// Search Virus Total for files matching some search parameters. Requires VT Premium!
    /// For more information see <https://virustotal.readme.io/v2.0/reference/file-search>.
    /// Note: This uses the V2 API.
    /// Example:
    ///
    /// ```rust,no_run
    /// use malwaredb_virustotal::{VirusTotalClient, filesearch::flags};
    ///
    /// // Use of `.unwrap()` for demonstration, don't actually do this.
    /// let client = VirusTotalClient::new(std::env::var("VT_API_KEY").unwrap());
    /// // Find PDFs, which are benign, have a fill-able form, and Javascript, first seen yesterday
    /// # tokio_test::block_on(async {
    /// #[cfg(not(feature = "chrono"))]
    /// let result = client.search(flags::FileType::Pdf + flags::BENIGN + flags::Tag::PdfForm + flags::Tag::PdfJs).await.unwrap();
    /// #[cfg(feature = "chrono")]
    /// let result = client.search(flags::FileType::Pdf + flags::BENIGN + flags::Tag::PdfForm + flags::Tag::PdfJs + flags::FirstSubmission::days(1)).await.unwrap();
    /// # })
    /// ```
    ///
    /// # Errors
    ///
    /// Will return an error if there is a networking problem or if the response wasn't expected.
    pub async fn search<Q: Display>(
        &self,
        query: Q,
    ) -> Result<FileSearchResponse, VirusTotalError> {
        let body = self.search_raw(&query).await?;
        let json_response = String::from_utf8(body.to_ascii_lowercase())
            .map_err(|_e| VirusTotalError::UTF8Error(body.to_vec()))?;
        let response: FileSearchResponse = VirusTotalError::parse_json(&json_response)?;

        let response = FileSearchResponse {
            response_code: response.response_code,
            offset: response.offset,
            hashes: response.hashes,
            query: query.to_string(),
            verbose_msg: response.verbose_msg,
        };
        Ok(response)
    }

    /// Search Virus Total for files matching some search parameters. Requires VT Premium!
    /// Use this to continue from a prior search for the next 300 results. Requires parsed response
    /// via [`Self::search()`]
    ///
    /// # Errors
    ///
    /// Will return an error if there is a networking problem or if the response wasn't expected.
    pub async fn search_offset(
        &self,
        prior: &FileSearchResponse,
    ) -> Result<FileSearchResponse, VirusTotalError> {
        if let Some(offset) = prior.offset.as_ref() {
            let url = format!(
                "https://www.virustotal.com/vtapi/v2/file/search?apikey={}&query={}&offset={}",
                self.key.as_str(),
                prior.query,
                offset
            );

            let body = self.client()?.get(url).send().await?.bytes().await?;
            let json_response = String::from_utf8(body.to_ascii_lowercase())
                .map_err(|_e| VirusTotalError::UTF8Error(body.to_vec()))?;
            let response: FileSearchResponse = VirusTotalError::parse_json(&json_response)?;

            let response = FileSearchResponse {
                response_code: response.response_code,
                offset: response.offset,
                hashes: response.hashes,
                query: prior.query.clone(),
                verbose_msg: response.verbose_msg,
            };
            Ok(response)
        } else {
            Err(VirusTotalError::NonPaginatedResults)
        }
    }

    /// Get a Virus Total report for a domain, returning the parsed response
    ///
    /// # Errors
    ///
    /// Will return an error if there is a networking problem or if the response wasn't expected.
    pub async fn get_domain_report(
        &self,
        domain: &str,
    ) -> Result<ReportResponseHeader<DomainAttributes>, VirusTotalError> {
        let body = self.get_report_raw(RecordType::Domain, domain).await?;
        let json_response = String::from_utf8(body.to_ascii_lowercase())
            .map_err(|_e| VirusTotalError::UTF8Error(body.to_vec()))?;
        let report: ReportRequestResponse<ReportResponseHeader<DomainAttributes>> =
            VirusTotalError::parse_json(&json_response)?;

        match report {
            ReportRequestResponse::Data(data) => Ok(data),
            ReportRequestResponse::Error(error) => Err(error),
        }
    }

    /// Request rescan of a domain and receive parsed response
    ///
    /// # Errors
    ///
    /// Will return an error if there is a networking problem or if the response wasn't expected.
    pub async fn request_domain_rescan(
        &self,
        domain: &str,
    ) -> Result<RescanRequestData, VirusTotalError> {
        let body = self.request_domain_rescan_raw(domain).await?;
        let json_response = String::from_utf8(body.to_ascii_lowercase())
            .map_err(|_e| VirusTotalError::UTF8Error(body.to_vec()))?;
        let report: ReportRequestResponse<RescanRequestData> =
            VirusTotalError::parse_json(&json_response)?;

        match report {
            ReportRequestResponse::Data(data) => Ok(data),
            ReportRequestResponse::Error(error) => Err(error),
        }
    }

    /// Request rescan of a domain and receive the unparsed response
    ///
    /// # Errors
    ///
    /// Will return an error if there is a networking problem.
    #[inline]
    pub async fn request_domain_rescan_raw(&self, domain: &str) -> Result<Bytes, VirusTotalError> {
        self.request_rescan_raw(RecordType::Domain, domain).await
    }

    /// Request Virus Total rescan of a file or domain, internally used
    ///
    /// # Errors
    ///
    /// Will return an error if there is a networking problem.
    #[inline]
    async fn request_rescan_raw(
        &self,
        rescan_type: RecordType,
        identifier: &str,
    ) -> Result<Bytes, VirusTotalError> {
        self.client()?
            .post(format!(
                "https://www.virustotal.com/api/v3/{rescan_type}/{identifier}/analyse"
            ))
            .header("content-length", "0")
            .send()
            .await
            .map_err(|e| {
                #[cfg(feature = "tracing")]
                tracing::error!("Error requesting VirusTotal rescan: {e}");
                e
            })?
            .bytes()
            .await
            .map_err(|e| {
                #[cfg(feature = "tracing")]
                tracing::error!("Error parsing VirusTotal rescan response: {e}");
                e.into()
            })
    }

    /// Get a Virus Total report for an IP address, returning the parsed response
    ///
    /// # Errors
    ///
    /// Will return an error if there is a networking problem or if the response wasn't expected.
    pub async fn get_ip_report(
        &self,
        ip: &str,
    ) -> Result<ReportResponseHeader<IPAttributes>, VirusTotalError> {
        let body = self.get_report_raw(RecordType::IPAddress, ip).await?;
        let json_response = String::from_utf8(body.to_ascii_lowercase())
            .map_err(|_e| VirusTotalError::UTF8Error(body.to_vec()))?;
        let report: ReportRequestResponse<ReportResponseHeader<IPAttributes>> =
            VirusTotalError::parse_json(&json_response)?;

        match report {
            ReportRequestResponse::Data(data) => Ok(data),
            ReportRequestResponse::Error(error) => Err(error),
        }
    }

    /// Request rescan of an IP address and receive the unparsed response
    ///
    /// # Errors
    ///
    /// Will return an error if there is a networking problem.
    #[inline]
    pub async fn request_ip_rescan_raw(&self, ip: &str) -> Result<Bytes, VirusTotalError> {
        self.request_rescan_raw(RecordType::IPAddress, ip).await
    }

    /// Request rescan of an IP address and receive parsed response
    ///
    /// # Errors
    ///
    /// Will return an error if there is a networking problem or if the response wasn't expected.
    pub async fn request_ip_rescan(&self, ip: &str) -> Result<RescanRequestData, VirusTotalError> {
        let body = self.request_ip_rescan_raw(ip).await?;
        let json_response = String::from_utf8(body.to_ascii_lowercase())
            .map_err(|_e| VirusTotalError::UTF8Error(body.to_vec()))?;
        let report: ReportRequestResponse<RescanRequestData> =
            VirusTotalError::parse_json(&json_response)?;

        match report {
            ReportRequestResponse::Data(data) => Ok(data),
            ReportRequestResponse::Error(error) => Err(error),
        }
    }

    /// Since this crate doesn't support every Virus Total feature, this function can receive a
    /// URL fragment and return the response.
    ///
    /// # Errors
    ///
    /// Will return an error if there is a networking problem.
    #[inline]
    pub async fn other(&self, url: &str) -> Result<Bytes, VirusTotalError> {
        let client = self.client()?;
        client
            .get(format!("https://www.virustotal.com/api/v3/{url}"))
            .send()
            .await
            .map_err(|e| {
                #[cfg(feature = "tracing")]
                tracing::error!("Error requesting VirusTotal other: {e}");
                VirusTotalError::NetworkError(e.to_string())
            })?
            .bytes()
            .await
            .map_err(|e| {
                #[cfg(feature = "tracing")]
                tracing::error!("Error parsing VirusTotal other response: {e}");
                VirusTotalError::NetworkError(e.to_string())
            })
    }
}

/// Get a Virus Total client from a key, checking that the key is the expected length.
impl FromStr for VirusTotalClient {
    type Err = &'static str;

    fn from_str(key: &str) -> Result<Self, Self::Err> {
        if key.len() == VirusTotalClient::KEY_LEN {
            Ok(Self {
                key: key.to_string(),
            })
        } else {
            Err("Invalid API key length")
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
    use sha2::{Digest, Sha256};

    const ELF: &[u8] = include_bytes!("../testdata/elf_haiku_x86");

    #[tokio::test]
    #[ignore]
    async fn api() {
        if let Ok(api_key) = std::env::var("VT_API_KEY") {
            const HASH: &str = "fff40032c3dc062147c530e3a0a5c7e6acda4d1f1369fbc994cddd3c19a2de88";

            let client = VirusTotalClient::new(api_key);

            let report = client
                .get_file_report(HASH)
                .await
                .expect("failed to get or parse VT scan report");
            assert!(report.attributes.last_analysis_results.len() > 10);

            let rescan = client
                .request_file_rescan(HASH)
                .await
                .expect("failed to get or parse VT rescan response");
            assert_eq!(rescan.rescan_type, "analysis");

            client
                .submit_bytes(Vec::from(ELF), "elf_haiku_x86".to_string())
                .await
                .unwrap();

            match client.get_file_report("AABBCCDD").await {
                Ok(_) => {
                    unreachable!("No way this should work");
                }
                Err(err) => {
                    assert_eq!(err, VirusTotalError::NotFoundError);
                }
            }

            let response = client
                .download("abc91ba39ea3220d23458f8049ed900c16ce1023")
                .await;
            match response {
                Ok(bytes) => {
                    let mut sha256 = Sha256::new();
                    sha256.update(&bytes);
                    let sha256 = sha256.finalize();
                    let sha256 = hex::encode(sha256);
                    assert_eq!(
                        sha256,
                        "de10ba5e5402b46ea975b5cb8a45eb7df9e81dc81012fd4efd145ed2dce3a740"
                    );
                }
                Err(e) => {
                    assert_eq!(e, VirusTotalError::ForbiddenError);
                }
            }

            let response = client.get_domain_report("haiku-os.org").await;
            match response {
                Ok(report) => {
                    println!("{:?}", report.attributes.extra);
                    assert!(report.attributes.extra.is_empty());
                }
                Err(e) => {
                    panic!("Domain report error: {e}");
                }
            }

            let response = client.request_domain_rescan("haiku-os.org").await;
            match response {
                Ok(report) => {
                    assert!(!report.links.is_empty());
                }
                Err(e) => {
                    panic!("Domain rescan error: {e}");
                }
            }

            let response = client
                .get_ip_report("23.53.35.49" /* phobos.apple.com */)
                .await;
            match response {
                Ok(report) => {
                    println!("{:?}", report.attributes.extra);
                    assert!(report.attributes.extra.is_empty());
                }
                Err(e) => {
                    panic!("IP address report error: {e}");
                }
            }
        } else {
            panic!("`VT_API_KEY` not set!")
        }
    }
}
