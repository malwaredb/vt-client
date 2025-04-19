// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct RawVTError {
    error: InnerVTError,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct InnerVTError {
    code: VirusTotalError,
    message: String,
}

/// Possible client errors from Virus Total for response parsing
/// See: <https://virustotal.readme.io/reference/errors>
#[derive(Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum VirusTotalError {
    /// The API request is invalid or malformed.
    #[serde(alias = "badrequesterror")]
    BadRequestError,

    /// Some of the provided arguments are incorrect.
    #[serde(alias = "invalidargumenterror")]
    InvalidArgumentError,

    /// The resource is not available yet but will become available later.
    #[serde(alias = "notavailableyet")]
    NotAvailableYet,

    /// Content search query is not selective enough.
    #[serde(alias = "unselectivecontentqueryerror")]
    UnselectiveContentQueryError,

    /// Unsupported content search query.
    #[serde(alias = "unsupportedcontentqueryerror")]
    UnsupportedContentQueryError,

    /// The operation requires an authenticated user. Verify that you have provided your API key.
    #[serde(alias = "authenticationrequirederror")]
    AuthenticationRequiredError,

    /// The user account is not active. Make sure you properly activated your account by following the link sent to your email.
    #[serde(alias = "usernotactiveerror")]
    UserNotActiveError,

    /// The provided API key is incorrect.
    #[serde(alias = "wrongcredentialserror")]
    WrongCredentialsError,

    /// You are not allowed to perform the requested operation.
    #[serde(alias = "forbiddenerror")]
    ForbiddenError,

    /// The requested resource was not found.
    #[serde(alias = "notfounderror")]
    NotFoundError,

    /// The resource already exists.
    #[serde(alias = "alreadyexistserror")]
    AlreadyExistsError,

    /// The request depended on another request, and that request failed.
    #[serde(alias = "faileddependencyerror")]
    FailedDependencyError,

    /// You have exceeded one of your quotas (minute, daily or monthly).
    #[serde(alias = "quotaexceedederror")]
    QuotaExceededError,

    /// Too many requests.
    #[serde(alias = "toomanyrequestserror")]
    TooManyRequestsError,

    /// Transient server error. Retry might work.
    #[serde(alias = "transienterror")]
    TransientError,

    /// The operation took too long to complete.
    #[serde(alias = "deadlineexceedederror")]
    DeadlineExceededError,

    /// If the custom upload endpoint URL request fails
    NoURLReturned,

    /// Json decoding error holding the string for which parsing failed
    JsonError(String),

    /// String UTF-8 decoding error holding the bytes for which parsing failed
    UTF8Error(Vec<u8>),

    /// Network error
    NetworkError(String),

    /// Error opening a file for submitting to Virus Total
    IOError(String),

    /// A search query didn't have an offset
    NonPaginatedResults,

    /// Some other unknown or unforeseen error occurred
    UnknownError,
}

impl VirusTotalError {
    /// Attempt to parse the desired response from Virus Total, or parse the error instead
    #[inline]
    pub(crate) fn parse_json<'a, T: Deserialize<'a>>(data: &'a str) -> Result<T, VirusTotalError> {
        let result: serde_json::error::Result<T> = serde_json::from_str(data);
        if let Ok(item) = result {
            return Ok(item);
        }

        match serde_json::from_str::<RawVTError>(data) {
            // If the error is a VirusTotal error
            Ok(item) => Err(item.error.code),

            // If the error was a failure to parse the VirusTotal report, return the string representation
            // This could be a malformed VirusTotal report or a malformed, or unknown error message.
            Err(e) => Err(VirusTotalError::JsonError(e.to_string())),
        }
    }

    /// Get the long message from the error
    #[must_use]
    pub fn message(&self) -> &'static str {
        match self {
            VirusTotalError::BadRequestError => "The API request is invalid or malformed.",
            VirusTotalError::InvalidArgumentError => "Some of the provided arguments are incorrect.",
            VirusTotalError::NotAvailableYet => "The resource is not available yet, but will become available later.",
            VirusTotalError::UnselectiveContentQueryError => "Content search query is not selective enough.",
            VirusTotalError::UnsupportedContentQueryError => "Unsupported content search query.",
            VirusTotalError::AuthenticationRequiredError => "The operation requires an authenticated user. Verify that you have provided your API key.",
            VirusTotalError::UserNotActiveError => "The user account is not active. Make sure you properly activated your account by following the link sent to your email.",
            VirusTotalError::WrongCredentialsError => "The provided API key is incorrect.",
            VirusTotalError::ForbiddenError => "You are not allowed to perform the requested operation.",
            VirusTotalError::NotFoundError => "The requested resource was not found.",
            VirusTotalError::AlreadyExistsError => "The resource already exists.",
            VirusTotalError::FailedDependencyError => "The request depended on another request and that request failed.",
            VirusTotalError::QuotaExceededError => "You have exceeded one of your quotas (minute, daily or monthly). Daily quotas are reset every day at 00:00 UTC. You may have run out of disk space and/or number of files on your VirusTotal Monitor account",
            VirusTotalError::TooManyRequestsError => "Too many requests.",
            VirusTotalError::TransientError => "Transient server error. Retry might work.",
            VirusTotalError::DeadlineExceededError => "The operation took too long to complete.",
            VirusTotalError::NoURLReturned => "If the custom upload endpoint URL request fails",
            VirusTotalError::JsonError(_) => "Json decoding error",
            VirusTotalError::UTF8Error(_) => "String UTF-8 decoding error",
            VirusTotalError::NetworkError(_) => "Network error",
            VirusTotalError::IOError(_) => "Error opening a file for submitting to VirusTotal",
            VirusTotalError::NonPaginatedResults => "A search query didn't have an offset",
            VirusTotalError::UnknownError => "Some other unknown or unforeseen error occurred",
        }
    }
}

impl std::fmt::Display for VirusTotalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message())
    }
}

impl From<reqwest::Error> for VirusTotalError {
    fn from(err: reqwest::Error) -> Self {
        let url = if let Some(url) = err.url() {
            format!(" loading {url}")
        } else {
            String::new()
        };
        VirusTotalError::NetworkError(format!("Http error{url}: {err}"))
    }
}

impl From<reqwest::StatusCode> for VirusTotalError {
    fn from(status: reqwest::StatusCode) -> Self {
        match status {
            reqwest::StatusCode::BAD_REQUEST => VirusTotalError::BadRequestError,
            reqwest::StatusCode::UNAUTHORIZED => VirusTotalError::AuthenticationRequiredError,
            reqwest::StatusCode::FORBIDDEN => VirusTotalError::ForbiddenError,
            reqwest::StatusCode::NOT_FOUND => VirusTotalError::NotFoundError,
            reqwest::StatusCode::CONFLICT => VirusTotalError::AlreadyExistsError,
            reqwest::StatusCode::TOO_MANY_REQUESTS => VirusTotalError::TooManyRequestsError,
            reqwest::StatusCode::INTERNAL_SERVER_ERROR => VirusTotalError::TransientError,
            _ => VirusTotalError::UnknownError,
        }
    }
}

impl std::error::Error for VirusTotalError {}
