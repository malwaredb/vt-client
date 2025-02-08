// SPDX-License-Identifier: Apache-2.0

use super::VirusTotalError;

use std::sync::LazyLock;

// See: https://virustotal.readme.io/reference/errors

/// The API request is invalid or malformed.
pub static BAD_REQUEST_ERROR: LazyLock<VirusTotalError> = LazyLock::new(|| {
    VirusTotalError {
    code: "BadRequestError".into(),
    message: "The API request is invalid or malformed. The message usually provides details about why the request is not valid.".into(),
}
});

/// Some of the provided arguments are incorrect.
pub static INVALID_ARGUMENT_ERROR: LazyLock<VirusTotalError> = LazyLock::new(|| VirusTotalError {
    code: "InvalidArgumentError".into(),
    message: "Some of the provided arguments are incorrect.".into(),
});

/// The resource is not available yet, but will become available later.
pub static NOT_AVAILABLE_YET: LazyLock<VirusTotalError> = LazyLock::new(|| VirusTotalError {
    code: "NotAvailableYet".into(),
    message: "The resource is not available yet, but will become available later.".into(),
});

/// Content search query is not selective enough.
pub static UNSELECTOVE_CONTENT_QUERY_ERROR: LazyLock<VirusTotalError> =
    LazyLock::new(|| VirusTotalError {
        code: "UnselectiveContentQueryError".into(),
        message: "Content search query is not selective enough.".into(),
    });

/// Unsupported content search query.
pub static UNSUPPORTED_CONTENT_QUERY_ERROR: LazyLock<VirusTotalError> =
    LazyLock::new(|| VirusTotalError {
        code: "UnsupportedContentQueryError".into(),
        message: "Unsupported content search query.".into(),
    });

/// The operation requires an authenticated user. Verify that you have provided your API key.
pub static AUTHENTICATION_REQUIRED_ERROR: LazyLock<VirusTotalError> = LazyLock::new(|| {
    VirusTotalError {
        code: "AuthenticationRequiredError".into(),
        message: "The operation requires an authenticated user. Verify that you have provided your API key.".into(),
    }
});

/// The user account is not active. Make sure you properly activated your account by following the link sent to your email.
pub static USER_NOT_ACTIVE_ERROR: LazyLock<VirusTotalError> = LazyLock::new(|| {
    VirusTotalError {
code: "UserNotActiveError".into(),
message: "The user account is not active. Make sure you properly activated your account by following the link sent to your email.".into(),
}
});

/// The provided API key is incorrect.
pub static WRONG_CREDENTIALS_ERROR: LazyLock<VirusTotalError> = LazyLock::new(|| VirusTotalError {
    code: "WrongCredentialsError".into(),
    message: "The provided API key is incorrect.".into(),
});

/// You are not allowed to perform the requested operation.
pub static FORBIDDEN_ERROR: LazyLock<VirusTotalError> = LazyLock::new(|| VirusTotalError {
    code: "ForbiddenError".into(),
    message: "You are not allowed to perform the requested operation.".into(),
});

/// The requested resource was not found.
pub static NOT_FOUND_ERROR: LazyLock<VirusTotalError> = LazyLock::new(|| VirusTotalError {
    code: "NotFoundError".into(),
    message: "The requested resource was not found.".into(),
});

/// The resource already exists.
pub static ALREADY_EXISTS_ERROR: LazyLock<VirusTotalError> = LazyLock::new(|| VirusTotalError {
    code: "AlreadyExistsError".into(),
    message: "The resource already exists.".into(),
});

/// The request depended on another request and that request failed.
pub static FAILED_DEPENDENCY_ERROR: LazyLock<VirusTotalError> = LazyLock::new(|| VirusTotalError {
    code: "FailedDependencyError".into(),
    message: "The request depended on another request and that request failed.".into(),
});

/// You have exceeded one of your quotas (minute, daily or monthly).
pub static QUOTA_EXCEEDED_ERROR: LazyLock<VirusTotalError> = LazyLock::new(|| {
    VirusTotalError {
code: "QuotaExceededError".into(),
message: "You have exceeded one of your quotas (minute, daily or monthly). Daily quotas are reset every day at 00:00 UTC.
You may have run out of disk space and/or number of files on your VirusTotal Monitor account.".into(),
}
});

/// Too many requests.
pub static TOO_MANY_REQUESTS_ERROR: LazyLock<VirusTotalError> = LazyLock::new(|| VirusTotalError {
    code: "TooManyRequestsError".into(),
    message: "Too many requests.".into(),
});

/// Transient server error. Retry might work.
pub static TRANSIENT_ERROR: LazyLock<VirusTotalError> = LazyLock::new(|| VirusTotalError {
    code: "TransientError".into(),
    message: "Transient server error. Retry might work.".into(),
});

/// The operation took too long to complete.
pub static DEADLINE_EXCEEDED_ERROR: LazyLock<VirusTotalError> = LazyLock::new(|| VirusTotalError {
    code: "DeadlineExceededError".into(),
    message: "The operation took too long to complete.".into(),
});
