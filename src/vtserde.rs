// SPDX-License-Identifier: Apache-2.0

use crate::VirusTotalClient;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct VirusTotalSerde {
    #[serde(alias = "vt_api_key")]
    key: String,
}

impl From<VirusTotalClient> for VirusTotalSerde {
    #[cfg(not(feature = "unsafe-serialization"))]
    fn from(_client: VirusTotalClient) -> Self {
        Self {
            key: "your-api-key-here".to_string(),
        }
    }
    #[cfg(feature = "unsafe-serialization")]
    fn from(client: VirusTotalClient) -> Self {
        Self {
            key: client.key.clone(),
        }
    }
}

impl From<VirusTotalSerde> for VirusTotalClient {
    fn from(client: VirusTotalSerde) -> Self {
        VirusTotalClient::new(client.key.clone()).expect("Failed to load VirusTotalClient")
    }
}
