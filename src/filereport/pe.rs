// SPDX-License-Identifier: Apache-2.0

use chrono::serde::ts_seconds_option;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Fields and information unique to PE32 files
/// [https://virustotal.readme.io/reference/pe_info]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PEInfo {
    /// Rich Header, which may reveal compiler information
    #[serde(default)]
    pub rich_pe_header_hash: Option<String>,

    /// When the program was compiled, can be spoofed
    #[serde(default, with = "ts_seconds_option")]
    pub timestamp: Option<DateTime<Utc>>,

    /// Compiler information, if available
    #[serde(default)]
    pub compiler_product_versions: Vec<String>,

    /// Starting point for execution
    pub entry_point: u64,

    /// CPU target for this program
    pub machine_type: u32,

    /// Import hash
    /// [https://www.mandiant.com/resources/blog/tracking-malware-import-hashing]
    pub imphash: String,

    /// Section information
    #[serde(default)]
    pub sections: Vec<PESection>,

    /// Imports by .dll
    #[serde(default)]
    pub import_list: Vec<PEImports>,

    /// Anything else not capture by this struct
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// PE section information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PESection {
    /// Section name
    pub name: String,

    /// Chi-Square metric
    pub chi2: f32,

    /// Address when loaded
    pub virtual_address: u64,

    /// Entropy
    pub entropy: f32,

    /// Size on disk
    pub raw_size: u64,

    /// Flags: executable, readable, writable
    pub flags: String,

    /// Size in memory
    pub virtual_size: u64,

    /// MD5 hash of the section
    pub md5: String,
}

/// Functions imported from a given .dll
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PEImports {
    /// .dll name
    pub library_name: String,

    /// Function names
    #[serde(default)]
    pub imported_functions: Vec<String>,
}

/// PE data related for .Net (CLR) binaries
/// [https://virustotal.readme.io/reference/dot_net_assembly]
pub mod dotnet {
    use super::*;

    /// .Net specific information for a PE32 file
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct DotNetAssembly {
        /// Entry point relative virtual address
        pub entry_point_rva: u64,

        /// Metadata header relative virtual address
        pub metadata_header_rva: u64,

        /// Assembly name
        pub assembly_name: String,

        /// Assembly flags
        pub assembly_flags: u32,

        /// Relative Virtual Address of the strong name signature hash
        pub strongname_va: u32,

        /// Simplified representation of tables_rows_map
        pub tables_rows_map_log: String,

        /// Other assemblies used by this sample
        pub external_assemblies: HashMap<String, ExternalAssembly>,

        /// Type definition list
        #[serde(default)]
        pub type_definition_list: Vec<TypeDefinition>,

        /// Entry point of the program
        pub entry_point_token: u64,

        /// Hex presentation of the tables_rows_map
        pub tables_rows_map: String,

        /// Human-readable version of assembly flags
        pub assembly_flags_txt: String,

        /// Information about assembly streams
        pub streams: HashMap<String, Stream>,

        /// Number of tables present
        pub tables_present: u32,

        /// Hex value of present tables bitmap
        pub tables_present_map: String,

        /// Version of the Common Language Runtime
        pub clr_version: String,

        /// Version of the Common Language Runtime metadata
        pub clr_meta_version: String,

        /// basic data about the assembly manifest
        pub assembly_data: AssemblyData,

        /// Resources Virtual Address
        pub resources_va: u64,
    }

    /// Assembly version
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct ExternalAssembly {
        /// Assembly version
        pub version: String,
    }

    /// Type definition and namespace
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct TypeDefinition {
        /// type definitions
        #[serde(default)]
        pub type_definitions: Vec<String>,

        /// Type namespace
        pub namespace: String,
    }

    /// Stats about the stream
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Stream {
        /// Stream chi2
        pub chi2: f32,

        /// Stream size
        pub size: u64,

        /// Stream entropy
        pub entropy: f32,

        /// MD-5 hash of the stream
        pub md5: String,
    }

    /// Assembly information
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct AssemblyData {
        /// Assembly major version
        pub majorversion: u64,

        /// Assembly minor version
        pub minorversion: u64,

        /// Id of hash used when signed
        pub hashalgid: u64,

        /// Specific characteristics of the assembly, such as x86, AMD64; human-readable
        #[serde(default)]
        pub flags_text: Option<String>,

        /// Build number
        pub buildnumber: u64,

        /// Specific characteristics of the assembly, such as x86, AMD64
        pub flags: u64,

        /// Revision number
        pub revisionnumber: u64,

        /// Assembly name
        pub name: String,
    }
}
