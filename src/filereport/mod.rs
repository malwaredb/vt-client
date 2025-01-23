/// Report details for a Linux/Unix/BSD file
pub mod elf;

/// Report details for a Mach-O file
pub mod macho;

/// Report details for a PE32 file
pub mod pe;

use crate::VirusTotalError;

use chrono::serde::{ts_seconds, ts_seconds_option};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// File report response, which could return data (success confirmation) or an error message
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FileReportRequestResponse {
    /// Information about the report request
    #[serde(rename = "data")]
    Data(FileReportData),

    /// Error message, file report request not successful
    #[serde(rename = "error")]
    Error(VirusTotalError),
}

/// Successful file report request response contents
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileReportData {
    /// The file report details, the interesting part
    pub attributes: ScanResultAttributes,

    /// Report type, probably "file"
    #[serde(rename = "type")]
    pub record_type: String,

    /// Report ID, also the file's SHA-256 hash
    pub id: String,

    /// Link to the file report
    pub links: HashMap<String, String>,
}

/// All scan results
/// [https://virustotal.readme.io/reference/files]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanResultAttributes {
    /// When the file was created, often spoofed by malware
    #[serde(default, with = "ts_seconds_option")]
    pub creation_date: Option<DateTime<Utc>>,

    /// List of tags related to the file's capabilities
    /// Requires VirusTotal Premium
    pub capabilities_tags: Option<Vec<String>>,

    /// Extracted malware configuration
    /// Requires VirusTotal Premium
    pub malware_config: Option<HashMap<String, String>>,

    /// A description of the file type
    pub type_description: String,

    /// Exiftool results, requires VirusTotal Premium
    pub exiftool: Option<ExifTool>,

    /// Trend Micro's Locality Sensitive Hash: [https://tlsh.org/]
    pub tlsh: Option<String>,

    /// VirusTotal's custom algorithm for clustering similar files
    pub vhash: Option<String>,

    /// Trend Micro's ELF hash
    pub telfhash: Option<String>,

    /// Tags which may show further details of the file type
    pub type_tags: Vec<String>,

    /// Additional attribute tags
    #[serde(default)]
    pub tags: Vec<String>,

    /// File names this sample has had when submitted to VirusTotal
    pub names: Vec<String>,

    /// When the file was last modified
    #[serde(with = "ts_seconds")]
    pub last_modification_date: DateTime<Utc>,

    /// Another first seen field
    #[serde(default, with = "ts_seconds_option")]
    pub first_seen_itw_date: Option<DateTime<Utc>>,

    /// Type tags which can be used with VirusTotal Intelligence
    pub type_tag: String,

    /// The number of times the file has been submitted to VirusTotal
    pub times_submitted: u32,

    /// Votes from the VirusTotal user community whether the file is dangerous
    pub total_votes: Votes,

    /// Size of the file, in bytes
    pub size: u64,

    /// Community votes as to the nature of the thread of this file
    pub popular_threat_classification: Option<PopularThreatClassification>,

    /// When the file was last submitted to VirusTotal
    #[serde(with = "ts_seconds")]
    pub last_submission_date: DateTime<Utc>,

    /// Antivirus results, where the key is the name of the antivirus software product
    /// More info: https://docs.virustotal.com/reference/analyses-object
    pub last_analysis_results: HashMap<String, AnalysisResult>,

    /// Results from TrID, an attempt to identify the file type
    /// See https://mark0.net/soft-trid-e.html
    pub trid: Option<Vec<TrID>>,

    /// Another file type detection program
    pub detectiteasy: Option<DetectItEasy>,

    /// SHA-256 hash of the file
    pub sha256: String,

    /// File extension for this file type
    pub type_extension: Option<String>,

    /// When the file was last analyzed by VirusTotal
    #[serde(with = "ts_seconds")]
    pub last_analysis_date: DateTime<Utc>,

    /// The number of unique sources which have submitted this file
    pub unique_sources: u32,

    /// When the file was first submitted to VirusTotal
    #[serde(with = "ts_seconds")]
    pub first_submission_date: DateTime<Utc>,

    /// MD-5 hash of the file
    pub md5: String,

    /// SSDeep fuzzy hash of the file
    /// See [https://ssdeep-project.github.io/ssdeep/index.html]
    pub ssdeep: String,

    /// SHA-1 of the file
    pub sha1: String,

    /// The output from libmagic, the `file` command for this file
    pub magic: String,

    /// Antivirus results summary
    pub last_analysis_stats: LastAnalysisStats,

    /// Dictionary containing the number of matched Sigma rules group by its severity
    /// [https://blog.virustotal.com/2021/05/context-is-king-part-i-crowdsourced.html]
    /// [https://virustotal.readme.io/docs/crowdsourced-sigma-rules]
    #[serde(default)]
    pub sigma_analysis_summary: HashMap<String, serde_json::Value>,

    /// Sigma results, if available
    /// [https://blog.virustotal.com/2021/05/context-is-king-part-i-crowdsourced.html]
    /// [https://virustotal.readme.io/docs/crowdsourced-sigma-rules]
    #[serde(default)]
    pub sigma_analysis_stats: Option<SigmaAnalysisStats>,

    /// Results from VT's Sigma rules
    /// See [https://github.com/SigmaHQ/sigma/wiki/Rule-Creation-Guide]
    #[serde(default)]
    pub sigma_analysis_results: Vec<SigmaAnalysisResults>,

    /// Executables: Information on packers, if available
    #[serde(default)]
    pub packers: HashMap<String, String>,

    /// The most interesting name of all the file names used with this file
    pub meaningful_name: String,

    /// The file's reputation from all votes,
    /// see [https://support.virustotal.com/hc/en-us/articles/115002146769-Vote-comment]
    pub reputation: u32,

    /// Mach-O details, if a Mach-O file (macOS, iOS, etc)
    /// This is a vector since there is a separate [macho::MachInfo] struct per
    /// each architecture if this is a Fat Mach-O file.
    pub macho_info: Option<Vec<macho::MachoInfo>>,

    /// Portable Executable (PE) details, if a PE32 file (Windows, OS2)
    pub pe_info: Option<pe::PEInfo>,

    /// PE32: DotNet Assembly Information
    #[serde(default)]
    pub dot_net_assembly: Option<pe::dotnet::DotNetAssembly>,

    /// PE32: SHA-256 hash used my Microsoft's AppLocker to ensure the binary is unmodified
    #[serde(default)]
    pub authentihash: Option<String>,

    /// Executable and Linkable Format (ELF) details, if an ELF (Linux, *BSD, Haiku, Solaris, etc)
    #[serde(default)]
    pub elf_info: Option<elf::ElfInfo>,

    /// Executables: Signature information, varies by executable file type
    #[serde(default)]
    pub signature_info: HashMap<String, serde_json::Value>,

    /// Results from opening the file in various sandbox environments
    #[serde(default)]
    pub sandbox_verdicts: HashMap<String, SandboxVerdict>,

    /// Anything else not capture by this struct
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Community votes whether a file is benign or malicious
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Votes {
    /// Votes that the file is harmless
    pub harmless: u32,

    /// Votes that the file is malicious
    pub malicious: u32,
}

/// Popular threat classification contains threat information pulled from antivirus results
/// [https://virustotal.readme.io/reference/popular_threat_classification]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PopularThreatClassification {
    /// Popular threat category and name
    pub suggested_threat_label: String,

    /// Threat categories or types, if available; examples might be "ransomware" or "trojan"
    #[serde(default)]
    pub popular_threat_category: Vec<PopularThreatClassificationInner>,

    /// Threat name(s) from antivirus results, if available
    #[serde(default)]
    pub popular_threat_name: Vec<PopularThreatClassificationInner>,
}

/// Popular thread classification details
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PopularThreatClassificationInner {
    /// Votes for this threat type
    pub count: u32,

    /// Type of threat
    pub value: String,
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

/// ExifTool metadata, requires VirusTotal Premium. See [https://docs.virustotal.com/reference/exiftool]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ExifTool {
    /// Windows PE: Application character set
    pub character_set: Option<String>,

    /// Windows PE: code side
    pub code_size: Option<String>,

    /// Windows PE: Company name
    pub company_name: Option<String>,

    /// PDF: Creation date
    pub create_date: Option<String>,

    /// PDF: Creator application
    pub creator: Option<String>,

    /// PDF: Creator tool
    pub creator_tool: Option<String>,

    /// PDF: Document ID
    #[serde(rename = "DocumentID")]
    pub document_id: Option<String>,

    /// Windows PE: entry point address
    pub entry_point: Option<String>,

    /// Windows PE: description about the file
    pub file_description: Option<String>,

    /// Windows PE: File flags mask
    pub file_flags_mask: Option<String>,

    /// Windows PE: expected operating system
    #[serde(rename = "FileOS")]
    pub file_os: Option<String>,

    /// Windows PE: size of the file
    pub file_size: Option<String>,

    /// Windows PE: File subtype
    pub file_subtype: Option<String>,

    /// PDF & Windows PE: File type
    pub file_type: Option<String>,

    /// PDF & Windows PE: file extension for the file type
    pub file_type_extension: Option<String>,

    /// Windows PE: file version
    pub file_version: Option<String>,

    /// Windows PE: file version number
    pub file_version_number: Option<String>,

    /// PDF (others?): File format
    pub format: Option<String>,

    /// PDF: Has forms (XML Forms Architecture)
    #[serde(rename = "HasXFA")]
    pub hasxfa: Option<String>,

    /// Windows PE: image file characteristics
    pub image_file_characteristics: Option<String>,

    /// Windows PE: image version
    pub image_version: Option<String>,

    /// Windows PE: initialized data size
    pub initialized_data_size: Option<String>,

    /// PDF: Instance ID
    #[serde(rename = "InstanceID")]
    pub instance_id: Option<String>,

    /// Windows PE: internal name
    pub internal_name: Option<String>,

    /// Windows PE: language code
    pub language_code: Option<String>,

    /// Windows PE: copyright information
    pub legal_copyright: Option<String>,

    /// PDF: If linearized
    pub linearized: Option<String>,

    /// Windows PE: linker version
    pub linker_version: Option<String>,

    /// PDF & Windows PE: MIME type
    #[serde(rename = "MIMEType")]
    pub mimetype: Option<String>,

    /// Windows PE: Machine type
    pub machine_type: Option<String>,

    /// PDF: Metadata date
    pub metadata_date: Option<String>,

    /// PDF: Modification date
    pub modify_date: Option<String>,

    /// Windows PE: operating system version
    #[serde(rename = "OSVersion")]
    pub os_version: Option<String>,

    /// Windows PE: Object file type
    pub object_file_type: Option<String>,

    /// Windows PE: original file name
    pub original_file_name: Option<String>,

    /// PDF: Page count
    pub page_count: Option<String>,

    /// PDF: PDF version
    #[serde(rename = "PDFVersion")]
    pub pdf_version: Option<String>,

    /// Windows PE: PE type
    #[serde(rename = "PEType")]
    pub petype: Option<String>,

    /// PDF: Producer
    pub producer: Option<String>,

    /// Windows PE: Product name
    pub product_name: Option<String>,

    /// Windows PE: product version
    pub product_version: Option<String>,

    /// Windows PE: product version number
    pub product_version_number: Option<String>,

    /// Windows PE: Windows subsystem type
    pub subsystem: Option<String>,

    /// Windows PE: Windows subsystem version
    pub subsystem_version: Option<String>,

    /// Windows PE: creation timestamp
    pub time_stamp: Option<String>,

    /// Windows PE: Uninitialized data size
    pub uninitialized_data_size: Option<String>,

    /// PDF: XMP (extensible metadata platform) toolkit
    #[serde(rename = "XMPToolkit")]
    pub xmp_toolkit: Option<String>,

    /// Anything else not capture by this struct
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// File type based on TrID
/// [https://virustotal.readme.io/reference/files-object-trid]
/// [https://mark0.net/soft-trid-e.html]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrID {
    /// Detected file type
    pub file_type: String,

    /// Probability the file is of this type
    pub probability: f32,
}

/// Output from Detect It Easy [https://github.com/horsicq/Detect-It-Easy]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DetectItEasy {
    /// File type
    pub filetype: String,

    /// Details
    #[serde(default)]
    pub values: Vec<DetectItEasyValues>,
}

/// File type from Detect It Easy
/// [https://virustotal.readme.io/reference/detectiteasy]
/// [https://github.com/horsicq/Detect-It-Easy]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DetectItEasyValues {
    /// Artifacts detected in the file
    pub info: Option<String>,

    /// File type
    #[serde(rename = "type")]
    pub detection_type: String,

    /// Name of the file
    pub name: String,

    /// Version
    pub version: Option<String>,
}

/// Last Analysis Stats
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LastAnalysisStats {
    /// Antivirus products which indicate this file is harmless
    pub harmless: u32,

    /// Antivirus products which don't support this file type
    #[serde(rename = "type-unsupported")]
    pub type_unsupported: u32,

    /// Antivirus products which indicate the file is suspicious
    pub suspicious: u32,

    /// Antivirus products which timed out trying to evaluate the file
    #[serde(rename = "confirmed-timeout")]
    pub confirmed_timeout: u32,

    /// Antivirus products which timed out trying to evaluate the file
    pub timeout: u32,

    /// Antivirus products which failed to analyze the file
    pub failure: u32,

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
        self.type_unsupported + self.confirmed_timeout + self.timeout + self.failure
    }

    /// In an effort to error on the side of caution, call a file benign is no antivirus products
    /// call it malicious or suspicious
    pub fn is_benign(&self) -> bool {
        self.malicious == 0 && self.suspicious == 0
    }
}

/// Sandbox verdicts, see [https://virustotal.readme.io/reference/sandbox_verdicts]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SandboxVerdict {
    /// Sandbox verdict
    pub category: SandboxVerdictCategory,

    /// Verdict confidence from 0 to 100.
    pub confidence: u8,

    /// Name of the sandbox environment
    pub sandbox_name: String,

    /// Raw sandbox verdicts
    #[serde(default)]
    pub malware_classification: Vec<String>,
}

/// Sandbox verdicts, see [https://virustotal.readme.io/reference/sandbox_verdicts]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SandboxVerdictCategory {
    /// Sample was suspicious
    #[serde(alias = "suspicious", alias = "Suspicious")]
    Suspicious,

    /// Sample was malicious
    #[serde(alias = "malicious", alias = "Malicious")]
    Malicious,

    /// Sample was harmless
    #[serde(alias = "harmless", alias = "Harmless")]
    Harmless,

    /// Threat not detected
    #[serde(alias = "undetected", alias = "Undetected")]
    Undetected,
}

/// Sigma analysis stats
/// [https://virustotal.readme.io/reference/sigma_analysis_stats]
/// [https://virustotal.readme.io/docs/crowdsourced-sigma-rules]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigmaAnalysisStats {
    /// Number of matched low severity rules.
    pub low: u64,

    /// Number of matched medium severity rules.
    pub medium: u64,

    /// Number of matched high severity rules
    pub high: u64,

    /// Number of matched critical severity rules.
    pub critical: u64,
}

/// Sigma analysis results
/// [https://virustotal.readme.io/reference/sigma_analysis_results]
/// [https://virustotal.readme.io/docs/crowdsourced-sigma-rules]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigmaAnalysisResults {
    /// Sigma rule title
    pub rule_title: String,

    /// Sigma rule source description
    pub rule_source: String,

    /// The `HashMap` likely has one field: "values" which is another map of event data
    pub match_context: Vec<HashMap<String, serde_json::Value>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::rtf(include_str!("../../testdata/fff40032c3dc062147c530e3a0a5c7e6acda4d1f1369fbc994cddd3c19a2de88.json"), "Rich Text Format")]
    #[case::com(include_str!("../../testdata/0001a1252300b4732e4a010a5dd13a291dcb8b0ebee6febedb5152dfb0bcd488.json"), "DOS COM")]
    #[case::word(include_str!("../../testdata/001015aafcae8a6942366cbb0e7d39c0738752a7800c41ea1c655d47b0a4d04c.json"), "MS Word Document")]
    #[case::exedotnet(include_str!("../../testdata/417c06700c3e899f0554654102fa064385bf1d3ecec32471ac488096d81bf38c.json"), "Win32 EXE")] // .Net
    #[case::macho(include_str!("../../testdata/b8e7a581d85807ea6659ea2f681bd16d5baa7017ff144aa3030aefba9cbcdfd3.json"), "Mach-O")]
    #[case::exe(include_str!("../../testdata/ddecc35aa198f401948c73a0d53fd93c4ecb770198ad7db308de026745c56b71.json"), "Win32 EXE")]
    #[case::elf(include_str!("../../testdata/de10ba5e5402b46ea975b5cb8a45eb7df9e81dc81012fd4efd145ed2dce3a740.json"), "ELF")]
    fn deserialize_valid_report(#[case] report: &str, #[case] file_type: &str) {
        let report: FileReportRequestResponse =
            serde_json::from_str(report).expect("failed to deserialize VT report");

        if let FileReportRequestResponse::Data(data) = report {
            if file_type == "Mach-O" {
                assert!(data.attributes.macho_info.is_some());
            } else if file_type == "Win32 EXE" {
                assert!(data.attributes.pe_info.is_some());
            } else if file_type == "ELF" {
                assert!(data.attributes.elf_info.is_some());
            }
            println!("{data:?}");
            assert_eq!(data.attributes.type_description, file_type);
            assert_eq!(data.record_type, "file");
            for (key, value) in &data.attributes.extra {
                println!("KEY: {key}");
                println!("VALUE: {value}\n\n");
            }
            assert!(data.attributes.extra.is_empty());
        } else {
            panic!("File wasn't a report!");
        }
    }

    #[rstest]
    #[case(include_str!("../../testdata/not_found.json"))]
    #[case(include_str!("../../testdata/wrong_key.json"))]
    fn deserialize_errors(#[case] contents: &str) {
        let report: FileReportRequestResponse =
            serde_json::from_str(contents).expect("failed to deserialize VT error response");

        match report {
            FileReportRequestResponse::Data(_) => panic!("Should have been an error type!"),
            FileReportRequestResponse::Error(_) => {}
        }
    }

    #[test]
    fn pe_exif() {
        // Data comes from VirusTotal documentation
        const PE_JSON: &str = r#"{
            "CodeSize": "86528",
            "EntryPoint": "0x5d45",
            "FileFlagsMask": "0x003f",
            "FileOS": "Windows NT 32-bit",
            "FileSubtype": "0",
            "FileType": "Win32 EXE",
            "FileTypeExtension": "exe",
            "FileVersionNumber": "1.0.0.1",
            "ImageFileCharacteristics": "Executable, 32-bit",
            "ImageVersion": "0.0",
            "InitializedDataSize": "15447552",
            "LinkerVersion": "10.0",
            "MIMEType": "application/octet-stream",
            "MachineType": "Intel 386 or later, and compatibles",
            "OSVersion": "5.1",
            "ObjectFileType": "Executable application",
            "PEType": "PE32",
            "ProductVersionNumber": "1.0.0.1",
            "Subsystem": "Windows GUI",
            "SubsystemVersion": "5.1",
            "TimeStamp": "2018:06:10 05:04:21+02:00",
            "UninitializedDataSize": "0"
            }"#;

        let exiftool: ExifTool = serde_json::from_str(PE_JSON).unwrap();
        assert_eq!(exiftool.file_type.unwrap(), "Win32 EXE");
        assert_eq!(exiftool.mimetype.unwrap(), "application/octet-stream");
        assert_eq!(exiftool.os_version.unwrap(), "5.1");
        assert!(exiftool.extra.is_empty());
    }

    #[test]
    fn pdf_exif() {
        // Data comes from VirusTotal documentation
        const PDF_JSON: &str = r#"{
            "CreateDate": "2020:02:27 18:03:45+03:00",
            "DocumentID": "uuid:5ac8d66b-6716-466c-b665-965766c06571",
            "FileType": "PDF",
            "FileTypeExtension": "pdf",
            "Format": "application/pdf",
            "HasXFA": "No",
            "InstanceID": "uuid:696b3606-6627-606f-b636-769b656676f0",
            "Linearized": "No",
            "MIMEType": "application/pdf",
            "MetadataDate": "2020:02:27 18:03:45+03:00",
            "ModifyDate": "2020:02:27 18:03:45+03:00",
            "PDFVersion": "1.6",
            "PageCount": "2",
            "XMPToolkit": "Adobe XMP Core 5.4-c005 78.147326, 2012/08/23-13:03:03"
            }"#;

        let exiftool: ExifTool = serde_json::from_str(PDF_JSON).unwrap();
        assert_eq!(exiftool.pdf_version.unwrap(), "1.6");
        assert_eq!(
            exiftool.xmp_toolkit.unwrap(),
            "Adobe XMP Core 5.4-c005 78.147326, 2012/08/23-13:03:03"
        );
        assert!(exiftool.extra.is_empty());
    }
}
