use std::fmt::{Debug, Display, Formatter};
use std::ops::{Add, BitOr, Shl, Shr};

use chrono::{DateTime, Days, Utc};

// See https://docs.virustotal.com/docs/file-search-modifiers for the complete list of flags.

/// File types to search for
#[derive(Copy, Clone, Debug, Hash)]
pub enum FileType {
    /// Non-Linux Unix file, Common Object File Format
    Coff,

    /// MS-DOS command file
    Com,

    /// Microsoft Word document, any format
    Word,

    /// Microsoft Word, older DOCFILE format
    Doc,

    /// Microsoft Word, newer Zip & XML-based format
    Docx,

    /// MS-DOS
    Dos,

    /// ELFs (Executable and Linkable File), used on Unix or Unix-like operating systems
    Elf,

    /// Microsoft Excel spreadsheet, any format
    Excel,

    /// Microsoft Excel, older DOCFILE format
    Xls,

    /// Microsoft Excel, newer Zip & XML-based format
    Xlsx,

    /// ELFs, but for Linux
    Linux,

    /// New Executable `https://en.wikipedia.org/wiki/New_Executable`
    /// This is an old format for Windows 1.0 - Windows 95/98, OS/2
    Ne,

    /// New Executable `https://en.wikipedia.org/wiki/New_Executable`, applications only
    /// This is an old format for Windows 1.0 - Windows 95/98, OS/2
    NeExe,

    /// New Executable `https://en.wikipedia.org/wiki/New_Executable`, shared library only
    /// This is an old format for Windows 1.0 - Windows 95/98, OS/2
    NeDll,

    /// Mach-O, for macOS, iOS, etc
    MachO,

    /// Mac DMG disk image
    MacDmg,

    /// Microsoft Office
    MsOffice,

    /// Adobe PDF (Portable Document Format)
    Pdf,

    /// Rich Text Format (RTF) documents
    Rtf,

    /// PE32 (Portable Executable) files, .exe and .dll
    PE32,

    /// PE32 files, just .dll
    PeDll,

    /// PE32 files, just .exe
    PeExe,

    /// Any PE32 file which could run on Windows
    Windows,

    /// Windows installer file
    WindowsMSI,
}

impl Display for FileType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            FileType::Coff => write!(f, "type:coff"),
            FileType::Com => write!(f, "type:com"),
            FileType::Word => write!(f, "type:word"),
            FileType::Doc => write!(f, "type:doc"),
            FileType::Docx => write!(f, "type:docx"),
            FileType::Dos => write!(f, "type:dos"),
            FileType::Elf => write!(f, "type:elf"),
            FileType::Excel => write!(f, "type:excel"),
            FileType::Xls => write!(f, "type:xls"),
            FileType::Xlsx => write!(f, "type:xlsx"),
            FileType::Linux => write!(f, "type:linux"),
            FileType::Ne => write!(f, "type:ne"),
            FileType::NeExe => write!(f, "type:neexe"),
            FileType::NeDll => write!(f, "type:nedll"),
            FileType::MachO => write!(f, "type:macho"),
            FileType::MacDmg => write!(f, "type:dmg"),
            FileType::MsOffice => write!(f, "type:msoffice"),
            FileType::Pdf => write!(f, "type:pdf"),
            FileType::Rtf => write!(f, "type:rtf"),
            FileType::PE32 => write!(f, "type:peexe OR type:pedll"),
            FileType::PeDll => write!(f, "type:pedll"),
            FileType::PeExe => write!(f, "type:peexe"),
            FileType::Windows => write!(f, "type:windows"),
            FileType::WindowsMSI => write!(f, "type:msi"),
        }
    }
}

impl BitOr for FileType {
    type Output = String;

    fn bitor(self, rhs: Self) -> Self::Output {
        format!("{self} OR {rhs}")
    }
}

/// [Vec<FileType>] with [Display] already implemented.
#[derive(Clone, Debug, Hash)]
pub struct FileTypes(pub Vec<FileType>);

impl Display for FileTypes {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let combined = self
            .0
            .iter()
            .map(|ft| ft.to_string())
            .collect::<Vec<String>>()
            .join(" OR ");
        write!(f, "{combined}")
    }
}

/// File attributes, many are file-type specific. Be sure to not use a [Tag] which is not
/// appropriate for the [FileType] being sought.
#[derive(Copy, Clone, Debug, Hash)]
pub enum Tag {
    /// PE32 file which uses the .Net Framework (CLR)
    DotNetAssembly,

    /// If the executable is 64-bit
    Executable64bit,

    /// PE32 file runs in the EFI environment
    ExecutableEFI,

    /// If the PE32 or Mach-O file has an embedded signature
    ExecutableSigned,

    /// If the sample makes use of a known exploit
    Exploit,

    /// Sample was caught in the wild with a honeypot system
    Honeypot,

    /// Microsoft Office file with macro(s)
    MSOfficeMacro,

    /// PDF document which does something when viewed
    PdfAutoAction,

    /// PDF document with some other file(s) embedded
    PdfEmbeddedFile,

    /// PDF document with a fillable form
    PdfForm,

    /// PDF document with embedded Javascript
    PdfJs,

    /// PDF document which executes Javascript when opened
    PdfLaunchAction,
}

impl Display for Tag {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Tag::DotNetAssembly => write!(f, "tag:assembly"),
            Tag::Executable64bit => write!(f, "tag:64bits"),
            Tag::ExecutableEFI => write!(f, "tag:efi"),
            Tag::ExecutableSigned => write!(f, "tag:signed"),
            Tag::Exploit => write!(f, "tag:exploit"),
            Tag::Honeypot => write!(f, "tag:honeypot"),
            Tag::MSOfficeMacro => write!(f, "tag:macros"),
            Tag::PdfAutoAction => write!(f, "tag:autoaction"),
            Tag::PdfEmbeddedFile => write!(f, "tag:file-embedded"),
            Tag::PdfForm => write!(f, "tag:acroform"),
            Tag::PdfJs => write!(f, "tag:js-embedded"),
            Tag::PdfLaunchAction => write!(f, "tag:launch-action"),
        }
    }
}

impl BitOr for Tag {
    type Output = String;

    fn bitor(self, rhs: Self) -> Self::Output {
        format!("{self} {rhs}")
    }
}

/// [Vec<Tag>] with [Display] already implemented.
#[derive(Clone, Debug, Hash)]
pub struct Tags(pub Vec<Tag>);

impl Display for Tags {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let combined = self
            .0
            .iter()
            .map(|t| t.to_string())
            .collect::<Vec<String>>()
            .join(" ");
        write!(f, "{combined}")
    }
}

/// Antivirus hit results, with optional upper bound.
#[derive(Copy, Clone, Debug, Hash)]
pub struct Positives {
    /// Minimum number of hits
    pub min: u32,

    /// Optional upper bound of amount of antivirus hits
    pub max: Option<u32>,

    /// Exact, [Positives::min] won't have `+`
    pub exact: bool,
}

impl Positives {
    pub const fn min(min: u32) -> Self {
        Positives {
            min,
            max: None,
            exact: false,
        }
    }

    pub const fn min_max(min: u32, max: u32) -> Self {
        Positives {
            min,
            max: Some(max),
            exact: false,
        }
    }
}

/// No VirusTotal hits, but benign today doesn't mean benign tomorrow.
pub const BENIGN: Positives = Positives {
    min: 0,
    max: Some(0),
    exact: true,
};

impl Default for Positives {
    fn default() -> Self {
        // This is definitely arbitrary, but 5 or more hits probably is something not wanted
        // on a computer system
        Positives {
            min: 5,
            max: None,
            exact: false,
        }
    }
}

impl Display for Positives {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.exact {
            return write!(f, "positives:{}", self.min);
        }

        write!(f, "positives:{}+", self.min)?;

        if let Some(max) = self.max {
            write!(f, " positives:{max}-")
        } else {
            write!(f, "")
        }
    }
}

/// Find files submitted on or after a specific date, or within a date range
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct FirstSubmission {
    /// First seen date & time
    pub first: DateTime<Utc>,

    /// Second date & time for a range
    pub second: Option<DateTime<Utc>>,

    /// If true, then only find files submitted at the first date
    pub exact: bool,

    /// For date vs datetime. Use only the specified formats [FirstSubmission::FORMAT_DATE] or
    /// [FirstSubmission::FORMATE_DATE_TIME], otherwise there will likely be errors or empty results
    pub format: &'static str,
}

impl FirstSubmission {
    pub const FORMAT_DATE: &'static str = "%Y-%m-%d";
    pub const FORMAT_DATETIME: &'static str = "%Y-%m-%dT%H:%M:%S";

    /// Only submitted at a specific date
    pub fn at_date(start: DateTime<Utc>) -> Self {
        Self {
            first: start,
            second: None,
            exact: true,
            format: Self::FORMAT_DATE,
        }
    }

    /// Only submitted at a specific date and time
    pub fn at_datetime(start: DateTime<Utc>) -> Self {
        Self {
            first: start,
            second: None,
            exact: true,
            format: Self::FORMAT_DATETIME,
        }
    }

    /// First submitted on or after a specific date
    pub fn from_date(start: DateTime<Utc>) -> Self {
        Self {
            first: start,
            second: None,
            exact: false,
            format: Self::FORMAT_DATE,
        }
    }

    /// First submitted on or after a specific date and time
    pub fn from_datetime(start: DateTime<Utc>) -> Self {
        Self {
            first: start,
            second: None,
            exact: false,
            format: Self::FORMAT_DATETIME,
        }
    }

    /// Builder: Set the end date
    pub fn until_date(self, end: DateTime<Utc>) -> Self {
        Self {
            first: self.first,
            second: Some(end),
            exact: false,
            format: self.format,
        }
    }

    /// Submitted on or after some [Days] ago
    pub fn days(days: u32) -> Self {
        let start = Utc::now() - Days::new(days as u64);
        Self {
            first: start,
            second: None,
            exact: false,
            format: Self::FORMAT_DATE,
        }
    }
}

impl Display for FirstSubmission {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.exact {
            return write!(f, "fs:{}", self.first.format(self.format));
        }

        write!(f, "fs:{}+", self.first.format(self.format))?;

        if let Some(second) = self.second {
            write!(f, " fs:{}-", second.format(self.format))
        } else {
            write!(f, "")
        }
    }
}

impl Add<Days> for FirstSubmission {
    type Output = FirstSubmission;

    /// Add [Days] to the end date, creating relative to start if not present
    fn add(self, rhs: Days) -> Self::Output {
        let end = if let Some(end) = self.second {
            end + rhs
        } else {
            self.first + rhs
        };

        Self {
            first: self.first,
            second: Some(end),
            exact: self.exact,
            format: self.format,
        }
    }
}

impl Shl<Days> for FirstSubmission {
    type Output = Self;

    /// Shift both the start and end dates forward by some amount of [Days]. Does not create
    /// and end date if it doesn't exist.
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn shl(self, rhs: Days) -> Self::Output {
        let start = self.first + rhs;
        let end = self.second.map(|second| second + rhs);

        Self {
            first: start,
            second: end,
            exact: self.exact,
            format: self.format,
        }
    }
}

impl Shr<Days> for FirstSubmission {
    type Output = Self;

    /// Shift both the start and dates backward by some amount of [Days]. Does not create
    /// and end date if it doesn't exist.
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn shr(self, rhs: Days) -> Self::Output {
        let start = self.first - rhs;
        let end = self.second.map(|second| second - rhs);

        Self {
            first: start,
            second: end,
            exact: self.exact,
            format: self.format,
        }
    }
}

impl Add<FileType> for Positives {
    type Output = String;
    fn add(self, rhs: FileType) -> Self::Output {
        format!("{rhs} {self}")
    }
}

impl Add<Positives> for FileType {
    type Output = String;
    fn add(self, rhs: Positives) -> Self::Output {
        format!("{self} {rhs}")
    }
}

impl Add<Tag> for FileType {
    type Output = String;
    fn add(self, rhs: Tag) -> Self::Output {
        format!("{self} {rhs}")
    }
}

impl Add<Tags> for FileType {
    type Output = String;
    fn add(self, rhs: Tags) -> Self::Output {
        format!("{self} {rhs}")
    }
}

impl Add<FirstSubmission> for FileType {
    type Output = String;
    fn add(self, rhs: FirstSubmission) -> Self::Output {
        format!("{self} {rhs}")
    }
}

impl Add<Positives> for Tag {
    type Output = String;
    fn add(self, rhs: Positives) -> Self::Output {
        format!("{self} {rhs}")
    }
}

impl Add<Positives> for Tags {
    type Output = String;
    fn add(self, rhs: Positives) -> Self::Output {
        format!("{self} {rhs}")
    }
}

impl Add<FirstSubmission> for Tag {
    type Output = String;
    fn add(self, rhs: FirstSubmission) -> Self::Output {
        format!("{self} {rhs}")
    }
}

impl Add<FileTypes> for Positives {
    type Output = String;
    fn add(self, rhs: FileTypes) -> Self::Output {
        format!("{rhs} {self}")
    }
}

impl Add<Positives> for FileTypes {
    type Output = String;
    fn add(self, rhs: Positives) -> Self::Output {
        format!("{self} {rhs}")
    }
}

impl Add<String> for FileTypes {
    type Output = String;
    fn add(self, rhs: String) -> Self::Output {
        format!("{self} {rhs}")
    }
}
impl Add<FirstSubmission> for FileTypes {
    type Output = String;
    fn add(self, rhs: FirstSubmission) -> Self::Output {
        format!("{self} {rhs}")
    }
}

impl Add<String> for Tags {
    type Output = String;

    fn add(self, rhs: String) -> Self::Output {
        format!("{rhs} {self}")
    }
}

impl Add<String> for Tag {
    type Output = String;

    fn add(self, rhs: String) -> Self::Output {
        format!("{rhs} {self}")
    }
}

impl Add<FirstSubmission> for Tags {
    type Output = String;

    fn add(self, rhs: FirstSubmission) -> Self::Output {
        format!("{rhs} {self}")
    }
}

impl Add<Tag> for String {
    type Output = String;

    fn add(self, rhs: Tag) -> Self::Output {
        format!("{self} {rhs}")
    }
}

impl Add<Tags> for String {
    type Output = String;

    fn add(self, rhs: Tags) -> Self::Output {
        format!("{self} {rhs}")
    }
}

impl Add<FileType> for String {
    type Output = String;

    fn add(self, rhs: FileType) -> Self::Output {
        format!("{self} {rhs}")
    }
}

impl Add<FirstSubmission> for String {
    type Output = String;

    fn add(self, rhs: FirstSubmission) -> Self::Output {
        format!("{self} {rhs}")
    }
}

impl Add<FileType> for FirstSubmission {
    type Output = String;

    fn add(self, rhs: FileType) -> Self::Output {
        format!("{self} {rhs}")
    }
}

impl Add<Positives> for FirstSubmission {
    type Output = String;

    fn add(self, rhs: Positives) -> Self::Output {
        format!("{self} {rhs}")
    }
}

impl Add<String> for FirstSubmission {
    type Output = String;

    fn add(self, rhs: String) -> Self::Output {
        format!("{self} {rhs}")
    }
}

impl Add<Tag> for FirstSubmission {
    type Output = String;

    fn add(self, rhs: Tag) -> Self::Output {
        format!("{self} {rhs}")
    }
}

impl Add<Tags> for FirstSubmission {
    type Output = String;

    fn add(self, rhs: Tags) -> Self::Output {
        format!("{self} {rhs}")
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    #[test]
    fn benign() {
        assert_eq!(BENIGN.to_string(), "positives:0");
    }

    #[test]
    fn types_positives() {
        let types: String = FileTypes(vec![FileType::MachO, FileType::Dos, FileType::WindowsMSI])
            + Positives::default()
            + Tag::ExecutableSigned;
        assert_eq!(
            types,
            "type:macho OR type:dos OR type:msi positives:5+ tag:signed"
        );
    }

    #[test]
    fn first_submission() {
        let first =
            FirstSubmission::at_datetime(Utc.with_ymd_and_hms(2015, 5, 15, 10, 20, 30).unwrap());
        assert_eq!(first.to_string(), "fs:2015-05-15T10:20:30");

        let first =
            FirstSubmission::at_datetime(Utc.with_ymd_and_hms(2015, 5, 15, 10, 20, 30).unwrap());
        let first = first.until_date(Utc.with_ymd_and_hms(2015, 12, 30, 23, 59, 59).unwrap());
        assert_eq!(
            first.to_string(),
            "fs:2015-05-15T10:20:30+ fs:2015-12-30T23:59:59-"
        );

        let shifted_forward = first.clone() << Days::new(1);
        assert_eq!(
            shifted_forward.to_string(),
            "fs:2015-05-16T10:20:30+ fs:2015-12-31T23:59:59-"
        );

        let shifted_back = shifted_forward >> Days::new(1);
        assert_eq!(shifted_back, first);
    }
}
