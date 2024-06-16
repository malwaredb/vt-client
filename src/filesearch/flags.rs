use std::fmt::{Display, Formatter};
use std::ops::{Add, BitOr};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benign() {
        assert_eq!(BENIGN.to_string(), "positives:0");
    }

    #[test]
    fn types_positives() {
        let types: String = FileTypes(vec![FileType::MachO, FileType::Dos, FileType::WindowsMSI])
            + Positives::default();
        assert_eq!(types, "type:macho OR type:dos OR type:msi positives:5+");
    }
}
