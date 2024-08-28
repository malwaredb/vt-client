use malwaredb_virustotal::VirusTotalClient;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};

#[derive(Parser)]
#[command(author, about, version)]
struct Args {
    /// API key for VirusTotal
    pub client: VirusTotalClient,

    /// Action to be performed with VirusTotal
    #[clap(subcommand)]
    pub action: Action,
}

#[derive(Parser, Clone)]
struct SubmitFileArg {
    /// The file to be used with VirusTotal
    pub file: PathBuf,
}

#[derive(Parser, Clone)]
struct FileReportArg {
    /// Fetch a VT report based on a file on disk
    #[arg(short, long)]
    pub file: Option<PathBuf>,

    /// Fetch a file report based on a hash (MD5, SHA-1, or SHA-256)
    #[arg(long)]
    pub hash: Option<String>,

    /// Output for the report, or display a summary only if no output was specified
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

#[derive(Parser, Clone)]
struct HashArg {
    /// Download a file based on a hash (MD5, SHA-1, or SHA-256)
    pub hash: String,
}

#[derive(Parser, Clone)]
struct StringArg {
    /// Search for files matching some criteria, returns hashes. Requires VT Premium!
    pub search: String,
}

impl HashArg {
    pub fn valid(&self) -> bool {
        self.hash.len() == 32 || self.hash.len() == 40 || self.hash.len() == 64
    }
}

#[derive(Subcommand, Clone)]
enum Action {
    /// Submit a file to VirusTotal
    Submit(SubmitFileArg),

    /// Get a report for a file, doesn't send the file to VirusTotal. Specify either a hash or a file
    /// path, which will send that file's SHA-256 hash. Specify both without an output file, and
    /// summary information for both files will be displayed.
    GetReport(FileReportArg),

    /// Request re-analysis of a file based on a hash (MD5, SHA-1, or SHA-256)
    Rescan(HashArg),

    /// Download a file based on a hash (MD5, SHA-1, or SHA-256). Requires VT Premium!
    Download(HashArg),

    /// Search for files matching some criteria, returns hashes. Requires VT Premium!
    Search(StringArg),
}

impl Action {
    async fn execute(&self, client: VirusTotalClient) -> Result<()> {
        match self {
            Action::Submit(arg) => {
                let contents = std::fs::read(&arg.file)?;
                let response = client
                    .submit(
                        contents,
                        arg.file
                            .file_name()
                            .map(|s| s.to_str().unwrap().to_string()),
                    )
                    .await?;
                println!("Submitted, request id {}", response.id);
            }
            Action::GetReport(arg) => {
                if arg.file.is_none() && arg.hash.is_none() {
                    bail!("Nothing to do, neither file path nor hash were specified.");
                }
                if let Some(report_dest) = &arg.output {
                    if let Some(input_file) = &arg.file {
                        let contents = std::fs::read(input_file)?;
                        let mut sha256 = Sha256::new();
                        sha256.update(contents);
                        let sha256 = sha256.finalize();
                        let sha256 = hex::encode(sha256);
                        let response = client.get_report(&sha256).await?;
                        let report = serde_json::to_string(&response)?;
                        std::fs::write(report_dest, report)?;
                        println!(
                            "AVs with detection: {} of {} for {input_file:?}",
                            response.attributes.last_analysis_stats.malicious,
                            response.attributes.last_analysis_stats.av_count()
                        );
                    } else if let Some(input_hash) = &arg.hash {
                        let response = client.get_report(input_hash).await?;
                        let report = serde_json::to_string(&response)?;
                        std::fs::write(report_dest, report)?;
                        println!(
                            "AVs with detection: {} of {} for {input_hash}",
                            response.attributes.last_analysis_stats.malicious,
                            response.attributes.last_analysis_stats.av_count()
                        );
                    }
                } else {
                    if let Some(input_file) = &arg.file {
                        let contents = std::fs::read(input_file)?;
                        let mut sha256 = Sha256::new();
                        sha256.update(contents);
                        let sha256 = sha256.finalize();
                        let sha256 = hex::encode(sha256);
                        let response = client.get_report(&sha256).await?;
                        println!(
                            "AVs with detection: {} of {} for {input_file:?}",
                            response.attributes.last_analysis_stats.malicious,
                            response.attributes.last_analysis_stats.av_count()
                        );
                    }

                    if let Some(input_hash) = &arg.hash {
                        let response = client.get_report(input_hash).await?;
                        println!(
                            "AVs with detection: {} of {} for {input_hash}",
                            response.attributes.last_analysis_stats.malicious,
                            response.attributes.last_analysis_stats.av_count()
                        );
                    }
                }
            }
            Action::Rescan(arg) => {
                if !arg.valid() {
                    bail!("Hash {} isn't an MD5, SHA-1, or SHA-256 hash.", arg.hash);
                }
                let response = client.request_rescan(&arg.hash).await?;
                println!("Rescan for {} requested: {}", arg.hash, response.id);
            }
            Action::Download(arg) => {
                if !arg.valid() {
                    bail!("Hash {} isn't an MD5, SHA-1, or SHA-256 hash.", arg.hash);
                }
                let response = client.download(&arg.hash).await?;
                std::fs::write(&arg.hash, response)?;
            }
            Action::Search(arg) => {
                let response = client.search(&arg.search).await?;
                if response.hashes.is_empty() {
                    println!("Nothing found.");
                } else {
                    for hash in response.hashes {
                        println!("{hash}");
                    }
                }
            }
        }

        Ok(())
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<ExitCode> {
    let args = Args::parse();
    args.action.execute(args.client).await?;

    Ok(ExitCode::SUCCESS)
}
