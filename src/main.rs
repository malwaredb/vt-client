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
    #[arg(long, env = "VT_API_KEY")]
    pub key: String,

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
    /// The file to be used with VirusTotal
    pub file: PathBuf,

    /// Output for the report
    pub output: Option<PathBuf>,
}

#[derive(Parser, Clone)]
struct HashArg {
    /// Download a file based on a hash (MD5, SHA-1, or SHA-256)
    pub hash: String,
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

    /// Get a report for a file, doesn't send the file to VirusTotal
    GetReport(FileReportArg),

    /// Request re-analysis of a file based on a hash (MD5, SHA-1, or SHA-256)
    Rescan(HashArg),

    /// Download a file based on a hash (MD5, SHA-1, or SHA-256)
    Download(HashArg),
}

impl Action {
    async fn execute(&self, client: &VirusTotalClient) -> Result<()> {
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
                let contents = std::fs::read(&arg.file)?;
                let mut sha256 = Sha256::new();
                sha256.update(contents);
                let sha256 = sha256.finalize();
                let sha256 = hex::encode(sha256);
                let response = client.get_report(&sha256).await?;
                if let Some(report_dest) = &arg.output {
                    let report = serde_json::to_string(&response)?;
                    std::fs::write(report_dest, report)?;
                }
                println!(
                    "AVs with detection: {} of {}",
                    response.attributes.last_analysis_stats.malicious,
                    response.attributes.last_analysis_stats.av_count()
                );
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
        }

        Ok(())
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<ExitCode> {
    let args = Args::parse();
    let client: VirusTotalClient = args.key.into();
    args.action.execute(&client).await?;

    Ok(ExitCode::SUCCESS)
}
