use malwaredb_virustotal::VirusTotalClient;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
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

#[derive(Subcommand, Clone)]
enum Action {
    /// Submit a file to VirusTotal
    Submit(SubmitFileArg),

    /// Get a report for a file, doesn't send the file to VirusTotal
    GetReport(FileReportArg),
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
