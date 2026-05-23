//! Build automation tasks for the OpenFang workspace.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "xtask", about = "OpenFang workspace automation")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate openapi.json from openfang-api utoipa annotations.
    Openapi {
        /// Output path for the spec (default: openapi.json at repo root).
        #[arg(short, long, default_value = "openapi.json")]
        out: PathBuf,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().cmd {
        Cmd::Openapi { out } => {
            use utoipa::OpenApi;
            let spec = openfang_api::openapi::ApiDoc::openapi().to_pretty_json()?;
            std::fs::write(&out, spec)?;
            println!("wrote {}", out.display());
            Ok(())
        }
    }
}
