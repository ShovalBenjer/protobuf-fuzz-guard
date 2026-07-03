//! `protofuzz`: scan `.proto` files for CVE/DoS patterns and generate
//! cross-language fuzz harnesses.
//!
//! Output convention (research §2): data / JSON goes to **stdout**; progress and
//! diagnostics go to **stderr**. Exit codes: `0` clean, `1` critical findings,
//! `2` usage error (emitted by clap).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use pfg_core::{generate_all, get_patterns, has_critical, parse_proto, scan, FindingReport};

#[derive(Parser)]
#[command(
    name = "protofuzz",
    about = "Cross-language protobuf fuzz harness generator with CVE-pattern detection",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan .proto files for known CVE patterns and structural risks.
    Scan {
        /// .proto files to scan.
        #[arg(required = true)]
        files: Vec<PathBuf>,
        /// Emit findings as JSON on stdout.
        #[arg(long)]
        json: bool,
    },
    /// Generate fuzz harnesses for the messages in .proto files.
    Generate {
        /// .proto files.
        #[arg(required = true)]
        files: Vec<PathBuf>,
        /// Target language(s); repeatable. Default: all.
        #[arg(long, short, value_parser = ["python", "cpp", "go", "rust"])]
        lang: Vec<String>,
        /// Output directory.
        #[arg(long, short, default_value = "fuzz_harnesses")]
        output: PathBuf,
    },
    /// List known CVE / RUSTSEC patterns.
    Patterns,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan { files, json } => cmd_scan(&files, json),
        Command::Generate {
            files,
            lang,
            output,
        } => cmd_generate(&files, &lang, &output),
        Command::Patterns => cmd_patterns(),
    }
}

fn cmd_scan(files: &[PathBuf], json: bool) -> ExitCode {
    #[derive(serde::Serialize)]
    struct JsonFinding {
        severity: &'static str,
        pattern_id: Option<&'static str>,
        message: String,
        file: String,
    }

    let mut json_out = Vec::new();
    let mut any_critical = false;
    let mut any_finding = false;

    for path in files {
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("error: cannot read {}: {e}", path.display());
                return ExitCode::from(2);
            }
        };
        let proto = parse_proto(&content, &path.to_string_lossy());
        let findings = scan(&proto);
        any_critical |= has_critical(&findings);
        any_finding |= !findings.is_empty();

        if json {
            for f in &findings {
                json_out.push(JsonFinding {
                    severity: f.severity.as_str(),
                    pattern_id: f.pattern_id,
                    message: f.message.clone(),
                    file: f.file_path.clone(),
                });
            }
        } else {
            for f in &findings {
                // Rich, span-highlighted diagnostic to stderr.
                let report = miette::Report::new(FindingReport::from_finding(f, &proto));
                eprintln!("{report:?}");
            }
        }
    }

    if json {
        match serde_json::to_string_pretty(&json_out) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("error: serializing JSON: {e}");
                return ExitCode::from(2);
            }
        }
    } else if !any_finding {
        println!("No findings. Clean.");
    }

    if any_critical {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn cmd_generate(files: &[PathBuf], lang: &[String], output: &Path) -> ExitCode {
    let langs: Option<Vec<&str>> = if lang.is_empty() {
        None
    } else {
        Some(lang.iter().map(String::as_str).collect())
    };

    for path in files {
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("error: cannot read {}: {e}", path.display());
                return ExitCode::from(2);
            }
        };
        let proto = parse_proto(&content, &path.to_string_lossy());
        let harnesses = match generate_all(&proto, langs.as_deref()) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::from(2);
            }
        };

        for (lang, items) in harnesses {
            let lang_dir = output.join(lang);
            if let Err(e) = fs::create_dir_all(&lang_dir) {
                eprintln!("error: creating {}: {e}", lang_dir.display());
                return ExitCode::from(2);
            }
            let ext = pfg_core::harness::file_extension(lang).unwrap_or("");
            for (msg_name, code) in items {
                let fname = format!("fuzz_{}{ext}", msg_name.to_lowercase());
                let dest = lang_dir.join(&fname);
                if let Err(e) = fs::write(&dest, code) {
                    eprintln!("error: writing {}: {e}", dest.display());
                    return ExitCode::from(2);
                }
                println!("  Generated: {}", dest.display());
            }
        }
    }

    println!("\nHarnesses written to {}/", output.display());
    ExitCode::SUCCESS
}

fn cmd_patterns() -> ExitCode {
    for p in get_patterns(None) {
        let langs = p.affected_languages.join(", ");
        println!("  {}", p.id);
        println!("    Title: {}", p.title);
        println!("    Languages: {langs}");
        if let Some(fix) = p.fixed_in {
            println!("    Fixed in: {fix}");
        }
        println!("    {}", p.description);
        println!();
    }
    ExitCode::SUCCESS
}
