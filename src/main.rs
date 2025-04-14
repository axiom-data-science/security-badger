//! security-badger Create badges based on audit reports
//!
//! TODO Long Description
//!
//! # Examples
//!
//! TODO Example
use std::fs::File;
use std::io::{Read, Write, Stdin};

use badge_maker::BadgeBuilder;
use security_badger::cargo_audit;
use security_badger::trivy::VulnerabilitySummary;
use security_badger::Badge;
use security_badger::Severity;
use security_badger::Summarize;
use simple_logger::SimpleLogger;

use clap::Parser;
use security_badger::trivy::{Report, VulnerabilityStatus, VulnerabilitySummaryBuilder};
use security_badger::Error;

/// Program Arguments
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Increase verbosity
    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    /// Ignore vulnerabilities reported by trivy with this status
    #[arg(long)]
    trivy_filter: Vec<VulnerabilityStatus>,

    /// Log vulnerabilities with at least this severity
    #[arg(long)]
    report_severity: Option<Severity>,

    /// Output an SVG Badge
    #[arg(long)]
    svg: Option<String>,

    /// SVG Badge Label to use, Defaults to "vulns"
    #[arg(short, long, default_value = "vulns")]
    label: String,

    /// Path to the audit report as JSON
    audit_json: Option<String>,
}

enum AuditReader {
    File(File),
    Stdin(Stdin),
}

impl Read for AuditReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::File(file) => file.read(buf),
            Self::Stdin(stdin) => stdin.read(buf),
        }
    }
}

impl Args {
    fn audit_reader(&self) -> Result<AuditReader, Error> {
        if let Some(input) = self.audit_json.as_ref() {
            Ok(AuditReader::File(File::open(input).map_err(Error::Read)?))
        } else {
            Ok(AuditReader::Stdin(std::io::stdin()))
        }
    }
}

pub enum Reporting {
    Trivy(VulnerabilitySummary),
    CargoAudit,
}

fn handle_trivy(args: &Args) -> Result<Box<dyn Badge>, Error> {
    let report: Report = {
        let rdr = args.audit_reader()?;
        serde_json::from_reader(rdr).map_err(Error::Json)?
    };
    let mut builder = VulnerabilitySummaryBuilder::new();
    for filter_status in args.trivy_filter.iter() {
        builder = builder.with_filter_on_status(filter_status);
    }
    let summary = builder.build(&report);
    summary.summarize();
    if let Some(report_sev) = &args.report_severity {
        summary.report_details(report_sev);
    }
    Ok(Box::new(summary))
}

fn handle_cargo_audit(args: &Args) -> Result<Box<dyn Badge>, Error> {
    let report: cargo_audit::Report = {
        let rdr = args.audit_reader()?;
        serde_json::from_reader(rdr).map_err(Error::Json)?
    };
    let summary = cargo_audit::VulnerabilitySummary::from(report);
    summary.summarize();
    if let Some(report_sev) = &args.report_severity {
        summary.report_details(report_sev);
    }

    Ok(Box::new(summary))
}

/// Main entry point
fn main() -> Result<(), Error> {
    SimpleLogger::new()
        .init()
        .expect("Failed to initialize logging.");
    // Parse arguments
    let args = Args::parse();
    let summary = match handle_trivy(&args) {
        Err(Error::Json(_)) => handle_cargo_audit(&args),
        Err(e) => Err(e),
        Ok(v) => Ok(v),
    }?;
    if let Some(pth) = &args.svg {
        let svg = BadgeBuilder::new()
            .label(&args.label)
            .message(&summary.badge_message())
            .color(summary.color())
            .build()
            .map_err(Error::Svg)?
            .svg();
        let mut f = File::create(pth).map_err(Error::Write)?;
        f.write_all(svg.as_bytes()).map_err(Error::Write)?;
    }

    Ok(())
}
