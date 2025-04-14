//! security-badger Create badges based on audit reports
//!
//! TODO Long Description
//!
//! # Examples
//!
//! TODO Example
use std::fs::File;
use std::io::Read;
use std::io::Write;

use badge_maker::BadgeBuilder;
use security_badger::trivy::VulnerabilitySummary;
use security_badger::Badge;
use security_badger::Summarize;
use security_badger::Severity;
use simple_logger::SimpleLogger;

use clap::Parser;
use security_badger::trivy::{
    Report, VulnQuery, VulnerabilityStatus, VulnerabilitySummaryBuilder,
};
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

    /// Path to the audit report as JSON
    audit_json: Option<String>,
}

impl Args {
    fn audit_reader(&self) -> Result<Box<dyn Read>, Error> {
        if let Some(audit_json) = self.audit_json.as_ref() {
            let f = File::open(audit_json).map_err(Error::Read)?;
            Ok(Box::new(f))
        } else {
            Ok(Box::new(std::io::stdin()))
        }
    }
}

fn handle_trivy(args: &Args, report: Report) -> Result<VulnerabilitySummary, Error> {
    let mut builder = VulnerabilitySummaryBuilder::new();
    for filter_status in args.trivy_filter.iter() {
        builder = builder.with_filter_on_status(filter_status);
    }
    let summary = builder.build(&report);
    summary.summarize();
    if let Some(report_sev) = &args.report_severity {
        summary.report_details(&report_sev);
    }
    Ok(summary)
}

/// Main entry point
fn main() -> Result<(), Error> {
    SimpleLogger::new()
        .init()
        .expect("Failed to initialize logging.");
    // Parse arguments
    let args = Args::parse();
    let report: Report = {
        let f = File::open(&args.audit_json).map_err(Error::Read)?;
        serde_json::from_reader(f).map_err(Error::Json)?
    };
    let summary = handle_trivy(&args, report)?;
    if let Some(pth) = &args.svg {
        let svg = BadgeBuilder::new()
            .label("vulns")
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
