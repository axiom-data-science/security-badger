//! security-badger Create badges based on audit reports
//!
//! TODO Long Description
//!
//! # Examples
//!
//! TODO Example
use std::fs::File;
use std::io::Write;

use badge_maker::color::Color;
use simple_logger::SimpleLogger;
use badge_maker::BadgeBuilder;
use badge_maker::color::NamedColor;

use clap::Parser;
use security_badger::trivy::{Report, VulnerabilityStatus, VulnerabilitySummaryBuilder, Severity};
use security_badger::Error;



/// Program Arguments
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Increase verbosity
    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    /// Ignore vulnerabilities with this status
    #[arg(long)]
    filter: Vec<VulnerabilityStatus>,

    /// Log vulnerabilities with at least this severity
    #[arg(long)]
    report_severity: Option<Severity>,

    /// Output an SVG Badge
    #[arg(long)]
    svg: Option<String>,

    /// Path to the audit report as JSON
    audit_json: String,
}


/// Main entry point
fn main() -> Result<(), Error> {
    SimpleLogger::new()
        .init()
        .expect("Failed to initialize logging.");
    // Parse arguments
    let args = Args::parse();
    let report: Report = {
        let f = File::open(args.audit_json).map_err(Error::Read)?;
        serde_json::from_reader(f).map_err(Error::Json)?
    };
    let mut builder = VulnerabilitySummaryBuilder::new();
    for filter_status in args.filter.iter() {
        builder = builder.with_filter_on_status(filter_status);
    }
    let summary = builder.build(&report);
    log::info!("Low Severity Vulnerabilities = {}", summary.low_severity);
    log::info!("Medium Severity Vulnerabilities = {}", summary.medium_severity);
    log::info!("High Severity Vulnerabilities = {}", summary.high_severity);
    log::info!("Critical Severity Vulnerabilities = {}", summary.critical_severity);
    if let Some(report_sev) = &args.report_severity {
        summary.vulnerabilities
            .iter()
            .filter(|v| {
                if let Some(sev) = &v.severity {
                    return sev.to_int() >= report_sev.to_int()
                }
                false
            })
            .for_each(|v| {
                log::info!("{} {}", v.vulnerability_id, v.title);
            });
    }

    if let Some(pth) = &args.svg {
        let message = format!("{} / {} / {} / {}", summary.critical_severity, summary.high_severity, summary.medium_severity, summary.low_severity);
        let color = if summary.critical_severity > 0 {
            Color::Named(NamedColor::Red)
        } else if summary.medium_severity > 0 {
            Color::Named(NamedColor::Orange)
        } else {
            Color::Named(NamedColor::Green)
        };
        let svg = BadgeBuilder::new()
            .label("vulns")
            .message(&message)
            .color(color)
            .build()
            .map_err(Error::Svg)?
            .svg();
        let mut f = File::create(pth).map_err(Error::Write)?;
        f.write_all(svg.as_bytes()).map_err(Error::Write)?;
    }

    Ok(())
}
