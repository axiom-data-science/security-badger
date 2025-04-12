use badge_maker::color::Color;
use serde::{Deserialize, Serialize};
use thiserror::Error as ThisError;
pub mod cargo_audit;
pub mod trivy;

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("Read: failed to open the file for reading: {0}")]
    Read(std::io::Error),

    #[error("Json: Failed to parse the file as valid JSON: {0}")]
    Json(serde_json::Error),

    #[error("NotAStatus: The value is not a valid VulnerabilityStatus")]
    NotAStatus,

    #[error("Svg: Failed to produce an SVG Badge: {0}")]
    Svg(badge_maker::error::Error),

    #[error("Write: failed to open a file for writing: {0}")]
    Write(std::io::Error),
}

pub trait Badge {
    fn badge_message(&self) -> String;

    fn color(&self) -> Color;
}

pub trait Summarize {
    /// Log a brief summary of the vulnerabiltiies identified in the report.
    fn summarize(&self);

    fn report_details(&self, report_sev: &Severity);
}

#[derive(Serialize, Deserialize, clap::ValueEnum, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn to_int(&self) -> u32 {
        match self {
            Severity::Unknown => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }

    pub fn short(&self) -> &str {
        match self {
            Severity::Unknown => "U",
            Severity::Low => "L",
            Severity::Medium => "M",
            Severity::High => "H",
            Severity::Critical => "C!",
        }
    }
}
