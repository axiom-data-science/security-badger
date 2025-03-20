use std::fmt::Display;

use convert_case::{Case, Casing};
use strum_macros::{VariantNames, AsRefStr};
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};


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

#[derive(Serialize, Deserialize, VariantNames, AsRefStr, clap::ValueEnum, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VulnerabilityStatus {
    Unknown,
    NotAffected,
    Affected,
    Fixed,
    UnderInvestigation,
    WillNotFix,
    FixDeferred,
    EndOfLife,
}

impl Display for VulnerabilityStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_case(Case::Snake))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PackageIdentifier {
    #[serde(rename = "PURL")]
    purl: Option<String>,
    #[serde(rename = "UID")]
    uid: Option<String>,
}

/// DetectedVulnerability struct mapped from trivy
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct DetectedVulnerability {
    #[serde(rename = "VulnerabilityID")]
    pub vulnerability_id: String,
    #[serde(rename = "PkgID")]
    pub pkg_id: String,
    pub title: String,
    pub description: Option<String>,
    pub severity: Option<Severity>,
    pub installed_version: Option<String>,
    pub pkg_name: Option<String>,
    pub pkg_identifier: Option<PackageIdentifier>,
    #[serde(default)]
    pub references: Vec<String>,

    #[serde(rename = "CweIDs", default)]
    pub cwe_ids: Vec<String>,

    pub status: Option<VulnerabilityStatus>,
    pub published_date: Option<DateTime<Utc>>,
    pub last_modified_date: Option<DateTime<Utc>>,
}

/// Result struct mapped from trivy
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct AuditResult {
    pub target: String,
    pub class: String,
    #[serde(rename = "Type")]
    pub result_type: String,

    #[serde(default)]
    pub vulnerabilities: Vec<DetectedVulnerability>,
}

/// Report struct mapped from trivy/pkg/types/report.go
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Report {
    pub artifact_name: String,
    pub schema_version: i32,
    pub artifact_type: String,

    pub results: Vec<AuditResult>,
}

#[derive(Default)]
pub struct VulnerabilitySummaryBuilder {
    status_filters: Vec<VulnerabilityStatus>,
}

impl VulnerabilitySummaryBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_filter_on_status(mut self, status: &VulnerabilityStatus) -> Self{
        self.status_filters.push(status.clone());
        self
    }

    pub fn build(self, report: &Report) -> VulnerabilitySummary {
        report.results
            .iter()
            .flat_map(|res| {
                res.vulnerabilities.iter()
            })
            .filter(|vuln| {
                if let Some(status) = &vuln.status {
                    !self.status_filters.contains(status)
                } else {
                    false
                }
            })
            .into()
    }
}


/// A summary of the vulnerability counts in the report
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VulnerabilitySummary {
    pub low_severity: u64,
    pub medium_severity: u64,
    pub high_severity: u64,
    pub critical_severity: u64,

    pub vulnerabilities: Vec<DetectedVulnerability>,
}

impl From<&Report> for VulnerabilitySummary {
    fn from(value: &Report) -> Self {

        value.results.iter().flat_map(|res| {
            res.vulnerabilities.iter()
        }).into()
    }
}

impl From<Report> for VulnerabilitySummary {
    fn from(value: Report) -> Self {
        Self::from(&value)
    }
}

impl<'a, T: IntoIterator<Item = &'a DetectedVulnerability>> From<T> for VulnerabilitySummary {
    fn from(iter: T) -> Self {
        let mut lows: u64 = 0;
        let mut meds: u64 = 0;
        let mut highs: u64 = 0;
        let mut crits: u64 = 0;
        let mut vulnerabilities: Vec<DetectedVulnerability> = vec![];
        iter.into_iter().for_each(|vuln| {
            vulnerabilities.push(vuln.clone());

            if let Some(sev) = &vuln.severity {
                match sev {
                    Severity::Low => { lows += 1; },
                    Severity::Medium => { meds += 1; },
                    Severity::High => { highs += 1; },
                    Severity::Critical => { crits += 1; },
                    _ => {},
                }
            }
        });
        Self {
            low_severity: lows,
            medium_severity: meds,
            high_severity: highs,
            critical_severity: crits,
            vulnerabilities,
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::fs::File;
    #[test]
    fn test_deserialize() -> Result<(), Box<dyn std::error::Error>>{
        let mut f = File::open("tests/data/sample-audit.json")?;
        let report: Report = serde_json::from_reader(&mut f)?;
        assert_eq!(report.artifact_name, "spectacles:latest");

        let debian_findings = &report.results[0];
        assert_eq!(debian_findings.target, "spectacles:latest (debian 11.11)");

        let first_vuln = &debian_findings.vulnerabilities[0];
        assert_eq!(first_vuln.vulnerability_id, "CVE-2011-3374");

        let finding_with_status = debian_findings.vulnerabilities
            .iter()
            .filter(|v| v.vulnerability_id == "CVE-2016-2781")
            .next()
            .expect("This vulnerability should be found.");

        assert!(matches!(finding_with_status.status.as_ref().unwrap(), VulnerabilityStatus::WillNotFix));
        Ok(())
    }

    #[test]
    fn test_summary() -> Result<(), Box<dyn std::error::Error>> {
        let mut f = File::open("tests/data/sample-audit.json")?;
        let report: Report = serde_json::from_reader(&mut f)?;

        let summary = VulnerabilitySummary::from(&report);
        assert_eq!(summary.low_severity, 76);
        assert_eq!(summary.medium_severity, 27);
        assert_eq!(summary.high_severity, 3);
        assert_eq!(summary.critical_severity, 2);

        Ok(())
    }
    #[test]
    fn test_summary_builder() -> Result<(), Box<dyn std::error::Error>> {
        let mut f = File::open("tests/data/sample-audit.json")?;
        let report: Report = serde_json::from_reader(&mut f)?;

        let summary = VulnerabilitySummaryBuilder::new()
            .with_filter_on_status(&VulnerabilityStatus::WillNotFix)
            .with_filter_on_status(&VulnerabilityStatus::NotAffected)
            .with_filter_on_status(&VulnerabilityStatus::Fixed)
            .build(&report);
        assert_eq!(summary.low_severity, 75);
        assert_eq!(summary.medium_severity, 19);
        assert_eq!(summary.high_severity, 3);
        assert_eq!(summary.critical_severity, 0);

        Ok(())
    }
}
