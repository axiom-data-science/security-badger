use std::fmt::Display;

use badge_maker::color::{Color, NamedColor};
use chrono::{DateTime, Utc};
use convert_case::{Case, Casing};
use enum_dispatch::enum_dispatch;
use serde::{Deserialize, Serialize};
use strum_macros::{AsRefStr, VariantNames};

use crate::{Badge, Severity, Summarize};

#[derive(
    Serialize, Deserialize, VariantNames, AsRefStr, clap::ValueEnum, Clone, Debug, PartialEq, Eq,
)]
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

#[enum_dispatch]
pub trait VulnQuery {
    fn status(&self) -> Option<&VulnerabilityStatus>;
    fn severity(&self) -> Option<&Severity>;
    fn vulnerability_id(&self) -> &str;
    fn title(&self) -> &str;
    fn description(&self) -> Option<&str>;
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
pub struct SystemPackageVulnerability {
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

impl VulnQuery for SystemPackageVulnerability {
    fn status(&self) -> Option<&VulnerabilityStatus> {
        self.status.as_ref()
    }

    fn severity(&self) -> Option<&Severity> {
        self.severity.as_ref()
    }

    fn vulnerability_id(&self) -> &str {
        &self.vulnerability_id
    }

    fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    fn title(&self) -> &str {
        &self.title
    }
}

/// Result struct mapped from trivy
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct DebianResult {
    pub target: String,
    pub class: String,
    #[serde(default)]
    pub vulnerabilities: Vec<SystemPackageVulnerability>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct AlpineResult {
    pub target: String,
    pub class: String,
    #[serde(default)]
    pub vulnerabilities: Vec<SystemPackageVulnerability>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct PythonVulnerability {
    #[serde(rename = "VulnerabilityID")]
    pub vulnerability_id: String,
    #[serde(rename = "PkgName")]
    pub package_name: String,
    pub status: Option<VulnerabilityStatus>,
    pub severity: Option<Severity>,
    pub title: String,
    pub description: Option<String>,
}

impl VulnQuery for PythonVulnerability {
    fn status(&self) -> Option<&VulnerabilityStatus> {
        self.status.as_ref()
    }

    fn severity(&self) -> Option<&Severity> {
        self.severity.as_ref()
    }

    fn vulnerability_id(&self) -> &str {
        &self.vulnerability_id
    }

    fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    fn title(&self) -> &str {
        &self.title
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct PythonPackageResult {
    pub target: String,
    pub class: String,

    #[serde(default)]
    pub vulnerabilities: Vec<PythonVulnerability>,
}

#[derive(Clone, Debug)]
#[enum_dispatch(VulnQuery)]
pub enum VulnerabilityType {
    SystemPackageVulnerability(SystemPackageVulnerability),
    PythonVulnerability(PythonVulnerability),
}

impl From<&Report> for Vec<VulnerabilityType> {
    fn from(report: &Report) -> Self {
        let mut vulnerabilities: Vec<VulnerabilityType> = vec![];
        report.results.iter().for_each(|res| match res {
            AuditResult::DebianResult(debian_result) => {
                debian_result.vulnerabilities.iter().cloned().for_each(|a| {
                    vulnerabilities.push(VulnerabilityType::SystemPackageVulnerability(a))
                })
            }
            AuditResult::AlpineResult(alpine_result) => {
                alpine_result.vulnerabilities.iter().cloned().for_each(|a| {
                    vulnerabilities.push(VulnerabilityType::SystemPackageVulnerability(a))
                })
            }
            AuditResult::PythonPackageResult(python_package_result) => python_package_result
                .vulnerabilities
                .iter()
                .cloned()
                .for_each(|a| vulnerabilities.push(VulnerabilityType::PythonVulnerability(a))),
        });
        vulnerabilities
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "Type")]
pub enum AuditResult {
    #[serde(rename = "debian")]
    DebianResult(DebianResult),

    #[serde(rename = "alpine")]
    AlpineResult(AlpineResult),

    #[serde(rename = "python-pkg")]
    PythonPackageResult(PythonPackageResult),
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

    /// Ignore vulnerabilities containing `status`.
    pub fn with_filter_on_status(mut self, status: &VulnerabilityStatus) -> Self {
        self.status_filters.push(status.clone());
        self
    }

    pub fn build(self, report: &Report) -> VulnerabilitySummary {
        let vulnerabilities: Vec<VulnerabilityType> = report.into();

        vulnerabilities
            .iter()
            .filter(|vuln| {
                let status = match vuln {
                    VulnerabilityType::SystemPackageVulnerability(debian_vulnerability) => {
                        debian_vulnerability.status()
                    }
                    VulnerabilityType::PythonVulnerability(python_vulnerability) => {
                        python_vulnerability.status()
                    }
                };
                if let Some(status) = status {
                    !self.status_filters.contains(status)
                } else {
                    false
                }
            })
            .into()
    }
}

/// A summary of the vulnerability counts in the report
#[derive(Clone, Debug)]
pub struct VulnerabilitySummary {
    pub low_severity: u64,
    pub medium_severity: u64,
    pub high_severity: u64,
    pub critical_severity: u64,

    pub vulnerabilities: Vec<VulnerabilityType>,
}

impl From<&Report> for VulnerabilitySummary {
    fn from(value: &Report) -> Self {
        let buf: Vec<VulnerabilityType> = value.into();
        buf.iter().into()
    }
}

impl From<Report> for VulnerabilitySummary {
    fn from(value: Report) -> Self {
        Self::from(&value)
    }
}

impl<'a, T: IntoIterator<Item = &'a VulnerabilityType>> From<T> for VulnerabilitySummary {
    fn from(iter: T) -> Self {
        let mut lows: u64 = 0;
        let mut meds: u64 = 0;
        let mut highs: u64 = 0;
        let mut crits: u64 = 0;
        let mut vulnerabilities: Vec<VulnerabilityType> = vec![];
        iter.into_iter().for_each(|vuln| {
            vulnerabilities.push(vuln.clone());

            if let Some(sev) = &vuln.severity() {
                match sev {
                    Severity::Low => {
                        lows += 1;
                    }
                    Severity::Medium => {
                        meds += 1;
                    }
                    Severity::High => {
                        highs += 1;
                    }
                    Severity::Critical => {
                        crits += 1;
                    }
                    _ => {}
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

impl Badge for VulnerabilitySummary {
    fn badge_message(&self) -> String {
        format!(
            "{} / {} / {} / {}",
            self.critical_severity, self.high_severity, self.medium_severity, self.low_severity
        )
    }

    fn color(&self) -> badge_maker::color::Color {
        if self.critical_severity > 0 {
            Color::Named(NamedColor::Red)
        } else if self.medium_severity > 0 {
            Color::Named(NamedColor::Orange)
        } else {
            Color::Named(NamedColor::Green)
        }
    }
}

impl Summarize for VulnerabilitySummary {
    fn summarize(&self) {
        log::info!("Low Severity Vulnerabilities = {}", self.low_severity);
        log::info!("Medium Severity Vulnerabilities = {}", self.medium_severity);
        log::info!("High Severity Vulnerabilities = {}", self.high_severity);
        log::info!(
            "Critical Severity Vulnerabilities = {}",
            self.critical_severity
        );
    }

    fn report_details(&self, report_sev: &Severity) {
        self.vulnerabilities
            .iter()
            .filter(|v| {
                if let Some(sev) = &v.severity() {
                    return sev.to_int() >= report_sev.to_int();
                }
                false
            })
            .for_each(|v| {
                log::info!(
                    "({}) {{{}}} {} {}",
                    v.severity().unwrap_or(&Severity::Unknown).short(),
                    v.status().unwrap_or(&VulnerabilityStatus::Unknown),
                    v.vulnerability_id(),
                    v.title()
                );
            });
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::fs::File;
    #[test]
    fn test_deserialize() -> Result<(), Box<dyn std::error::Error>> {
        let mut f = File::open("tests/data/sample-audit.json")?;
        let report: Report = serde_json::from_reader(&mut f)?;
        assert_eq!(report.artifact_name, "spectacles:latest");

        let debian_findings = match &report.results[0] {
            AuditResult::DebianResult(debian_result) => debian_result,
            _ => panic!("Unexpected result type as first result."),
        };
        assert_eq!(debian_findings.target, "spectacles:latest (debian 11.11)");

        let first_vuln = &debian_findings.vulnerabilities[0];
        assert_eq!(first_vuln.vulnerability_id, "CVE-2011-3374");

        let finding_with_status = debian_findings
            .vulnerabilities
            .iter()
            .filter(|v| v.vulnerability_id == "CVE-2016-2781")
            .next()
            .expect("This vulnerability should be found.");

        assert!(matches!(
            finding_with_status.status.as_ref().unwrap(),
            VulnerabilityStatus::WillNotFix
        ));
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

    #[test]
    fn test_alpine_summary() -> Result<(), Box<dyn std::error::Error>> {
        let mut f = File::open("tests/data/trivy-report-alpine.json")?;
        let report: Report = serde_json::from_reader(&mut f)?;

        let summary = VulnerabilitySummary::from(report);
        assert_eq!(summary.low_severity, 4);
        assert_eq!(summary.medium_severity, 28);
        assert_eq!(summary.high_severity, 0);
        assert_eq!(summary.critical_severity, 0);

        Ok(())
    }

    #[test]
    fn test_debian_vuln_deserialize() -> Result<(), Box<dyn std::error::Error>> {
        let mut f = File::open("tests/data/debian-vuln.json")?;
        let debian_vulnerability: SystemPackageVulnerability = serde_json::from_reader(&mut f)?;
        assert_eq!(
            debian_vulnerability.title(),
            "It was found that apt-key in apt, all versions, do not correctly valid ..."
        );

        Ok(())
    }

    #[test]
    fn test_debian_result_deserialize() -> Result<(), Box<dyn std::error::Error>> {
        let mut f = File::open("tests/data/debian-result.json")?;
        let result: DebianResult = serde_json::from_reader(&mut f)?;

        assert_eq!(result.vulnerabilities[0].title(), "zlib: integer overflow and resultant heap-based buffer overflow in zipOpenNewFileInZip4_6");

        Ok(())
    }

    #[test]
    fn test_combined_result_deserialize() -> Result<(), Box<dyn std::error::Error>> {
        let mut f = File::open("tests/data/debian-result.json")?;
        let _result: AuditResult = serde_json::from_reader(&mut f)?;

        Ok(())
    }

    #[test]
    fn test_deserialize_python_vuln() -> Result<(), Box<dyn std::error::Error>> {
        let mut f = File::open("tests/data/python-vuln.json")?;
        let _result: PythonVulnerability = serde_json::from_reader(&mut f)?;

        Ok(())
    }

    #[test]
    fn test_deserialize_python_result() -> Result<(), Box<dyn std::error::Error>> {
        let mut f = File::open("tests/data/python-result.json")?;
        let _result: PythonPackageResult = serde_json::from_reader(&mut f)?;

        Ok(())
    }

    #[test]
    fn test_combined_with_python() -> Result<(), Box<dyn std::error::Error>> {
        let mut f = File::open("tests/data/metascripts-audit.json")?;
        let report: Report = serde_json::from_reader(&mut f)?;

        let summary = VulnerabilitySummaryBuilder::new()
            .with_filter_on_status(&VulnerabilityStatus::Unknown)
            .with_filter_on_status(&VulnerabilityStatus::NotAffected)
            .build(&report);

        assert_eq!(summary.low_severity, 58);
        assert_eq!(summary.medium_severity, 16);
        assert_eq!(summary.high_severity, 1);
        assert_eq!(summary.critical_severity, 1);

        Ok(())
    }
}
