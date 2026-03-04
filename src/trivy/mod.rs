pub mod alpine;
pub use alpine::AlpineResult;
pub mod debian;
pub use debian::DebianResult;
pub mod java;
pub use java::{JavaJarResult, JavaVulnerability};
pub mod python;
pub use python::{PythonPackageResult, PythonVulnerability};
pub mod secret_scan;
pub use secret_scan::{SecretScanResult, SecretScanVulnerability};

use std::fmt::Display;

use badge_maker::color::{Color, NamedColor};
use chrono::{DateTime, Utc};
use convert_case::{Case, Casing};
use enum_dispatch::enum_dispatch;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
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
    fn package(&self) -> Option<&str>;
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

    fn package(&self) -> Option<&str> {
        Some(&self.pkg_id)
    }
}




#[derive(Clone, Debug)]
#[enum_dispatch(VulnQuery)]
pub enum VulnerabilityType {
    SystemPackageVulnerability(SystemPackageVulnerability),
    PythonVulnerability(PythonVulnerability),
    SecretScanVulnerability(SecretScanVulnerability),
    JavaVulnerability(JavaVulnerability),
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
            AuditResult::JavaJarResult(java_jar_result) => java_jar_result
                .vulnerabilities
                .iter()
                .cloned()
                .for_each(|a| vulnerabilities.push(VulnerabilityType::JavaVulnerability(a))),
            AuditResult::SecretScanResult(secret_scan_result) => {
                secret_scan_result.secrets.iter().cloned().for_each(|a| {
                    vulnerabilities.push(VulnerabilityType::SecretScanVulnerability(a))
                })
            }
        });
        vulnerabilities
    }
}

#[derive(Serialize, Clone, Debug)]
pub enum AuditResult {
    #[serde(rename = "debian")]
    DebianResult(DebianResult),

    #[serde(rename = "alpine")]
    AlpineResult(AlpineResult),

    #[serde(rename = "python-pkg")]
    PythonPackageResult(PythonPackageResult),

    #[serde(rename = "secret")]
    SecretScanResult(SecretScanResult),

    #[serde(rename = "jar")]
    JavaJarResult(JavaJarResult),
}

impl<'de> Deserialize<'de> for AuditResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Deserialize into a generic JSON Value first to inspect the structure
        let value = Value::deserialize(deserializer)?;

        let obj = value
            .as_object()
            .ok_or_else(|| serde::de::Error::custom("Expected object for AuditResult"))?;

        if let Some(type_field) = obj.get("Type").and_then(|v| v.as_str()) {
            match type_field {
                "debian" => {
                    return DebianResult::deserialize(value)
                        .map(AuditResult::DebianResult)
                        .map_err(serde::de::Error::custom);
                }
                "ubuntu" => {
                    return DebianResult::deserialize(value)
                        .map(AuditResult::DebianResult)
                        .map_err(serde::de::Error::custom);
                }
                "alpine" => {
                    return AlpineResult::deserialize(value)
                        .map(AuditResult::AlpineResult)
                        .map_err(serde::de::Error::custom);
                }
                "python-pkg" => {
                    return PythonPackageResult::deserialize(value)
                        .map(AuditResult::PythonPackageResult)
                        .map_err(serde::de::Error::custom);
                }
                "jar" => {
                    return JavaJarResult::deserialize(value)
                        .map(AuditResult::JavaJarResult)
                        .map_err(serde::de::Error::custom);
                }
                _ => {}
            }
        }

        if let Some(class_field) = obj.get("Class").and_then(|v| v.as_str()) {
            if class_field == "secret" {
                return SecretScanResult::deserialize(value)
                    .map(AuditResult::SecretScanResult)
                    .map_err(serde::de::Error::custom);
            }
        }

        Err(serde::de::Error::custom(
            "Unable to determine AuditResult variable from JSON structure",
        ))
    }
}

/// Report struct mapped from trivy/pkg/types/report.go
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct Report {
    pub artifact_name: String,
    pub schema_version: i32,
    pub artifact_type: String,

    #[serde(default)]
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
                    VulnerabilityType::SecretScanVulnerability(secret_scan_vuln) => {
                        secret_scan_vuln.status()
                    }
                    VulnerabilityType::JavaVulnerability(java_vulnerability) => {
                        java_vulnerability.status()
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
                if let Some(package) = v.package() {
                    log::debug!("{}", package);
                }
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
