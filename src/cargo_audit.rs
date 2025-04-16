use chrono::NaiveDate;
use std::fmt::Display;

use badge_maker::color::{Color, NamedColor};
use cvss::v3::Base;
use serde::{Deserialize, Serialize};

use crate::{Badge, Severity, Summarize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Metadata {
    /// Security advisory ID (e.g. RUSTSEC-YYYY-NNNN)
    pub id: String,

    /// Name of affected crate
    pub package: String,

    /// One-liner description of a vulnerability
    #[serde(default)]
    pub title: String,

    /// Extended description of a vulnerability
    #[serde(default)]
    pub description: String,

    /// NaiveDate the underlying issue was reported
    pub date: NaiveDate,

    /// Advisory IDs in other databases which point to the same advisory
    #[serde(default)]
    pub aliases: Vec<String>,

    /// RustSec vulnerability categories: one of a fixed list of vulnerability
    /// categorizations accepted by the project.
    #[serde(default)]
    pub categories: Vec<String>,

    /// Freeform keywords which succinctly describe this vulnerability (e.g. "ssl", "rce", "xss")
    #[serde(default)]
    pub keywords: Vec<String>,

    /// CVSS v3.1 Base Metrics vector string containing severity information.
    ///
    /// Example:
    ///
    /// ```text
    /// CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
    /// ```
    pub cvss: Option<cvss::v3::Base>,

    /// Additional reference URLs with more information related to this advisory
    #[serde(default)]
    pub references: Vec<String>,

    /// URL with an announcement (e.g. blog post, PR, disclosure issue, CVE)
    pub url: Option<String>,

    /// Was this advisory (i.e. itself, regardless of the crate) withdrawn?
    /// If yes, when?
    ///
    /// This can be used to soft-delete advisories which were filed in error.
    #[serde(default)]
    pub withdrawn: Option<NaiveDate>,

    /// License under which the advisory content is available
    #[serde(default)]
    pub license: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Package {
    /// Name of the package
    pub name: String,

    /// Version of the package
    pub version: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Versions {
    /// Versions which are patched and not vulnerable (expressed as semantic version requirements)
    patched: Vec<String>,

    /// Versions which were never affected in the first place
    #[serde(default)]
    unaffected: Vec<String>,
}

impl Versions {
    fn patched(&self) -> &[String] {
        self.patched.as_slice()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Vulnerability {
    /// Security advisory for which the package is vulnerable
    pub advisory: Metadata,

    /// Versions impacted by this vulnerability
    pub versions: Versions,

    /*
    /// More specific information about what this advisory affects (if available)
    pub affected: Option<advisory::Affected>,

    */
    /// Vulnerable package
    pub package: Package,
}

/// Information about detected vulnerabilities
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct VulnerabilityInfo {
    /// Were any vulnerabilities found?
    pub found: bool,

    /// Number of vulnerabilities found
    pub count: usize,

    /// List of detected vulnerabilities
    pub list: Vec<Vulnerability>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Report {
    /// Vulnerabilities detected in project
    pub vulnerabilities: VulnerabilityInfo,
}

#[derive(Debug, Clone, Serialize)]
pub enum VulnerabilityStatus {
    /// The crate has a patch on a more recent version
    Patched,
    /// The crate does not have a patch or remains still affected for other reasons
    Affected,
}

impl VulnerabilityStatus {
    fn as_str(&self) -> &str {
        match self {
            VulnerabilityStatus::Patched => "patched",
            VulnerabilityStatus::Affected => "affected",
        }
    }
}

impl Display for VulnerabilityStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl From<&Vulnerability> for VulnerabilityStatus {
    fn from(vuln: &Vulnerability) -> Self {
        if vuln.versions.patched().is_empty() {
            Self::Affected
        } else {
            Self::Patched
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct VulnerabilityOverview {
    pub package: String,
    pub title: String,
    pub advisory_aliases: Vec<String>,
    pub keywords: Vec<String>,
    pub cvss: Option<Base>,
    pub severity: Severity,
    pub status: VulnerabilityStatus,
}

impl From<&cvss::Severity> for Severity {
    fn from(severity: &cvss::Severity) -> Self {
        match severity {
            cvss::Severity::None => Self::Unknown,
            cvss::Severity::Low => Self::Low,
            cvss::Severity::Medium => Self::Medium,
            cvss::Severity::High => Self::High,
            cvss::Severity::Critical => Self::Critical,
        }
    }
}

impl From<cvss::Severity> for Severity {
    fn from(severity: cvss::Severity) -> Self {
        Self::from(&severity)
    }
}

impl From<&Vulnerability> for VulnerabilityOverview {
    fn from(vuln: &Vulnerability) -> Self {
        Self {
            package: format!("{}@{}", vuln.package.name, vuln.package.version),
            title: vuln.advisory.title.clone(),
            advisory_aliases: vuln
                .advisory
                .aliases
                .iter()
                .map(|id| id.as_str().into())
                .collect(),
            keywords: vuln
                .advisory
                .keywords
                .iter()
                .map(|keyword| keyword.as_str().into())
                .collect(),
            cvss: vuln.advisory.cvss.clone(),
            severity: vuln
                .advisory
                .cvss
                .as_ref()
                .map_or(Severity::Unknown, |cvss| cvss.severity().into()),
            status: VulnerabilityStatus::from(vuln),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct VulnerabilitySummary {
    pub unknown: u32,
    pub low: u32,
    pub medium: u32,
    pub high: u32,
    pub critical: u32,
    pub vulnerabilities: Vec<VulnerabilityOverview>,
}

impl From<Vec<VulnerabilityOverview>> for VulnerabilitySummary {
    fn from(vulns: Vec<VulnerabilityOverview>) -> Self {
        let mut unknown: u32 = 0;
        let mut low: u32 = 0;
        let mut medium: u32 = 0;
        let mut high: u32 = 0;
        let mut critical: u32 = 0;
        vulns.iter().for_each(|overview| match overview.severity {
            Severity::Unknown => unknown += 1,
            Severity::Low => low += 1,
            Severity::Medium => medium += 1,
            Severity::High => high += 1,
            Severity::Critical => critical += 1,
        });
        Self {
            unknown,
            low,
            medium,
            high,
            critical,
            vulnerabilities: vulns,
        }
    }
}

impl From<Report> for VulnerabilitySummary {
    fn from(report: Report) -> Self {
        let overviews: Vec<VulnerabilityOverview> = report
            .vulnerabilities
            .list
            .iter()
            .map(VulnerabilityOverview::from)
            .collect();
        Self::from(overviews)
    }
}

impl Badge for VulnerabilitySummary {
    fn badge_message(&self) -> String {
        format!(
            "{} / {} / {} / {} / {}",
            self.critical, self.high, self.medium, self.low, self.unknown
        )
    }
    fn color(&self) -> badge_maker::color::Color {
        if self.critical > 0 {
            Color::Named(NamedColor::Red)
        } else if self.medium > 0 {
            Color::Named(NamedColor::Orange)
        } else if self.unknown > 0 {
            Color::Named(NamedColor::Grey)
        } else {
            Color::Named(NamedColor::Green)
        }
    }
}

impl Summarize for VulnerabilitySummary {
    fn summarize(&self) {
        log::info!("Unknown Vulnerabilities = {}", self.unknown);
        log::info!("Low Severity Vulnerabilities = {}", self.low);
        log::info!("Medium Severity Vulnerabilities = {}", self.medium);
        log::info!("High Severity Vulnerabilities = {}", self.high);
        log::info!("Critical Severity Vulnerabilities = {}", self.critical);
    }

    fn report_details(&self, report_sev: &Severity) {
        self.vulnerabilities
            .iter()
            .filter(|v| v.severity.to_int() >= report_sev.to_int())
            .for_each(|v| {
                log::info!(
                    "({}) {{{}}} {} {} {}",
                    v.severity.short(),
                    v.status.as_str(),
                    v.advisory_aliases.join(" "),
                    v.package,
                    v.title
                );
            });
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use super::{Report, VulnerabilitySummary};
    #[test]
    fn test_deserialize_cargo_audit() -> Result<(), Box<dyn std::error::Error>> {
        let f = File::open("tests/data/cargo-audit-high.json")?;
        let rep: Report = serde_json::from_reader(f)?;
        let summary = VulnerabilitySummary::from(rep);
        assert_eq!(summary.critical, 0);
        assert_eq!(summary.high, 1);
        assert_eq!(summary.medium, 0);
        assert_eq!(summary.low, 0);
        assert_eq!(summary.unknown, 0);

        Ok(())
    }
}
