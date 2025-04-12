use std::fmt::Display;

use badge_maker::color::{Color, NamedColor};
use cvss::v3::Base;
pub use rustsec::Report;
use rustsec::Vulnerability;
use serde::Serialize;

use crate::{Badge, Severity, Summarize};

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

impl From<&rustsec::Vulnerability> for VulnerabilityOverview {
    fn from(vuln: &rustsec::Vulnerability) -> Self {
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
                .map_or(Severity::Unknown, |cvss| cvss.severity().clone().into()),
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
            .map(|vuln| VulnerabilityOverview::from(vuln))
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
            .filter(|v| {
                v.severity.to_int() >= report_sev.to_int()
            })
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

    use super::{Report, VulnerabilityOverview, VulnerabilitySummary};
    #[test]
    fn test_deserialize_cargo_audit() -> Result<(), Box<dyn std::error::Error>> {
        let f = File::open("tests/data/cargo-audit-high.json")?;
        let rep: Report = serde_json::from_reader(f)?;
        let summary = VulnerabilitySummary::from(rep);
        println!("{:#?}", summary);

        Ok(())
    }
}
