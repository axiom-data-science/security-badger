use serde::{Deserialize, Serialize};

use crate::Severity;

use super::{VulnQuery, VulnerabilityStatus};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct SecretScanVulnerability {
    pub severity: String,
    pub title: String,
    pub category: String,
}

impl VulnQuery for SecretScanVulnerability {
    fn status(&self) -> Option<&VulnerabilityStatus> {
        None
    }

    fn severity(&self) -> Option<&Severity> {
        match self.severity.as_str() {
            "MEDIUM" => Some(&Severity::Medium),
            "HIGH" => Some(&Severity::High),
            "CRITICAL" => Some(&Severity::Critical),
            "LOW" => Some(&Severity::Low),
            _ => None,
        }
    }

    fn vulnerability_id(&self) -> &str {
        &self.title
    }

    fn title(&self) -> &str {
        &self.title
    }

    fn description(&self) -> Option<&str> {
        Some(&self.title)
    }

    fn package(&self) -> Option<&str> {
        None
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct SecretScanResult {
    pub target: String,
    pub class: String,
    pub secrets: Vec<SecretScanVulnerability>,
}
