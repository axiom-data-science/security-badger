use serde::{Deserialize, Serialize};

use crate::Severity;

use super::{VulnQuery, VulnerabilityStatus};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct JavaVulnerability {
    #[serde(rename = "VulnerabilityID")]
    pub vulnerability_id: String,
    #[serde(rename = "PkgName")]
    pub package_name: String,
    pub status: Option<VulnerabilityStatus>,
    pub severity: Option<Severity>,
    pub title: String,
    pub description: Option<String>,
}

impl VulnQuery for JavaVulnerability {
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
        Some(&self.package_name)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct JavaJarResult {
    pub target: String,
    pub class: String,
    #[serde(rename = "Type")]
    pub package_type: String,

    #[serde(default)]
    pub vulnerabilities: Vec<JavaVulnerability>,
}
