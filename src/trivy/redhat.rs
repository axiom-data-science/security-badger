use serde::{Deserialize, Serialize};

use super::SystemPackageVulnerability;

/// Result struct mapped from trivy
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct RedhatResult {
    pub target: String,
    pub class: String,
    #[serde(default)]
    pub vulnerabilities: Vec<SystemPackageVulnerability>,
}
