use serde::{Deserialize, Serialize};

use super::SystemPackageVulnerability;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct AlpineResult {
    pub target: String,
    pub class: String,
    #[serde(default)]
    pub vulnerabilities: Vec<SystemPackageVulnerability>,
}
