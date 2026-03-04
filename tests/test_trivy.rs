use flate2::read::GzDecoder;
use security_badger::trivy::{
    AuditResult, DebianResult, PythonPackageResult, PythonVulnerability, Report,
    SystemPackageVulnerability, VulnerabilitySummary, VulnerabilitySummaryBuilder,
    VulnerabilityStatus, VulnQuery,
};

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

#[test]
fn test_debian12() -> Result<(), Box<dyn std::error::Error>> {
    let mut f = File::open("tests/data/debian12-report.json")?;
    let report: Report = serde_json::from_reader(&mut f)?;
    let summary = VulnerabilitySummaryBuilder::new().build(&report);

    assert_eq!(summary.low_severity, 1);
    assert_eq!(summary.medium_severity, 0);
    assert_eq!(summary.high_severity, 0);
    assert_eq!(summary.critical_severity, 0);

    Ok(())
}

#[test]
fn test_geoserver() -> Result<(), Box<dyn std::error::Error>> {
    let f = File::open("tests/data/geoserver-2.28.x.trivy.json.gz")?;
    let mut reader = GzDecoder::new(f);
    let report: Report = serde_json::from_reader(&mut reader)?;
    let summary = VulnerabilitySummaryBuilder::new().build(&report);
    assert_eq!(summary.low_severity, 33);
    assert_eq!(summary.medium_severity, 76);
    assert_eq!(summary.high_severity, 4);
    assert_eq!(summary.critical_severity, 3);

    Ok(())
}


#[test]
fn test_empty_results() -> Result<(), Box<dyn std::error::Error>> {
    let f = std::fs::read_to_string("tests/data/empty-audit.json")?;
    let report: Report = serde_json::from_str(&f)?;
    let summary = VulnerabilitySummaryBuilder::new().build(&report);
    println!("{:?}", summary);
    Ok(())
}
