use thiserror::Error as ThisError;
pub mod trivy;

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("Read: failed to open the file for reading: {0}")]
    Read(std::io::Error),

    #[error("Json: Failed to parse the file as valid JSON: {0}")]
    Json(serde_json::Error),

    #[error("NotAStatus: The value is not a valid VulnerabilityStatus")]
    NotAStatus,

    #[error("Svg: Failed to produce an SVG Badge: {0}")]
    Svg(badge_maker::error::Error),

    #[error("Write: failed to open a file for writing: {0}")]
    Write(std::io::Error),
}
