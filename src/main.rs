//! security-badger Create badges based on audit reports
//!
//! TODO Long Description
//!
//! # Examples
//!
//! TODO Example
use simple_logger::SimpleLogger;

use clap::Parser;



/// Program Arguments
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Increase verbosity
    #[arg(short, long, default_value_t = false)]
    verbose: bool,
}


/// Main entry point
fn main() {
    SimpleLogger::new()
        .init()
        .expect("Failed to initialize logging.");
    log::info!("Hello, World!");
    // Parse arguments
    let args = Args::parse();
}
