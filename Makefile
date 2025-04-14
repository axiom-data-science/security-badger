generate-badges:
	cargo run -- --svg examples/filtered.svg --trivy-filter will-not-fix --trivy-filter not-affected tests/data/sample-audit.json
	cargo run -- --svg examples/vulnerable.svg tests/data/sample-audit.json
	cargo run -- --label 'Cargo Audit' --svg examples/cargo-audit.svg tests/data/cargo-audit-high.json
