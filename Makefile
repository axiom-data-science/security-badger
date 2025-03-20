generate-badges:
	cargo run -- --svg examples/filtered.svg --filter will-not-fix --filter not-affected tests/data/sample-audit.json
	cargo run -- --svg examples/vulnerable.svg tests/data/sample-audit.json
