![Pipeline Status](http://git.axiom/axiom/security-badger/badges/main/pipeline.svg)

security-badger
===============

![logo](logo.png)

Create badges based on audit reports. security-badger can parse trivy and
cargo-audit reports as JSON document, and produce an SVG Badge of the severity
breakdown of the reported vulnerabilities.

Copyright 2025 Axiom Data Science, LLC

See LICENSE for details.

Building
--------

In order to build the project, contributors need rust, see
[Install Rust](https://www.rust-lang.org/tools/install) for details about
installing the rust development environment on your system.

To build the project:

    cargo build

To run the binary without building a release version or installing to a locally available path:

    cargo run

For details about `cargo` and using `cargo`, please see [The Cargo Book](https://doc.rust-lang.org/cargo/commands/index.html)

Docker
------

To build the docker image:

    docker build -t security-badger .

To run the image as a docker container

    docker run -it --rm security-badger


Usage
-----

```
Usage: security-badger [OPTIONS] <AUDIT_JSON>

Arguments:
  <AUDIT_JSON>  Path to the audit report as JSON

Options:
  -v, --verbose
          Increase verbosity
      --trivy-filter <TRIVY_FILTER>
          Ignore vulnerabilities reported by trivy with this status [possible values: unknown, not-affected, affected, fixed, under-investigation, will-not-fix, fix-deferred, end-of-life]
      --report-severity <REPORT_SEVERITY>
          Log vulnerabilities with at least this severity [possible values: unknown, low, medium, high, critical]
      --svg <SVG>
          Output an SVG Badge
  -l, --label <LABEL>
          SVG Badge Label to use, Defaults to "vulns" [default: vulns]
  -h, --help
          Print help
  -V, --version
          Print version
```

Examples
--------

To log a brief summary of critical vulnerabilities:

```
$ security-badger --report-severity critical tests/data/sample-audit.json
2025-03-20T14:34:28.219Z INFO  [security_badger] Low Severity Vulnerabilities = 76
2025-03-20T14:34:28.219Z INFO  [security_badger] Medium Severity Vulnerabilities = 27
2025-03-20T14:34:28.219Z INFO  [security_badger] High Severity Vulnerabilities = 3
2025-03-20T14:34:28.219Z INFO  [security_badger] Critical Severity Vulnerabilities = 2
2025-03-20T14:34:28.219Z INFO  [security_badger] (C!) {will_not_fix} CVE-2019-8457 sqlite: heap out-of-bound read in function rtreenode()
2025-03-20T14:34:28.219Z INFO  [security_badger] (C!) {will_not_fix} CVE-2023-45853 zlib: integer overflow and resultant heap-based buffer overflow in zipOpenNewFileInZip4_6
```


To generate an SVG badge:
```
$ security-badger --svg vulns.svg tests/data/sample-audit.json
2025-03-20T14:34:28.219Z INFO  [security_badger] Low Severity Vulnerabilities = 76
2025-03-20T14:34:28.219Z INFO  [security_badger] Medium Severity Vulnerabilities = 27
2025-03-20T14:34:28.219Z INFO  [security_badger] High Severity Vulnerabilities = 3
2025-03-20T14:34:28.219Z INFO  [security_badger] Critical Severity Vulnerabilities = 2
```

![vulnerable.svg](examples/vulnerable.svg)

To generate a badge but filter vulnerabiltiies marked as `wont_fix` or `not_affected`:

```
$ security-badger --svg vulns.svg tests/data/sample-audit.json
2025-03-20T14:37:08.839Z INFO  [security_badger] Low Severity Vulnerabilities = 75
2025-03-20T14:37:08.839Z INFO  [security_badger] Medium Severity Vulnerabilities = 25
2025-03-20T14:37:08.839Z INFO  [security_badger] High Severity Vulnerabilities = 3
2025-03-20T14:37:08.839Z INFO  [security_badger] Critical Severity Vulnerabilities = 0
```

![filtered.svg](examples/filtered.svg)
