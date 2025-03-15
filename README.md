## VirusTotal Client
[![Test](https://github.com/malwaredb/vt-client/actions/workflows/test.yml/badge.svg)](https://github.com/malwaredb/vt-client/actions/workflows/test.yml)[![Lint](https://github.com/malwaredb/vt-client/actions/workflows/lint.yml/badge.svg)](https://github.com/malwaredb/vt-client/actions/workflows/lint.yml)[![Documentation](https://docs.rs/malwaredb-virustotal/badge.svg)](https://docs.rs/malwaredb-virustotal/)[![Crates.io Version](https://img.shields.io/crates/v/malwaredb-virustotal)](https://crates.io/crates/malwaredb-virustotal)[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/malwaredb/vt-client/badge)](https://securityscorecards.dev/viewer/?uri=github.com/malwaredb/vt-client)

This is logic for interacting with [VirusTotal](https://www.virustotal.com)'s [V3 API](https://virustotal.readme.io/reference/overview). At present, only the following actions are supported:
* Fetch file & domain reports: this gets the anti-virus scan data for a given sample, and there are examples in the `testdata/` directory.
  * The goal is for the file report to have all the possible fields for increased ease of use.
* Request file re-scan: ask VirusTotal to run a given sample through their collection of anti-virus applications and analysis tools.
* Submit a file sample: send a sample to VirusTotal for analysis.
* Download a file sample: download the original sample from VirusTotal (not fully tested, requires VirusTotal Premium).
* Search: find the hashes of files which match some search criteria (not fully tested, requires VirusTotal Premium, uses older V2 API). See VirusTotal's [doc](https://virustotal.readme.io/v2.0/reference/file-search) for more information.
* The file report object and error types can be useful when interacting with VirusTotal using another crate or using VT's API directly; you don't have to use the client object in this crate to use the data (and error) types in this crate.

VirusTotal supports these actions given a MD5, SHA-1, or SHA-256 hash.

Additionally, this provides a client application (in `bin/`, or [malwaredb-virustotal-bin](https://crates.io/crates/malwaredb-virustotal-bin)) for the supported operations on the command line.

### MUSL Targets
It's recommended to use the `native-tls-vendored` feature to avoid OpenSSL build errors when compiling for Linux [MUSL](https://musl.libc.org/) targets. See the example `Cargo.toml` entry below:

```toml
[target.'cfg(target_env = "musl")'.dependencies]
malwaredb-virustotal = { version = "0.4", features = ["native-tls-vendored"] }
```
