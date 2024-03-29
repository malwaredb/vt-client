## MalwareDB VirusTotal Client
[![Test](https://github.com/malwaredb/vt-client/actions/workflows/test.yml/badge.svg)](https://github.com/malwaredb/vt-client/actions/workflows/test.yml)[![Lint](https://github.com/malwaredb/vt-client/actions/workflows/lint.yml/badge.svg)](https://github.com/malwaredb/vt-client/actions/workflows/lint.yml)[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/malwaredb/vt-client/badge)](https://securityscorecards.dev/viewer/?uri=github.com/malwaredb/vt-client)

This is logic for interacting with [VirusTotal](https://www.virustotal.com)'s [V3 API](https://virustotal.readme.io/reference/overview). At present, only the following actions are supported:
* Fetch file report: this gets the anti-virus scan data for a given sample, and there are examples in the `testdata/` directory.
* Request re-scan: ask VirusTotal to run a given sample through their collection of anti-virus applications and analysis tools.
* Submit a sample: send a sample to VirusTotal for analysis.
* The file report object and error types can be useful when interacting with VirusTotal using another crate or using VT's API directly; you don't have to use the client object in this crate to use the data (and error) types in this crate.
* Download a sample: download the original sample from VirusTotal (not fully tested, requires VirusTotal Premium).

VirusTotal supports these actions given a MD5, SHA-1, or SHA-256 hash.

Crates `chrono` and `serde` are used to parse timestamps and deserialize the data into Structs for ease and convenience of working with this data.
