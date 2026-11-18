# Nessus Scan Automation

A .NET 10 command-line tool and library that drives one Nessus scan through the REST API. It creates the scan, launches it, monitors it to a terminal state, and exports the findings to JSON and CSV. It is built for an explicitly authorised scope, and it fails safely when the API, the network or the scan misbehaves.

The original single-file prototype (`AutoNessus.cs`) did not compile and disabled TLS validation process-wide. It also dropped the selected template from the create request, swallowed every HTTP error, and could poll forever. This version replaces it. The prototype remains in the git history.

## What it does

| Command | Network | What happens |
|---|---|---|
| `validate` | none | Parses and checks every scan option offline: scope, targets, template/policy choice, timeouts and output paths. |
| `templates` | read-only | Lists Tenable scan templates (`GET /editor/scan/templates`). |
| `policies` | read-only | Lists saved policies (`GET /policies`). |
| `scan --dry-run` | read-only | Authenticates, resolves the template/policy and prints the exact `POST /scans` body. Nothing is created. |
| `scan --confirm-authorized` | **launches a scan** | Create → launch → poll → collect findings → write `<prefix>.findings.json` and `<prefix>.findings.csv`. |
| `results` | read-only | Exports findings from an existing completed scan (optionally a specific `--history-id`). |

It does not schedule scans, discover hosts, expand the target list or manage scanners. It sends only the targets you list, and only after checking each one against the scope you supply.

## Architecture

```
src/NessusAutomation/            class library
  Api/            NessusClient (HttpClient, auth, timeouts, retry rules), response parser, models, errors
  Configuration/  connection/TLS/retry options, scan-job options, target-scope validator
  Http/           per-client SocketsHttpHandler factory (certificate policy lives here)
  Orchestration/  ScanOrchestrator: resolve → create → launch → poll → collect; status classification
  Export/         findings model, JSON/CSV writer (atomic writes, CSV escaping)
  Security/       SecretRedactor, redacting logger
src/NessusAutomation.Cli/        `nessus-auto` executable: argument parsing, env-var credentials, exit codes
tests/NessusAutomation.Tests/    xUnit tests against an in-memory fake Nessus HTTP handler
```

The CLI takes its stdout/stderr writers, environment lookup and HTTP handler as constructor arguments, so tests run every command end to end without a server.

## Nessus API assumptions

These are the endpoints and fields the tool depends on. The request and response shapes come from two Tenable sources: the source of Tenable's own Python SDK ([pytenable `tenable.nessus`](https://pytenable.readthedocs.io/en/latest/_modules/tenable/nessus/scans.html)), and the [Tenable Vulnerability Management API reference](https://developer.tenable.com/reference/scans-create), which documents the same `/scans`, `/editor` and `/policies` endpoints. **The tool has not been run against a live Nessus instance as part of this work.** Check these assumptions against the API documentation that ships with your Nessus version before relying on it. See [Lab verification](docs/lab-verification.md).

| Step | Request | Fields used |
|---|---|---|
| Login (password) | `POST /session` `{username, password}` | `token`, then sent as `X-Cookie: token=…` |
| Login (API keys) | none | `X-ApiKeys: accessKey=…; secretKey=…` on every request |
| Logout | `DELETE /session` | only for password sessions |
| Templates | `GET /editor/scan/templates` | `templates[].uuid`, `.name`, `.title`, `.unsupported` |
| Policies | `GET /policies` | `policies[].id`, `.name`, `.template_uuid` (`null` list = none saved) |
| Create | `POST /scans` | body below; response `scan.id` |
| Launch | `POST /scans/{id}/launch` | response `scan_uuid` (optional; see below) |
| Poll | `GET /scans/{id}` | `info.status`, `history[].history_id/uuid/status` |
| Collect | `GET /scans/{id}?history_id=` | `hosts[].host_id/hostname` |
| Host findings | `GET /scans/{id}/hosts/{host_id}?history_id=` | `vulnerabilities[].plugin_id/plugin_name/plugin_family/severity/count` |
| Plugin details | `GET /scans/{id}/hosts/{host_id}/plugins/{plugin_id}?history_id=` | `info.plugindescription.pluginattributes.synopsis/solution/risk_information/ref_information` |
| Stop (opt-in) | `POST /scans/{id}/stop` | none |

**Templates and policies are different things.** A template is Tenable-provided and identified by a UUID. A policy is a configuration you saved, identified by an integer ID, and it records the template it was built from as `template_uuid`. The create body follows from that:

```jsonc
// --template basic
{ "uuid": "<template uuid>", "settings": { "name": "…", "text_targets": "192.0.2.10,web01.lab.test", "enabled": false } }
// --policy-id 15
{ "uuid": "<policy's template_uuid>", "settings": { "name": "…", "text_targets": "…", "enabled": false, "policy_id": 15 } }
```

`description` and `folder_id` are added only when supplied. `enabled: false` means the scan has no schedule and runs only when explicitly launched. No other settings are sent.

**Polling tracks the run you launched.** When the launch response includes `scan_uuid`, the poller reads the status of the `history[]` entry with that UUID and pins result collection to its `history_id`. That way an older run's status or results cannot be mistaken for the new run's. If `scan_uuid` is absent, the tool logs a warning and falls back to `info.status`.

**Fields read only when present.** The CVSS scores and CVE references come from `risk_information.cvss3_base_score`, `risk_information.cvss_base_score` and `ref_information.ref[name=cve]`. Tenable's published references show these objects but do not fully specify their keys, so missing values become empty columns rather than errors.

**Edition limits.** Tenable has changed over time which Nessus editions allow scan management through the API (for example around Nessus Professional 7). Check that your edition and licence permit API scan creation. If Nessus rejects the request, the tool reports the HTTP error and stops. It does not try to work around product restrictions.

## Prerequisites

- .NET SDK 10.0.100 or later (pinned with `rollForward: latestFeature` in `global.json`). Built and tested locally with SDK 10.0.404.
- For the `scan`, `results`, `templates` and `policies` commands: a reachable Nessus instance over HTTPS, an account permitted to create and launch scans, and written authorisation for every target.

## Build and test

```bash
dotnet build NessusAutomation.slnx -c Release
```

```bash
dotnet test NessusAutomation.slnx -c Release
```

The default test suite is fully offline. It uses a fake `HttpMessageHandler` and needs no Nessus instance, credentials, network access or cloud resources. CI (`.github/workflows/ci.yml`) runs the same build and tests on Ubuntu and Windows with a read-only `contents: read` token and SHA-pinned actions.

Running the CLI from source:

```bash
dotnet run --project src/NessusAutomation.Cli -- help
```

Or publish the CLI (the executable is named `nessus-auto`):

```bash
dotnet publish src/NessusAutomation.Cli -c Release -o publish
```

## Configuration

### Credentials (environment only)

Secrets are never accepted as command-line arguments. `--password`, `--secret-key`, `--token` and similar options are rejected outright, so credentials stay out of shell history and process listings. Set **exactly one** pair:

| Variables | Mechanism |
|---|---|
| `NESSUS_ACCESS_KEY`, `NESSUS_SECRET_KEY` | API keys (`X-ApiKeys`). Preferred: no session is created. |
| `NESSUS_USERNAME`, `NESSUS_PASSWORD` | `POST /session` token. The session is closed with `DELETE /session` on exit, including after Ctrl+C. |

`NESSUS_URL` may stand in for `--url`. If both pairs are set, or only half of one, the tool exits with code 2.

Example (PowerShell 7+, prompting so the secret is not typed into history):

```powershell
$env:NESSUS_URL = "https://nessus.lab.example:8834"
$env:NESSUS_ACCESS_KEY = Read-Host "Access key"
$env:NESSUS_SECRET_KEY = Read-Host "Secret key" -MaskInput
```

Bash:

```bash
export NESSUS_URL=https://nessus.lab.example:8834
read -rp "Access key: " NESSUS_ACCESS_KEY; read -rsp "Secret key: " NESSUS_SECRET_KEY; echo; export NESSUS_ACCESS_KEY NESSUS_SECRET_KEY
```

### TLS and certificate trust

Certificate validation is **on by default** and uses the operating system's trust store and hostname checks. Nessus usually ships with a self-signed certificate. There are two ways to handle that:

1. **Recommended: trust the lab CA explicitly.** Export the CA that signed the Nessus server certificate, or the server's self-signed certificate, as PEM or DER and pass `--ca-cert lab-ca.pem`. In this mode the chain must build to one of the supplied certificates, the OS store is not consulted, and the hostname must still match the certificate. Where Nessus keeps its CA depends on the version and platform, so check Tenable's documentation on custom SSL certificates. Replacing the default certificate with one from your lab CA is the cleaner option.
2. **Last resort: `--insecure-skip-tls-verify`.** This disables validation for that one client's handler only. It logs a prominent warning when the client is created and again at the end of the run. It cannot be combined with `--ca-cert`. Nothing in the code sets `ServicePointManager.ServerCertificateValidationCallback` or any other process-wide hook, and a test asserts this.

`http://` URLs, URLs with embedded credentials and URLs with query strings are rejected. HTTP redirects are not followed, so authentication headers are never replayed to another location.

### Scope and targets

Every `scan` and `validate` run needs both:

- `--scope` (repeatable) and/or `--scope-file`: the ranges and hostnames you are authorised to scan. In a scope file, `#` starts a comment.
- `--target` (repeatable): what to scan in this run. Each target must fall inside the scope.

Accepted target forms are a single IPv4/IPv6 address, a CIDR block written with its network address (`192.0.2.16/28`, not `192.0.2.20/28`), or a DNS hostname. Hostnames cannot be resolved offline, so a hostname target must appear verbatim in the scope. Ranges (`a-b`), wildcards, URLs, comma or space separated lists, `/0`, the unspecified address, broadcast and multicast addresses are all rejected. Targets are de-duplicated, and their combined size is capped by `--max-addresses` (default 256). `scan` also refuses to launch without `--confirm-authorized`.

### All scan options

| Option | Default | Meaning |
|---|---|---|
| `--url` | `NESSUS_URL` | Nessus base URL (HTTPS) |
| `--name` | required | Scan name |
| `--template <name\|uuid>` / `--policy-id <id>` | one required | Tenable template, or saved policy |
| `--description`, `--folder-id` | none | Optional scan settings |
| `--output <prefix>` | required | Writes `<prefix>.findings.json` and `.csv`. The directory must exist. Existing files are kept unless `--overwrite` is given. |
| `--poll-interval` | `30s` | Time between status polls |
| `--timeout` | `4h` | Overall deadline after launch |
| `--request-timeout` | `60s` | Per-HTTP-request timeout |
| `--retries` | `3` | Attempts for retry-safe requests |
| `--max-poll-failures` | `5` | Consecutive transient poll failures tolerated |
| `--wait-while-paused` | off | Keep waiting through `paused` instead of exiting 7 |
| `--stop-on-abort` | off | Send `POST /scans/{id}/stop` on deadline or Ctrl+C |
| `--min-severity` | `info` | `info`, `low`, `medium`, `high` or `critical` |
| `--skip-plugin-details` | off | Skip the per-plugin solution/CVE lookups |
| `--ca-cert`, `--insecure-skip-tls-verify` | off | See TLS above |

Durations accept `500ms`, `30s`, `15m`, `4h` or a bare number of seconds.

## Usage

```bash
# 1. Check the plan offline.
nessus-auto validate --scope 192.0.2.0/24 --target 192.0.2.10 --name "Lab baseline" --template basic --output out/lab-baseline

# 2. See what is available on the server.
nessus-auto templates --ca-cert lab-ca.pem
nessus-auto policies  --ca-cert lab-ca.pem

# 3. Print the exact create request without creating anything.
nessus-auto scan --scope 192.0.2.0/24 --target 192.0.2.10 --name "Lab baseline" --template basic --output out/lab-baseline --ca-cert lab-ca.pem --dry-run

# 4. Launch, monitor and export (only for authorised targets).
nessus-auto scan --scope 192.0.2.0/24 --target 192.0.2.10 --name "Lab baseline" --template basic --output out/lab-baseline --ca-cert lab-ca.pem --timeout 2h --stop-on-abort --confirm-authorized

# 5. Re-export an existing completed scan.
nessus-auto results --scan-id 42 --output out/scan-42 --min-severity medium --ca-cert lab-ca.pem
```

### Example output (fixture, not a real scan)

The output below was produced by running the CLI against the test suite's **fake Nessus server**. The addresses (RFC 5737 `192.0.2.0/24`), hostnames (`.test`), plugin 201000 and the CVE IDs are fixture data. Timestamps and paths are trimmed.

```text
$ nessus-auto scan --target 192.0.2.10 --target web01.lab.test --scope 192.0.2.0/24 --scope web01.lab.test \
    --name "Lab baseline" --template basic --output out/lab --poll-interval 10ms --confirm-authorized
[INFO] Authentication: using API keys (X-ApiKeys); no session will be created.
[INFO] Using template 'basic' (Basic Network Scan, uuid 731a8e52-…).
[INFO] Authorised targets (2): 192.0.2.10,web01.lab.test
[INFO] Created scan 42 'Lab baseline'.
[INFO] Launched scan 42 (run run-3c5f0b8e-…). Polling every 0.01s, deadline 4h.
[INFO] Scan 42 status: pending
[INFO] Scan 42 status: running
[INFO] Scan 42 status: completed

== Scan summary ==
Scan ID:   42 (history 7) run run-3c5f0b8e-0000-4000-8000-000000000001
Status:    completed
Hosts:     2
Findings:  4 (Critical 1, High 0, Medium 2, Low 0, Info 1); minimum severity Info
High/critical findings (first 10):
  [Critical] 192.0.2.10 plugin 201000: Example Remote Code Execution
JSON:      …/out/lab.findings.json
CSV:       …/out/lab.findings.csv
```

Fixture CSV (first rows). The text fields show both CSV quoting and formula neutralisation:

```text
finding_key,scan_id,history_id,host_id,host,host_ip,host_fqdn,plugin_id,plugin_name,plugin_family,severity,severity_label,count,risk_factor,cvss3_base_score,cvss_base_score,cves,synopsis,solution
192.0.2.10|201000,42,7,1,192.0.2.10,192.0.2.10,db01.lab.test,201000,Example Remote Code Execution,Misc.,4,Critical,1,Critical,9.8,,CVE-2099-0001;CVE-2099-0002,"'=HYPERLINK(""http://attacker.example"")","Upgrade to version 2.0, ""patched"",
then restart."
web01.lab.test|57582,42,7,2,web01.lab.test,192.0.2.20,,57582,SSL Self-Signed Certificate,General,2,Medium,2,Medium,6.5,,,The SSL certificate chain ends in an unrecognized self-signed certificate.,Purchase or generate a proper SSL certificate for this service.
```

Fixture JSON (abridged):

```json
{
  "schema": "nessus-scan-automation/findings/v1",
  "retrieval_status": "succeeded",
  "scan": { "scan_id": 42, "history_id": 7, "scan_uuid": "run-3c5f0b8e-…", "status": "completed", "server": "nessus.lab.test:8834", "targets": ["192.0.2.10", "web01.lab.test"] },
  "host_count": 2,
  "finding_count": 4,
  "severity_counts": { "critical": 1, "high": 0, "medium": 2, "low": 0, "info": 1 },
  "warnings": [],
  "findings": [
    { "finding_key": "192.0.2.10|201000", "host_id": 1, "host": "192.0.2.10", "plugin_id": 201000, "severity": 4, "severity_label": "Critical",
      "risk_factor": "Critical", "cvss3_base_score": "9.8", "cves": ["CVE-2099-0001", "CVE-2099-0002"], "solution": "Upgrade to version 2.0, …" }
  ]
}
```

## Results and exports

- `finding_key` (`host|plugin_id`, with the host lower-cased) stays the same across scans, so successive exports can be diffed. `scan_id`, `history_id` and `host_id` identify the exact Nessus records.
- **Empty is not the same as failed.** A written export always has `"retrieval_status": "succeeded"`. Zero findings means Nessus reported nothing at or above `--min-severity`. If any retrieval call fails, no export file is written and the exit code is non-zero. If Nessus omits the `hosts` array, the export records a warning instead of silently reporting zero hosts.
- Each file is written to a temporary file and renamed, so a failure never leaves a partial export.
- CSV follows RFC 4180 (CRLF line endings, with quoting for commas, quotes, newlines and edge spaces). Plugin text can echo content from scanned hosts, so text cells that start with `= + - @`, a tab or CR get an apostrophe prefix to stop spreadsheet formula injection. Numeric columns are not modified. JSON keeps the original text.
- Plugin details are fetched once per unique plugin ID, using the first host that reported it. `--skip-plugin-details` turns those lookups off.

## Error handling, retries and timeouts

| Situation | Behaviour |
|---|---|
| Per-request timeout | Each attempt is cancelled after `--request-timeout`. A timeout is reported separately from a Ctrl+C cancellation. |
| Retry-safe requests (all `GET`s, login) | Up to `--retries` attempts on connection errors, timeouts, 408, 429, 502, 503 and 504, with exponential back-off and jitter. `Retry-After` is honoured, capped at 15 s. |
| Not retried | 4xx (other than 408/429), 500, malformed JSON, missing required fields, TLS failures (the message suggests `--ca-cert`). |
| `POST /scans`, `/launch`, `/stop` | **Exactly one attempt.** A timeout, 5xx or dropped connection after the request was sent is marked *outcome unknown*. The tool stops with exit code 8, so a blind re-run cannot create or launch a duplicate. A launch failure reports the ID of the scan that was already created. |
| Polling | Bounded by `--timeout`. Up to `--max-poll-failures` consecutive transient failures are tolerated. Unknown statuses are logged once and polling continues until the deadline. |
| Terminal states | `completed` → collect. `aborted`, `canceled`, `stopped` and `imported` → exit 5. `paused` → exit 7 unless `--wait-while-paused`. In-progress states: `empty`, `pending`, `initializing`, `running`, `processing`, `publishing`, `resuming`, `pausing`, `stopping`. |
| Deadline or Ctrl+C | Monitoring stops. The scan keeps running on the server unless `--stop-on-abort` is set. The password session is still closed. A second Ctrl+C forces exit. |
| Redaction | Passwords, API keys and session tokens are registered with a redactor as soon as they are read. Every log line, error message and export warning passes through it, along with pattern rules for `token=`, `accessKey=`/`secretKey=`, JSON `"password"`/`"token"` fields and `Authorization:` headers. Request bodies and auth headers are never logged. |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success (exports written, possibly with zero findings) |
| 1 | Unexpected error, including file-system errors |
| 2 | Usage or configuration error (nothing was sent to Nessus) |
| 3 | Authentication or authorisation failure |
| 4 | API error: HTTP status, malformed JSON, missing fields, transport or timeout |
| 5 | Scan ended unsuccessfully (`aborted`, `canceled`, `stopped`), or `results` was run on a scan that is not completed |
| 6 | Deadline exceeded |
| 7 | Scan paused |
| 8 | Create/launch outcome unknown: check Nessus before retrying |
| 130 | Cancelled (Ctrl+C) |

## Tests

The suite covers:

- Authentication: success and failure, missing token, API-key header format, and exactly one logout.
- The exact create payload for both template and policy selection.
- Launch and status transitions, including tracking the launched run rather than an older history entry.
- Terminal states: aborted, canceled, stopped, paused (with and without waiting), unknown statuses, the deadline, and cancellation with and without stop.
- Errors: HTTP errors, malformed JSON, missing required fields, request timeouts, transport and TLS failures.
- Retries: transient GET retries, the attempt cap, and single-attempt create/launch with outcome-unknown marking.
- Validation of targets and scope, URLs, credentials, durations and options.
- JSON/CSV export correctness, RFC 4180 escaping, formula neutralisation and atomic writes.
- Redaction of secrets in logs, errors and exports.
- TLS: secure defaults, handler-scoped insecure mode, and custom-root trust using generated test certificates.
- End-to-end CLI runs, including exit codes.

Fixture data uses only documentation addresses (RFC 5737) and reserved `.test`/`.example` names.

## Limitations

- **Not verified against live Nessus.** All behaviour is tested against a fake server built from Tenable's published request and response shapes. See [docs/lab-verification.md](docs/lab-verification.md) for an optional manual check in an authorised lab.
- Password sessions are not refreshed. A scan that outlives the Nessus session timeout fails its next poll with exit code 3. API keys avoid this.
- Findings come from the per-host JSON endpoints, not Nessus's native `.nessus`/CSV export. Large scans make one request per host plus one per unique plugin.
- Plugin output text, ports and compliance results are not exported.
- Only `name`, `description`, `text_targets`, `enabled`, `policy_id` and `folder_id` are set at creation. Credentials, plugin selection and other settings must come from the chosen template or saved policy.
- Hostname targets are matched against the scope as written. The tool cannot tell whether a hostname resolves into an authorised range.
- The tool never deletes scans.

## Responsible use

Scan only systems you own or have written permission to test. `--confirm-authorized` records your intent; it does not establish authorisation.
