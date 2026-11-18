# Optional verification in an authorised lab

The automated test suite runs entirely against a fake HTTP transport. This procedure is the
**manual** step that confirms the tool against a real Nessus instance. It is optional, it is
not run in CI, and it must only be performed on infrastructure you are authorised to scan.

## Preconditions

- [ ] A Nessus instance you administer, on an isolated lab network, with an edition and licence that permit scan creation through the API.
- [ ] Written authorisation for one target host that you own (ideally a disposable VM on the same isolated network).
- [ ] An API key pair for a dedicated, least-privilege lab account, generated in the Nessus UI.
- [ ] The CA certificate that signed the Nessus server certificate (PEM), or the server's self-signed certificate.
- [ ] A record of the Nessus version under test (Settings → About).

Never use production credentials, shared accounts or targets outside the lab.

## Procedure

Set credentials in the environment (see README → Credentials), then:

```bash
export NESSUS_URL=https://nessus.lab.example:8834
mkdir -p out
```

1. **Offline validation.** Expect exit 0 and the plan printed.

   ```bash
   nessus-auto validate --scope <lab-host-ip> --target <lab-host-ip> --name "lab-verify" --template basic --output out/lab-verify
   ```

2. **TLS.** Expect exit 4 with a TLS hint when no CA is given (unless the certificate is publicly trusted), then exit 0 with `--ca-cert`.

   ```bash
   nessus-auto templates
   nessus-auto templates --ca-cert lab-ca.pem
   ```

   Confirm that `basic` appears and note its UUID.

3. **Read-only API.** Expect exit 0. Record whether `policies` returns `null` or `[]` when there are none.

   ```bash
   nessus-auto policies --ca-cert lab-ca.pem
   ```

4. **Dry run.** Expect exit 0, a printed `POST /scans` body, and **no new scan in the Nessus UI**.

   ```bash
   nessus-auto scan --scope <lab-host-ip> --target <lab-host-ip> --name "lab-verify" --template basic --output out/lab-verify --ca-cert lab-ca.pem --dry-run
   ```

5. **Authentication failure.** Set a wrong secret key and run `templates`. Expect exit 3 and no secret in the output.

6. **Single authorised scan.** Expect status transitions in the log, exit 0, and both export files.

   ```bash
   nessus-auto scan --scope <lab-host-ip> --target <lab-host-ip> --name "lab-verify" --template basic \
     --output out/lab-verify --ca-cert lab-ca.pem --poll-interval 15s --timeout 1h --stop-on-abort --confirm-authorized
   ```

   Check:
   - [ ] Exactly one scan named `lab-verify` was created and launched (Nessus UI).
   - [ ] Its targets in the UI equal `<lab-host-ip>` and nothing else.
   - [ ] `finding_count` in the JSON matches the Nessus UI's vulnerability count for that host at the same minimum severity.
   - [ ] `solution`, `risk_factor`, `cvss3_base_score` and `cves` are populated for a few medium/high findings. Note any field that stays empty, since those keys are parsed only when present.
   - [ ] The CSV opens in a spreadsheet with one row per finding.

7. **Cancellation.** Start step 6 again with a new `--name` and press Ctrl+C once while it reports `running`. Expect exit 130, a stop request in the log (because of `--stop-on-abort`), and the scan shown as stopping or stopped in the UI.

8. **Re-export.** Using the scan ID from step 6, expect exit 0 and the same `finding_count`.

   ```bash
   nessus-auto results --scan-id <id> --output out/lab-verify-reexport --ca-cert lab-ca.pem
   ```

9. **Clean up.** Delete the test scans in the Nessus UI, revoke the lab API keys, and delete `out/` (exports contain vulnerability data).

## Recording results

Record the Nessus version, the date, each step's exit code, and any field-name differences
from the README's API table. File differences as issues rather than editing the fixtures to
match: the fixtures document the request and response shapes the code was written against.
