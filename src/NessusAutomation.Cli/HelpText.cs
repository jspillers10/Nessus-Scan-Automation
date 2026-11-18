namespace NessusAutomation.Cli;

internal static class HelpText
{
    public const string Text = """
        nessus-auto: create, launch, monitor and export a Nessus scan for an explicitly authorised scope.

        USAGE
          nessus-auto <command> [options]

        COMMANDS
          validate    Check scan options offline (no network, no credentials needed).
          templates   List scan templates (GET /editor/scan/templates).
          policies    List saved policies (GET /policies).
          scan        Create, launch and monitor a scan, then export findings. Requires --confirm-authorized.
          results     Export findings from an existing completed scan.
          help        Show this text.

        CONNECTION (templates, policies, scan, results)
          --url <https://host:8834>     Nessus base URL (or NESSUS_URL). HTTPS only.
          --ca-cert <file>              Trust this PEM/DER CA or self-signed certificate (hostname still checked).
          --insecure-skip-tls-verify    Disable certificate verification for this run only. Lab use; prints warnings.
          --request-timeout <dur>       Per-request timeout (default 60s).
          --retries <n>                 Attempts for retry-safe requests (default 3). Create/launch/stop are never retried.

        CREDENTIALS (environment variables only; never command-line arguments)
          NESSUS_ACCESS_KEY + NESSUS_SECRET_KEY    API keys, sent as X-ApiKeys.
          NESSUS_USERNAME + NESSUS_PASSWORD        Session login; the session is closed on exit.

        SCAN / VALIDATE
          --target <ip|cidr|hostname>   Repeatable. Each target must be inside the authorised scope.
          --scope <ip|cidr|hostname>    Repeatable authorised scope entry.
          --scope-file <file>           One scope entry per line; '#' starts a comment.
          --max-addresses <n>           Upper bound on addresses covered by targets (default 256).
          --name <text>                 Scan name (required).
          --description <text>
          --template <name|uuid>        Tenable scan template, e.g. basic.   } exactly one
          --policy-id <id>              Saved policy ID.                     }
          --folder-id <id>              Optional Nessus folder.
          --output <prefix>             Writes <prefix>.findings.json and <prefix>.findings.csv (required).
          --overwrite                   Replace existing export files.
          --poll-interval <dur>         Status poll interval (default 30s).
          --timeout <dur>               Overall deadline after launch (default 4h).
          --max-poll-failures <n>       Consecutive transient poll failures tolerated (default 5).
          --wait-while-paused           Keep waiting if the scan is paused (default: stop monitoring, exit 7).
          --stop-on-abort               Send a stop request if the deadline passes or Ctrl+C is pressed.
          --skip-plugin-details         Skip per-plugin solution/synopsis/CVE lookups.
          --min-severity <level>        info|low|medium|high|critical (default info).
          --dry-run                     Authenticate and resolve the template/policy, print the POST /scans body, create nothing.
          --confirm-authorized          Required to launch: confirms you are authorised to scan every target.

        RESULTS
          --scan-id <id> [--history-id <id>] --output <prefix> [--overwrite] [--min-severity <level>] [--skip-plugin-details]

        DURATIONS
          500ms, 30s, 15m, 4h, or a bare number of seconds.

        EXIT CODES
          0 success   2 usage/configuration   3 authentication   4 API/HTTP/JSON error
          5 scan ended unsuccessfully (aborted/canceled/stopped)   6 deadline exceeded   7 scan paused
          8 create/launch outcome unknown (check Nessus before retrying)   130 cancelled   1 unexpected error

        """;
}
