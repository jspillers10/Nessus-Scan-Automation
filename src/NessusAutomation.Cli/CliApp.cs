using System.Globalization;
using NessusAutomation.Api;
using NessusAutomation.Configuration;
using NessusAutomation.Export;
using NessusAutomation.Http;
using NessusAutomation.Orchestration;
using NessusAutomation.Security;

namespace NessusAutomation.Cli;

/// <summary>
/// Command dispatcher. All I/O and the HTTP transport are injected so the full CLI can be
/// exercised in tests without a Nessus server.
/// </summary>
internal sealed class CliApp
{
    private readonly TextWriter _stdout;
    private readonly TextWriter _stderr;
    private readonly Func<string, string?> _env;
    private readonly Func<TlsOptions, IAppLog, HttpMessageHandler> _handlerFactory;
    private readonly TimeProvider _time;
    private readonly SecretRedactor _redactor = new();
    private readonly RedactingLog _log;

    public CliApp(
        TextWriter stdout,
        TextWriter stderr,
        Func<string, string?> env,
        Func<TlsOptions, IAppLog, HttpMessageHandler>? handlerFactory = null,
        TimeProvider? time = null)
    {
        _stdout = stdout;
        _stderr = stderr;
        _env = env;
        _handlerFactory = handlerFactory ?? ((tls, log) => NessusHttpHandlerFactory.Create(tls, log));
        _time = time ?? TimeProvider.System;
        _log = new RedactingLog(stderr, _redactor, _time);

        // Register secrets before anything can log or throw.
        foreach (var name in new[] { CredentialSource.PasswordVariable, CredentialSource.AccessKeyVariable, CredentialSource.SecretKeyVariable })
        {
            _redactor.Register(env(name));
        }
    }

    public async Task<int> RunAsync(IReadOnlyList<string> args, CancellationToken cancellationToken)
    {
        try
        {
            var cli = CliArguments.Parse(args);
            if (cli.Command == "help" || cli.Has("help"))
            {
                await _stdout.WriteAsync(HelpText.Text).ConfigureAwait(false);
                return ExitCodes.Success;
            }

            return cli.Command switch
            {
                "validate" => Validate(cli),
                "scan" => await ScanAsync(cli, cancellationToken).ConfigureAwait(false),
                "results" => await ResultsAsync(cli, cancellationToken).ConfigureAwait(false),
                "templates" => await TemplatesAsync(cli, cancellationToken).ConfigureAwait(false),
                "policies" => await PoliciesAsync(cli, cancellationToken).ConfigureAwait(false),
                _ => throw new CliUsageException($"Unknown command '{cli.Command}'."),
            };
        }
        catch (CliUsageException ex)
        {
            _log.Error(ex.Message);
            return ExitCodes.UsageOrConfiguration;
        }
        catch (ConfigurationException ex)
        {
            foreach (var line in ex.Errors.Count > 0 ? ex.Errors : [ex.Message])
            {
                _log.Error(line);
            }

            return ExitCodes.UsageOrConfiguration;
        }
        catch (ScanLifecycleException ex)
        {
            _log.Error(ex.Message);
            return ex.InnerException switch
            {
                NessusApiException { OutcomeUnknown: true } => ExitCodes.OutcomeUnknown,
                NessusApiException { Kind: NessusErrorKind.Authentication } => ExitCodes.AuthenticationFailed,
                NessusApiException => ExitCodes.ApiError,
                _ when ex.Stage == ScanStage.ResolveSelection => ExitCodes.UsageOrConfiguration,
                _ => ExitCodes.ApiError,
            };
        }
        catch (NessusApiException ex)
        {
            _log.Error(ex.Message);
            return ex.Kind == NessusErrorKind.Authentication ? ExitCodes.AuthenticationFailed : ExitCodes.ApiError;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            _log.Error("Cancelled.");
            return ExitCodes.Cancelled;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _log.Error($"File error: {ex.Message}");
            return ExitCodes.UnexpectedError;
        }
#pragma warning disable CA1031 // Top-level boundary: report any failure redacted, without a stack trace.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            _log.Error($"Unexpected error ({ex.GetType().Name}): {ex.Message}");
            return ExitCodes.UnexpectedError;
        }
    }

    private int Validate(CliArguments cli)
    {
        var plan = BuildScanPlan(cli);
        _stdout.WriteLine("Configuration is valid. No network requests were made.");
        WritePlan(plan);
        if (!cli.Has("confirm-authorized"))
        {
            _stdout.WriteLine("Note: 'scan' will also require --confirm-authorized.");
        }

        return ExitCodes.Success;
    }

    private async Task<int> ScanAsync(CliArguments cli, CancellationToken cancellationToken)
    {
        var plan = BuildScanPlan(cli);
        var dryRun = cli.Has("dry-run");
        if (!dryRun && !cli.Has("confirm-authorized"))
        {
            throw new CliUsageException(
                "'scan' creates and launches a real scan. Re-run with --confirm-authorized to confirm you are authorised to scan every listed target, or use --dry-run.");
        }

        var connection = BuildConnection(cli);
        await using var client = CreateClient(connection);
        await client.AuthenticateAsync(cancellationToken).ConfigureAwait(false);
        var orchestrator = new ScanOrchestrator(client, _log, connection.BaseUri, _time);

        if (dryRun)
        {
            var selection = await orchestrator.ResolveSelectionAsync(plan.Job.Selection, cancellationToken).ConfigureAwait(false);
            var body = NessusClient.BuildCreateScanBody(ScanOrchestrator.BuildCreateRequest(plan.Job, selection));
            _stdout.WriteLine($"Dry run: resolved {selection.Description}.");
            _stdout.WriteLine("POST /scans would be sent with this body (no scan was created or launched):");
            _stdout.WriteLine(body.ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
            return ExitCodes.Success;
        }

        var result = await orchestrator.RunAsync(plan.Job, cancellationToken).ConfigureAwait(false);
        if (result.Outcome != ScanOutcome.Completed || result.Report is null)
        {
            _log.Error(result.Message);
            WriteTlsReminder(client);
            return result.Outcome switch
            {
                ScanOutcome.Failed => ExitCodes.ScanFailed,
                ScanOutcome.DeadlineExceeded => ExitCodes.DeadlineExceeded,
                ScanOutcome.Paused => ExitCodes.ScanPaused,
                ScanOutcome.Cancelled => ExitCodes.Cancelled,
                _ => ExitCodes.UnexpectedError,
            };
        }

        ReportWriter.WriteAll(result.Report, plan.Paths, _redactor);
        ConsoleSummary.Write(_stdout, result.Report, plan.Paths, _redactor);
        WriteTlsReminder(client);
        return ExitCodes.Success;
    }

    private async Task<int> ResultsAsync(CliArguments cli, CancellationToken cancellationToken)
    {
        var scanId = cli.Int("scan-id") ?? throw new CliUsageException("--scan-id is required.");
        var historyId = cli.Int("history-id");
        if (scanId <= 0 || historyId is <= 0)
        {
            throw new CliUsageException("--scan-id and --history-id must be positive integers.");
        }

        var results = BuildResultOptions(cli);
        results.Validate();
        var paths = ExportPaths.FromPrefix(cli.Single("output") ?? throw new CliUsageException("--output is required."));
        paths.EnsureWritable(cli.Has("overwrite"));

        var connection = BuildConnection(cli);
        await using var client = CreateClient(connection);
        await client.AuthenticateAsync(cancellationToken).ConfigureAwait(false);
        var orchestrator = new ScanOrchestrator(client, _log, connection.BaseUri, _time);

        var details = await client.GetScanDetailsAsync(scanId, historyId, cancellationToken).ConfigureAwait(false);
        if (ScanStatus.Classify(details.Status) != ScanStatusCategory.Completed)
        {
            _log.Error($"Scan {scanId}{(historyId is null ? string.Empty : $" history {historyId}")} has status '{details.Status}', not 'completed'. Nothing was exported.");
            return details.Status.Equals("paused", StringComparison.OrdinalIgnoreCase) ? ExitCodes.ScanPaused : ExitCodes.ScanFailed;
        }

        var report = await orchestrator.CollectReportAsync(scanId, historyId, null, details.Name, null, null, results, cancellationToken).ConfigureAwait(false);
        ReportWriter.WriteAll(report, paths, _redactor);
        ConsoleSummary.Write(_stdout, report, paths, _redactor);
        WriteTlsReminder(client);
        return ExitCodes.Success;
    }

    private async Task<int> TemplatesAsync(CliArguments cli, CancellationToken cancellationToken)
    {
        await using var client = CreateClient(BuildConnection(cli));
        await client.AuthenticateAsync(cancellationToken).ConfigureAwait(false);
        var templates = await client.GetScanTemplatesAsync(cancellationToken).ConfigureAwait(false);
        _stdout.WriteLine($"{"NAME",-28} {"UNSUPPORTED",-11} {"UUID",-40} TITLE");
        foreach (var t in templates.OrderBy(t => t.Name, StringComparer.Ordinal))
        {
            _stdout.WriteLine($"{t.Name,-28} {(t.Unsupported ? "yes" : "no"),-11} {t.Uuid,-40} {t.Title}");
        }

        _stdout.WriteLine($"{templates.Count} template(s). Use --template <name|uuid> with 'scan'.");
        WriteTlsReminder(client);
        return ExitCodes.Success;
    }

    private async Task<int> PoliciesAsync(CliArguments cli, CancellationToken cancellationToken)
    {
        await using var client = CreateClient(BuildConnection(cli));
        await client.AuthenticateAsync(cancellationToken).ConfigureAwait(false);
        var policies = await client.GetPoliciesAsync(cancellationToken).ConfigureAwait(false);
        _stdout.WriteLine($"{"ID",-8} {"TEMPLATE_UUID",-40} NAME");
        foreach (var p in policies.OrderBy(p => p.Id))
        {
            _stdout.WriteLine($"{p.Id,-8} {p.TemplateUuid ?? "(none)",-40} {p.Name}");
        }

        _stdout.WriteLine($"{policies.Count} saved policy/policies. Use --policy-id <id> with 'scan'.");
        WriteTlsReminder(client);
        return ExitCodes.Success;
    }

    private static ScanPlan BuildScanPlan(CliArguments cli)
    {
        var errors = new List<string>();

        var scopeEntries = new List<string>(cli.All("scope"));
        if (cli.Single("scope-file") is { } scopeFile)
        {
            if (!File.Exists(scopeFile))
            {
                throw new ConfigurationException($"Scope file not found: {scopeFile}");
            }

            scopeEntries.AddRange(File.ReadAllLines(scopeFile)
                .Select(l => l.Split('#', 2)[0].Trim())
                .Where(l => l.Length > 0));
        }

        IReadOnlyList<ScanTarget> targets = [];
        try
        {
            var scope = TargetScopeValidator.ParseScope(scopeEntries);
            targets = TargetScopeValidator.ValidateTargets(cli.All("target"), scope, cli.Int("max-addresses") ?? TargetScopeValidator.DefaultMaxAddresses);
        }
        catch (ConfigurationException ex)
        {
            errors.AddRange(ex.Errors.Count > 0 ? ex.Errors : [ex.Message]);
        }

        var template = cli.Single("template");
        var policyId = cli.Int("policy-id");
        ScanSelection? selection = (template, policyId) switch
        {
            (not null, null) => new ScanSelection.Template(template),
            (null, not null) => new ScanSelection.Policy(policyId.Value),
            (not null, not null) => null,
            _ => null,
        };
        if (selection is null)
        {
            errors.Add(template is not null
                ? "Use either --template or --policy-id, not both."
                : "Choose a scan configuration: --template <name|uuid> (Tenable template) or --policy-id <id> (saved policy).");
        }

        ExportPaths? paths = null;
        try
        {
            paths = ExportPaths.FromPrefix(cli.Single("output") ?? string.Empty);
            paths.EnsureWritable(cli.Has("overwrite"));
        }
        catch (ConfigurationException ex)
        {
            errors.Add(ex.Message);
        }

        var polling = new PollingOptions
        {
            Interval = cli.Duration("poll-interval") ?? TimeSpan.FromSeconds(30),
            Deadline = cli.Duration("timeout") ?? TimeSpan.FromHours(4),
            WaitWhilePaused = cli.Has("wait-while-paused"),
            StopScanOnAbort = cli.Has("stop-on-abort"),
            MaxConsecutiveFailures = cli.Int("max-poll-failures") ?? 5,
        };

        if (errors.Count > 0)
        {
            throw new ConfigurationException(errors);
        }

        var job = new ScanJobOptions
        {
            Name = cli.Single("name") ?? string.Empty,
            Description = cli.Single("description"),
            Selection = selection!,
            Targets = targets,
            FolderId = cli.Int("folder-id"),
            Polling = polling,
            Results = BuildResultOptions(cli),
        };
        job.Validate();
        return new ScanPlan(job, paths!);
    }

    private static ResultOptions BuildResultOptions(CliArguments cli) => new()
    {
        IncludePluginDetails = !cli.Has("skip-plugin-details"),
        MinimumSeverity = cli.Single("min-severity") is { } s ? Severity.Parse(s) : 0,
    };

    private NessusConnectionOptions BuildConnection(CliArguments cli)
    {
        var insecure = cli.Has("insecure-skip-tls-verify");
        var caCert = cli.Single("ca-cert");
        if (insecure && caCert is not null)
        {
            throw new CliUsageException("--ca-cert and --insecure-skip-tls-verify are mutually exclusive; prefer --ca-cert.");
        }

        var retries = cli.Int("retries");
        var options = new NessusConnectionOptions
        {
            BaseUri = NessusConnectionOptions.ParseBaseUri(cli.Single("url") ?? _env(CredentialSource.UrlVariable)),
            Credentials = CredentialSource.Resolve(_env),
            RequestTimeout = cli.Duration("request-timeout") ?? TimeSpan.FromSeconds(60),
            Tls = insecure
                ? new TlsOptions { Mode = TlsValidationMode.InsecureSkipVerify }
                : caCert is not null
                    ? new TlsOptions { Mode = TlsValidationMode.CustomRoot, CaCertificatePath = caCert }
                    : new TlsOptions(),
            Retry = retries is { } r ? new RetryOptions { MaxAttempts = r } : new RetryOptions(),
        };
        options.Validate();
        return options;
    }

    private NessusClient CreateClient(NessusConnectionOptions options) =>
        new(options, _handlerFactory(options.Tls, _log), _redactor, _log, _time);

    private void WritePlan(ScanPlan plan)
    {
        var job = plan.Job;
        _stdout.WriteLine($"  Name:            {job.Name}");
        _stdout.WriteLine($"  Selection:       {job.Selection switch { ScanSelection.Template t => $"template '{t.NameOrUuid}'", ScanSelection.Policy p => $"saved policy {p.PolicyId}", _ => "?" }}");
        _stdout.WriteLine($"  Targets:         {string.Join(", ", job.Targets.Select(t => t.Value))}");
        _stdout.WriteLine($"  Address count:   {job.Targets.Aggregate(System.Numerics.BigInteger.Zero, (sum, t) => sum + t.AddressCount)}");
        _stdout.WriteLine($"  Poll interval:   {job.Polling.Interval}");
        _stdout.WriteLine($"  Scan timeout:    {job.Polling.Deadline}");
        _stdout.WriteLine($"  Exports:         {plan.Paths.JsonPath}");
        _stdout.WriteLine($"                   {plan.Paths.CsvPath}");
    }

    private void WriteTlsReminder(NessusClient client)
    {
        if (client.TlsVerificationDisabled)
        {
            _stderr.WriteLine("WARNING: TLS certificate verification was DISABLED for this run (--insecure-skip-tls-verify).");
        }
    }

    private sealed record ScanPlan(ScanJobOptions Job, ExportPaths Paths);
}

internal static class ConsoleSummary
{
    public static void Write(TextWriter output, ScanReport report, ExportPaths paths, SecretRedactor redactor)
    {
        var m = report.Metadata;
        var counts = string.Join(", ", report.SeverityCounts.Select(kv => $"{kv.Key} {kv.Value}"));
        output.WriteLine();
        output.WriteLine("== Scan summary ==");
        output.WriteLine($"Scan ID:   {m.ScanId}{(m.HistoryId is { } h ? $" (history {h})" : string.Empty)}{(m.ScanUuid is { } u ? $" run {u}" : string.Empty)}");
        output.WriteLine($"Status:    {m.Status}");
        output.WriteLine($"Hosts:     {report.HostCount}");
        if (report.Findings.Count == 0)
        {
            output.WriteLine($"Findings:  0. Retrieval succeeded; Nessus reported no findings at or above {Severity.Label(m.MinimumSeverity)}.");
        }
        else
        {
            output.WriteLine($"Findings:  {report.Findings.Count} ({counts}); minimum severity {Severity.Label(m.MinimumSeverity)}");
        }

        foreach (var warning in report.Warnings)
        {
            output.WriteLine($"Warning:   {redactor.Redact(warning)}");
        }

        var top = report.Findings.Where(f => f.Severity >= 3).Take(10).ToList();
        if (top.Count > 0)
        {
            output.WriteLine("High/critical findings (first 10):");
            foreach (var f in top)
            {
                output.WriteLine(string.Create(CultureInfo.InvariantCulture, $"  [{f.SeverityLabel}] {f.Host} plugin {f.PluginId}: {f.PluginName}"));
            }
        }

        output.WriteLine($"JSON:      {paths.JsonPath}");
        output.WriteLine($"CSV:       {paths.CsvPath}");
    }
}
