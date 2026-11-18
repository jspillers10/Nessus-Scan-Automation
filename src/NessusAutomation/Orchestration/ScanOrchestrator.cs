using System.Globalization;
using NessusAutomation.Api;
using NessusAutomation.Configuration;
using NessusAutomation.Export;
using NessusAutomation.Security;

namespace NessusAutomation.Orchestration;

/// <summary>
/// Runs one scan end to end: resolve template/policy → create → launch → poll → collect.
/// Create and launch are issued exactly once; if their outcome is uncertain the run stops
/// and reports the scan ID rather than risking a duplicate scan.
/// </summary>
public sealed class ScanOrchestrator
{
    private readonly NessusClient _client;
    private readonly IAppLog _log;
    private readonly TimeProvider _time;
    private readonly string _serverHost;

    public ScanOrchestrator(NessusClient client, IAppLog log, Uri serverUri, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(serverUri);
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _log = log ?? throw new ArgumentNullException(nameof(log));
        _time = time ?? TimeProvider.System;
        _serverHost = serverUri.Authority;
    }

    /// <summary>
    /// Resolves a template (by name or UUID) or a saved policy (by ID) to the
    /// <c>uuid</c>/<c>settings.policy_id</c> pair sent when creating a scan.
    /// </summary>
    public async Task<ResolvedSelection> ResolveSelectionAsync(ScanSelection selection, CancellationToken cancellationToken)
    {
        switch (selection)
        {
            case ScanSelection.Template t:
            {
                var templates = await _client.GetScanTemplatesAsync(cancellationToken).ConfigureAwait(false);
                var key = t.NameOrUuid.Trim();
                var matches = templates
                    .Where(x => string.Equals(x.Uuid, key, StringComparison.OrdinalIgnoreCase) || string.Equals(x.Name, key, StringComparison.OrdinalIgnoreCase))
                    .ToList();

                if (matches.Count == 0)
                {
                    var available = string.Join(", ", templates.Select(x => x.Name).Order(StringComparer.Ordinal));
                    throw new ScanLifecycleException(ScanStage.ResolveSelection, null,
                        $"No scan template matches '{key}'. Available template names: {(available.Length > 0 ? available : "(none)")}. Run 'nessus-auto templates' to list them.", null);
                }

                if (matches.Count > 1)
                {
                    throw new ScanLifecycleException(ScanStage.ResolveSelection, null,
                        $"'{key}' matches {matches.Count} templates; pass the template UUID instead.", null);
                }

                var template = matches[0];
                if (template.Unsupported)
                {
                    throw new ScanLifecycleException(ScanStage.ResolveSelection, null,
                        $"Template '{template.Name}' is marked unsupported by this Nessus instance (license or product edition).", null);
                }

                return new ResolvedSelection(template.Uuid, null, $"template '{template.Name}' ({template.Title ?? "untitled"}, uuid {template.Uuid})");
            }

            case ScanSelection.Policy p:
            {
                var policies = await _client.GetPoliciesAsync(cancellationToken).ConfigureAwait(false);
                var policy = policies.FirstOrDefault(x => x.Id == p.PolicyId)
                    ?? throw new ScanLifecycleException(ScanStage.ResolveSelection, null,
                        $"No saved policy with ID {p.PolicyId}. Run 'nessus-auto policies' to list saved policies.", null);

                if (string.IsNullOrWhiteSpace(policy.TemplateUuid))
                {
                    throw new NessusApiException(NessusErrorKind.MalformedResponse,
                        $"GET /policies: malformed response: policy {policy.Id} has no template_uuid.", "GET", "/policies");
                }

                return new ResolvedSelection(policy.TemplateUuid, policy.Id, $"saved policy {policy.Id} '{policy.Name}' (template uuid {policy.TemplateUuid})");
            }

            default:
                throw new ArgumentOutOfRangeException(nameof(selection));
        }
    }

    public static CreateScanRequest BuildCreateRequest(ScanJobOptions job, ResolvedSelection selection)
    {
        ArgumentNullException.ThrowIfNull(job);
        ArgumentNullException.ThrowIfNull(selection);
        return new CreateScanRequest(
            selection.TemplateUuid,
            job.Name,
            job.Description,
            string.Join(',', job.Targets.Select(t => t.Value)),
            selection.PolicyId,
            job.FolderId);
    }

    public async Task<ScanRunResult> RunAsync(ScanJobOptions job, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(job);
        job.Validate();

        var selection = await ResolveSelectionAsync(job.Selection, cancellationToken).ConfigureAwait(false);
        var request = BuildCreateRequest(job, selection);
        _log.Info($"Using {selection.Description}.");
        _log.Info($"Authorised targets ({job.Targets.Count}): {request.TextTargets}");

        CreatedScan created;
        try
        {
            created = await _client.CreateScanAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (NessusApiException ex)
        {
            var message = ex.OutcomeUnknown
                ? $"Scan creation outcome is unknown ({ex.Message}). A scan named '{job.Name}' may exist; check Nessus before re-running to avoid a duplicate."
                : $"Scan creation failed: {ex.Message}";
            throw new ScanLifecycleException(ScanStage.Create, null, message, ex);
        }

        _log.Info($"Created scan {created.Id} '{job.Name}'.");

        string? scanUuid;
        try
        {
            scanUuid = await _client.LaunchScanAsync(created.Id, cancellationToken).ConfigureAwait(false);
        }
        catch (NessusApiException ex)
        {
            var message = ex.OutcomeUnknown
                ? $"Launch outcome for scan {created.Id} is unknown ({ex.Message}). Check its status in Nessus before launching it again."
                : $"Scan {created.Id} was created but could not be launched: {ex.Message}";
            throw new ScanLifecycleException(ScanStage.Launch, created.Id, message, ex);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return new ScanRunResult(ScanOutcome.Cancelled, created.Id, null, null, null, null, false,
                $"Cancelled while launching scan {created.Id}; it may or may not have started. Check Nessus.");
        }

        if (scanUuid is null)
        {
            _log.Warn($"Launch response for scan {created.Id} did not include scan_uuid; polling the scan's overall status instead of a specific run.");
        }

        _log.Info($"Launched scan {created.Id}{(scanUuid is null ? string.Empty : $" (run {scanUuid})")}. Polling every {Format(job.Polling.Interval)}, deadline {Format(job.Polling.Deadline)}.");

        var poll = await WaitForCompletionAsync(created.Id, scanUuid, job.Polling, cancellationToken).ConfigureAwait(false);

        var stopRequested = false;
        if (poll.Outcome is ScanOutcome.DeadlineExceeded or ScanOutcome.Cancelled && job.Polling.StopScanOnAbort)
        {
            stopRequested = await TryStopAsync(created.Id).ConfigureAwait(false);
        }

        if (poll.Outcome != ScanOutcome.Completed)
        {
            return new ScanRunResult(poll.Outcome, created.Id, scanUuid, poll.HistoryId, poll.LastStatus, null, stopRequested,
                DescribeUnsuccessful(created.Id, poll, job.Polling, stopRequested));
        }

        var report = await CollectReportAsync(created.Id, poll.HistoryId, scanUuid, job.Name, request.TextTargets.Split(','), selection.Description, job.Results, cancellationToken)
            .ConfigureAwait(false);

        return new ScanRunResult(ScanOutcome.Completed, created.Id, scanUuid, poll.HistoryId, poll.LastStatus, report, false,
            $"Scan {created.Id} completed.");
    }

    /// <summary>
    /// Polls <c>GET /scans/{id}</c> until the run reaches a terminal state, the deadline
    /// passes, or <paramref name="cancellationToken"/> is cancelled.
    /// </summary>
    public async Task<PollResult> WaitForCompletionAsync(int scanId, string? scanUuid, PollingOptions polling, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(polling);
        polling.Validate();

        var deadline = _time.GetUtcNow() + polling.Deadline;
        string? lastStatus = null;
        int? historyId = null;
        var consecutiveFailures = 0;
        var warnedUnknown = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        while (true)
        {
            try
            {
                ScanDetails? details = null;
                try
                {
                    details = await _client.GetScanDetailsAsync(scanId, null, cancellationToken).ConfigureAwait(false);
                    consecutiveFailures = 0;
                }
                catch (NessusApiException ex) when (ex.IsTransient)
                {
                    consecutiveFailures++;
                    if (consecutiveFailures >= polling.MaxConsecutiveFailures)
                    {
                        throw;
                    }

                    _log.Warn($"Polling scan {scanId} failed ({ex.Message}); {consecutiveFailures}/{polling.MaxConsecutiveFailures} consecutive failures tolerated.");
                }

                if (details is not null)
                {
                    var (status, runHistoryId) = ResolveRunStatus(details, scanUuid);
                    historyId = runHistoryId ?? historyId;
                    if (!string.Equals(status, lastStatus, StringComparison.OrdinalIgnoreCase))
                    {
                        _log.Info($"Scan {scanId} status: {status}");
                        lastStatus = status;
                    }

                    switch (ScanStatus.Classify(status))
                    {
                        case ScanStatusCategory.Completed:
                            return new PollResult(ScanOutcome.Completed, status, historyId);
                        case ScanStatusCategory.Failed:
                            return new PollResult(ScanOutcome.Failed, status, historyId);
                        case ScanStatusCategory.Paused when !polling.WaitWhilePaused:
                            return new PollResult(ScanOutcome.Paused, status, historyId);
                        case ScanStatusCategory.Unknown when warnedUnknown.Add(status):
                            _log.Warn($"Scan {scanId} reported unrecognised status '{status}'; continuing to poll until the deadline.");
                            break;
                    }
                }

                var now = _time.GetUtcNow();
                if (now >= deadline)
                {
                    return new PollResult(ScanOutcome.DeadlineExceeded, lastStatus, historyId);
                }

                var remaining = deadline - now;
                await Task.Delay(remaining < polling.Interval ? remaining : polling.Interval, _time, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return new PollResult(ScanOutcome.Cancelled, lastStatus, historyId);
            }
        }
    }

    /// <summary>
    /// Collects per-host findings for a completed run. Any API failure propagates: a
    /// returned report always means retrieval succeeded.
    /// </summary>
    public async Task<ScanReport> CollectReportAsync(
        int scanId,
        int? historyId,
        string? scanUuid,
        string? scanName,
        IReadOnlyList<string>? targets,
        string? selection,
        ResultOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();

        var details = await _client.GetScanDetailsAsync(scanId, historyId, cancellationToken).ConfigureAwait(false);
        var warnings = new List<string>();
        if (!details.HostsFieldPresent)
        {
            warnings.Add("Nessus returned no 'hosts' array for this scan; it is reported as zero hosts. Verify in the Nessus UI if hosts were expected.");
        }

        if (ScanStatus.Classify(details.Status) != ScanStatusCategory.Completed && historyId is null)
        {
            warnings.Add($"Scan status is '{details.Status}', not 'completed'; results may be partial.");
        }

        var findings = new List<Finding>();
        var pluginCache = new Dictionary<int, PluginDetails>();

        foreach (var host in details.Hosts.OrderBy(h => h.HostId))
        {
            var hostDetails = await _client.GetHostDetailsAsync(scanId, host.HostId, historyId, cancellationToken).ConfigureAwait(false);
            foreach (var v in hostDetails.Vulnerabilities.Where(v => v.Severity >= options.MinimumSeverity))
            {
                PluginDetails? plugin = null;
                if (options.IncludePluginDetails && !pluginCache.TryGetValue(v.PluginId, out plugin))
                {
                    plugin = await _client.GetPluginDetailsAsync(scanId, host.HostId, v.PluginId, historyId, cancellationToken).ConfigureAwait(false);
                    pluginCache[v.PluginId] = plugin;
                }

                findings.Add(new Finding(
                    FindingKey: FormattableString.Invariant($"{host.Hostname.ToLowerInvariant()}|{v.PluginId}"),
                    ScanId: scanId,
                    HistoryId: historyId,
                    HostId: host.HostId,
                    Host: host.Hostname,
                    HostIp: hostDetails.HostIp,
                    HostFqdn: hostDetails.HostFqdn,
                    PluginId: v.PluginId,
                    PluginName: v.PluginName,
                    PluginFamily: v.PluginFamily,
                    Severity: v.Severity,
                    SeverityLabel: Severity.Label(v.Severity),
                    Count: v.Count,
                    RiskFactor: plugin?.RiskFactor,
                    Cvss3BaseScore: plugin?.Cvss3BaseScore,
                    CvssBaseScore: plugin?.CvssBaseScore,
                    Cves: plugin?.Cves ?? [],
                    Synopsis: plugin?.Synopsis,
                    Solution: plugin?.Solution));
            }
        }

        var ordered = findings
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.Host, StringComparer.OrdinalIgnoreCase)
            .ThenBy(f => f.PluginId)
            .ToList();

        var metadata = new ScanReportMetadata(
            scanId,
            historyId,
            scanUuid,
            scanName ?? details.Name,
            details.Status,
            _serverHost,
            targets,
            selection,
            _time.GetUtcNow(),
            options.IncludePluginDetails,
            options.MinimumSeverity);

        return new ScanReport(metadata, details.Hosts.Count, ordered, warnings);
    }

    internal static (string Status, int? HistoryId) ResolveRunStatus(ScanDetails details, string? scanUuid)
    {
        if (scanUuid is not null)
        {
            var run = details.History.FirstOrDefault(h => string.Equals(h.Uuid, scanUuid, StringComparison.OrdinalIgnoreCase));
            return run is null
                // The new run may not be listed yet; the scan-level status reflects the latest run.
                ? (details.Status, null)
                : (string.IsNullOrWhiteSpace(run.Status) ? details.Status : run.Status!, run.HistoryId);
        }

        var latest = details.History.MaxBy(h => h.HistoryId);
        return (details.Status, latest?.HistoryId);
    }

    private async Task<bool> TryStopAsync(int scanId)
    {
        try
        {
            // The caller's token may already be cancelled; stopping must still be attempted.
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await _client.StopScanAsync(scanId, cts.Token).ConfigureAwait(false);
            _log.Warn($"Requested stop for scan {scanId}.");
            return true;
        }
        catch (Exception ex) when (ex is NessusApiException or OperationCanceledException)
        {
            _log.Error($"Could not stop scan {scanId}: {ex.Message}. Stop it manually in Nessus.");
            return false;
        }
    }

    private static string DescribeUnsuccessful(int scanId, PollResult poll, PollingOptions polling, bool stopRequested)
    {
        var running = stopRequested
            ? " A stop request was sent."
            : " The scan may still be running on the server; stop it in Nessus if needed (or use --stop-on-abort).";
        return poll.Outcome switch
        {
            ScanOutcome.Failed => $"Scan {scanId} ended with status '{poll.LastStatus}'. No results were exported.",
            ScanOutcome.Paused => $"Scan {scanId} is paused. Resume it in Nessus and run 'nessus-auto results --scan-id {scanId}', or pass --wait-while-paused.",
            ScanOutcome.DeadlineExceeded => $"Scan {scanId} did not finish within {Format(polling.Deadline)} (last status '{poll.LastStatus ?? "unknown"}').{running}",
            ScanOutcome.Cancelled => $"Monitoring of scan {scanId} was cancelled (last status '{poll.LastStatus ?? "unknown"}').{running}",
            _ => $"Scan {scanId}: {poll.Outcome}.",
        };
    }

    private static string Format(TimeSpan value) => value.TotalHours >= 1
        ? value.TotalHours.ToString("0.##", CultureInfo.InvariantCulture) + "h"
        : value.TotalMinutes >= 1
            ? value.TotalMinutes.ToString("0.##", CultureInfo.InvariantCulture) + "m"
            : value.TotalSeconds.ToString("0.###", CultureInfo.InvariantCulture) + "s";
}
