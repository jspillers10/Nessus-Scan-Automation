using System.Net;
using System.Text.Json;
using NessusAutomation.Api;
using NessusAutomation.Configuration;
using NessusAutomation.Orchestration;
using NessusAutomation.Tests.Fakes;
using static NessusAutomation.Tests.Fakes.FakeNessusServer;

namespace NessusAutomation.Tests;

public class ScanOrchestratorTests
{
    private static async Task<(Harness Harness, ScanOrchestrator Orchestrator)> CreateAsync(FakeNessusServer server)
    {
        var h = new Harness(server);
        await h.AuthenticatedAsync();
        return (h, new ScanOrchestrator(h.Client, h.Log, h.Options.BaseUri));
    }

    [Fact]
    public async Task Template_selection_sends_template_uuid_and_no_policy_id()
    {
        var (h, orchestrator) = await CreateAsync(new FakeNessusServer().HappyPath());
        await using var cleanup = h;

        await orchestrator.RunAsync(Fixtures.Job(new ScanSelection.Template("basic")), CancellationToken.None);

        var create = Assert.Single(h.Server.Requests, r => r is { Method: "POST", Path: "/scans" });
        var body = create.BodyJson;
        Assert.Equal(Fixtures.BasicTemplateUuid, body.GetProperty("uuid").GetString());
        var settings = body.GetProperty("settings");
        Assert.Equal("Fixture lab scan", settings.GetProperty("name").GetString());
        Assert.Equal("Unit-test fixture", settings.GetProperty("description").GetString());
        Assert.Equal("192.0.2.10,192.0.2.16/30", settings.GetProperty("text_targets").GetString());
        Assert.False(settings.GetProperty("enabled").GetBoolean());
        Assert.False(settings.TryGetProperty("policy_id", out _));
        Assert.False(settings.TryGetProperty("launch_now", out _));
    }

    [Fact]
    public async Task Template_can_be_selected_by_uuid()
    {
        var (h, orchestrator) = await CreateAsync(new FakeNessusServer().HappyPath());
        await using var cleanup = h;

        var selection = await orchestrator.ResolveSelectionAsync(new ScanSelection.Template(Fixtures.BasicTemplateUuid.ToUpperInvariant()), CancellationToken.None);
        Assert.Equal(Fixtures.BasicTemplateUuid, selection.TemplateUuid);
        Assert.Null(selection.PolicyId);
    }

    [Fact]
    public async Task Policy_selection_sends_policy_template_uuid_and_policy_id()
    {
        var (h, orchestrator) = await CreateAsync(new FakeNessusServer().HappyPath());
        await using var cleanup = h;

        await orchestrator.RunAsync(Fixtures.Job(new ScanSelection.Policy(15)), CancellationToken.None);

        var body = Assert.Single(h.Server.Requests, r => r is { Method: "POST", Path: "/scans" }).BodyJson;
        Assert.Equal("ad629e16-03b6-8c1d-cef6-ef8c9dd3c658d24bd260ef5f9e66", body.GetProperty("uuid").GetString());
        Assert.Equal(15, body.GetProperty("settings").GetProperty("policy_id").GetInt32());
        Assert.Equal(0, h.Server.Count("GET", "/editor/scan/templates"));
    }

    [Theory]
    [InlineData("does-not-exist", "No scan template matches")]
    [InlineData("pci", "marked unsupported")]
    public async Task Unknown_or_unsupported_template_fails_before_creating_anything(string template, string expected)
    {
        var (h, orchestrator) = await CreateAsync(new FakeNessusServer().HappyPath());
        await using var cleanup = h;

        var ex = await Assert.ThrowsAsync<ScanLifecycleException>(() =>
            orchestrator.RunAsync(Fixtures.Job(new ScanSelection.Template(template)), CancellationToken.None));

        Assert.Equal(ScanStage.ResolveSelection, ex.Stage);
        Assert.Contains(expected, ex.Message, StringComparison.Ordinal);
        Assert.Equal(0, h.Server.Count("POST", "/scans"));
    }

    [Fact]
    public async Task Unknown_policy_fails_before_creating_anything()
    {
        var (h, orchestrator) = await CreateAsync(new FakeNessusServer().HappyPath());
        await using var cleanup = h;

        var ex = await Assert.ThrowsAsync<ScanLifecycleException>(() =>
            orchestrator.RunAsync(Fixtures.Job(new ScanSelection.Policy(999)), CancellationToken.None));
        Assert.Contains("No saved policy with ID 999", ex.Message, StringComparison.Ordinal);
        Assert.Equal(0, h.Server.Count("POST", "/scans"));
    }

    [Fact]
    public async Task Successful_run_launches_once_polls_to_completion_and_collects_findings()
    {
        var (h, orchestrator) = await CreateAsync(new FakeNessusServer().HappyPath("pending", "running", "running", "completed"));
        await using var cleanup = h;

        var result = await orchestrator.RunAsync(Fixtures.Job(), CancellationToken.None);

        Assert.Equal(ScanOutcome.Completed, result.Outcome);
        Assert.Equal(Fixtures.ScanId, result.ScanId);
        Assert.Equal(Fixtures.RunUuid, result.ScanUuid);
        Assert.Equal(Fixtures.HistoryId, result.HistoryId);
        Assert.Equal(1, h.Server.Count("POST", "/scans"));
        Assert.Equal(1, h.Server.Count("POST", "/scans/42/launch"));

        var polls = h.Server.Requests.Where(r => r.Path == "/scans/42" && r.Query.Length == 0).ToList();
        Assert.Equal(4, polls.Count);

        // Result collection is pinned to the run that was launched.
        Assert.All(h.Server.Requests.Where(r => r.Path.StartsWith("/scans/42/hosts", StringComparison.Ordinal)),
            r => Assert.Equal("?history_id=7", r.Query));

        var report = Assert.IsType<NessusAutomation.Export.ScanReport>(result.Report);
        Assert.Equal(2, report.HostCount);
        Assert.Equal(4, report.Findings.Count);
        Assert.Equal("Critical", report.Findings[0].SeverityLabel);
        Assert.Equal("192.0.2.10|201000", report.Findings[0].FindingKey);
        Assert.Equal(["CVE-2099-0001", "CVE-2099-0002"], report.Findings[0].Cves);

        // Plugin details are fetched once per unique plugin, not per host.
        Assert.Equal(1, h.Server.Requests.Count(r => r.Path.EndsWith("/plugins/57582", StringComparison.Ordinal)));
        Assert.Contains("status: running", h.LogText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Polling_follows_the_launched_run_not_an_older_history_entry()
    {
        var server = new FakeNessusServer().HappyPath();
        var polls = 0;
        server.On("GET", "/scans/42", r =>
        {
            if (r.Query.Length > 0)
            {
                return Json(Fixtures.ScanDetailsBody("completed"));
            }

            // Scan-level status says completed (from the older run) while the new run is still running.
            return Json(Fixtures.ScanDetailsBody("completed", historyStatus: ++polls < 3 ? "running" : "completed"));
        });
        var (h, orchestrator) = await CreateAsync(server);
        await using var cleanup = h;

        var result = await orchestrator.RunAsync(Fixtures.Job(), CancellationToken.None);

        Assert.Equal(ScanOutcome.Completed, result.Outcome);
        Assert.Equal(3, polls);
    }

    [Theory]
    [InlineData("aborted")]
    [InlineData("canceled")]
    [InlineData("stopped")]
    public async Task Unsuccessful_terminal_states_end_the_run_without_exporting(string status)
    {
        var (h, orchestrator) = await CreateAsync(new FakeNessusServer().HappyPath("running", status));
        await using var cleanup = h;

        var result = await orchestrator.RunAsync(Fixtures.Job(), CancellationToken.None);

        Assert.Equal(ScanOutcome.Failed, result.Outcome);
        Assert.Equal(status, result.FinalStatus);
        Assert.Null(result.Report);
        Assert.Contains(status, result.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(h.Server.Requests, r => r.Path.Contains("/hosts/", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Paused_scan_ends_monitoring_by_default()
    {
        var (h, orchestrator) = await CreateAsync(new FakeNessusServer().HappyPath("running", "paused"));
        await using var cleanup = h;

        var result = await orchestrator.RunAsync(Fixtures.Job(), CancellationToken.None);

        Assert.Equal(ScanOutcome.Paused, result.Outcome);
        Assert.Contains("nessus-auto results --scan-id 42", result.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Paused_scan_is_awaited_when_requested()
    {
        var (h, orchestrator) = await CreateAsync(new FakeNessusServer().HappyPath("running", "paused", "resuming", "running", "completed"));
        await using var cleanup = h;

        var polling = Fixtures.FastPolling() with { WaitWhilePaused = true };
        var result = await orchestrator.RunAsync(Fixtures.Job(polling: polling), CancellationToken.None);

        Assert.Equal(ScanOutcome.Completed, result.Outcome);
    }

    [Fact]
    public async Task Deadline_is_enforced_and_stop_is_sent_only_when_requested()
    {
        var (h, orchestrator) = await CreateAsync(new FakeNessusServer().HappyPath("running"));
        await using var cleanup = h;

        var withoutStop = await orchestrator.RunAsync(Fixtures.Job(polling: Fixtures.FastPolling(TimeSpan.FromMilliseconds(150))), CancellationToken.None);
        Assert.Equal(ScanOutcome.DeadlineExceeded, withoutStop.Outcome);
        Assert.False(withoutStop.StopRequested);
        Assert.Equal(0, h.Server.Count("POST", "/scans/42/stop"));
        Assert.Contains("may still be running", withoutStop.Message, StringComparison.Ordinal);

        var polling = Fixtures.FastPolling(TimeSpan.FromMilliseconds(150)) with { StopScanOnAbort = true };
        var withStop = await orchestrator.RunAsync(Fixtures.Job(polling: polling), CancellationToken.None);
        Assert.Equal(ScanOutcome.DeadlineExceeded, withStop.Outcome);
        Assert.True(withStop.StopRequested);
        Assert.Equal(1, h.Server.Count("POST", "/scans/42/stop"));
    }

    [Fact]
    public async Task Unknown_status_keeps_polling_but_is_bounded_by_the_deadline()
    {
        var (h, orchestrator) = await CreateAsync(new FakeNessusServer().HappyPath("mystery-state"));
        await using var cleanup = h;

        var result = await orchestrator.RunAsync(Fixtures.Job(polling: Fixtures.FastPolling(TimeSpan.FromMilliseconds(100))), CancellationToken.None);

        Assert.Equal(ScanOutcome.DeadlineExceeded, result.Outcome);
        Assert.Single(h.LogText.Split('\n'), l => l.Contains("unrecognised status 'mystery-state'", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Cancellation_during_polling_returns_cancelled_and_can_stop_the_scan()
    {
        using var cts = new CancellationTokenSource();
        var server = new FakeNessusServer().HappyPath();
        var polls = 0;
        server.On("GET", "/scans/42", _ =>
        {
            if (++polls == 2)
            {
                cts.Cancel();
            }

            return Json(Fixtures.ScanDetailsBody("running"));
        });
        var (h, orchestrator) = await CreateAsync(server);
        await using var cleanup = h;

        var polling = Fixtures.FastPolling() with { StopScanOnAbort = true };
        var result = await orchestrator.RunAsync(Fixtures.Job(polling: polling), cts.Token);

        Assert.Equal(ScanOutcome.Cancelled, result.Outcome);
        Assert.True(result.StopRequested);
        Assert.Equal(1, server.Count("POST", "/scans/42/stop"));
        Assert.Equal(1, server.Count("POST", "/scans/42/launch"));
    }

    [Fact]
    public async Task Transient_poll_failures_are_tolerated_up_to_the_limit()
    {
        var server = new FakeNessusServer().HappyPath();
        server.OnSequence("GET", "/scans/42",
            _ => Status(HttpStatusCode.ServiceUnavailable),
            _ => Status(HttpStatusCode.ServiceUnavailable),
            _ => Status(HttpStatusCode.ServiceUnavailable),
            _ => Status(HttpStatusCode.ServiceUnavailable),
            r => Json(Fixtures.ScanDetailsBody("completed")));
        var h = new Harness(server, Fixtures.Connection(maxAttempts: 1));
        await using var cleanup = h;
        await h.AuthenticatedAsync();
        var orchestrator = new ScanOrchestrator(h.Client, h.Log, h.Options.BaseUri);

        var polling = Fixtures.FastPolling() with { MaxConsecutiveFailures = 5 };
        var result = await orchestrator.WaitForCompletionAsync(42, Fixtures.RunUuid, polling, CancellationToken.None);
        Assert.Equal(ScanOutcome.Completed, result.Outcome);

        var strict = Fixtures.FastPolling() with { MaxConsecutiveFailures = 2 };
        server.On("GET", "/scans/42", _ => Status(HttpStatusCode.ServiceUnavailable));
        var ex = await Assert.ThrowsAsync<NessusApiException>(() => orchestrator.WaitForCompletionAsync(42, Fixtures.RunUuid, strict, CancellationToken.None));
        Assert.Equal(HttpStatusCode.ServiceUnavailable, ex.StatusCode);
    }

    [Fact]
    public async Task Ambiguous_create_failure_is_reported_once_and_never_launched()
    {
        var server = new FakeNessusServer().HappyPath()
            .On("POST", "/scans", _ => Status(HttpStatusCode.GatewayTimeout));
        var (h, orchestrator) = await CreateAsync(server);
        await using var cleanup = h;

        var ex = await Assert.ThrowsAsync<ScanLifecycleException>(() => orchestrator.RunAsync(Fixtures.Job(), CancellationToken.None));

        Assert.Equal(ScanStage.Create, ex.Stage);
        Assert.Contains("may exist", ex.Message, StringComparison.Ordinal);
        Assert.Equal(1, server.Count("POST", "/scans"));
        Assert.DoesNotContain(server.Requests, r => r.Path.EndsWith("/launch", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Launch_failure_reports_the_created_scan_id_without_relaunching()
    {
        var server = new FakeNessusServer().HappyPath()
            .On("POST", "/scans/42/launch", _ => Json("""{"error":"Scanner is busy"}""", HttpStatusCode.Conflict));
        var (h, orchestrator) = await CreateAsync(server);
        await using var cleanup = h;

        var ex = await Assert.ThrowsAsync<ScanLifecycleException>(() => orchestrator.RunAsync(Fixtures.Job(), CancellationToken.None));

        Assert.Equal(ScanStage.Launch, ex.Stage);
        Assert.Equal(42, ex.ScanId);
        Assert.Contains("created but could not be launched", ex.Message, StringComparison.Ordinal);
        Assert.Contains("Scanner is busy", ex.Message, StringComparison.Ordinal);
        Assert.Equal(1, server.Count("POST", "/scans"));
        Assert.Equal(1, server.Count("POST", "/scans/42/launch"));
    }

    [Fact]
    public async Task Launch_without_scan_uuid_falls_back_to_scan_level_status()
    {
        var server = new FakeNessusServer().HappyPath("running", "completed")
            .On("POST", "/scans/42/launch", _ => Json("{}"));
        var (h, orchestrator) = await CreateAsync(server);
        await using var cleanup = h;

        var result = await orchestrator.RunAsync(Fixtures.Job(), CancellationToken.None);

        Assert.Equal(ScanOutcome.Completed, result.Outcome);
        Assert.Null(result.ScanUuid);
        Assert.Contains("did not include scan_uuid", h.LogText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Completed_scan_with_no_hosts_is_an_empty_successful_report()
    {
        var server = new FakeNessusServer().HappyPath("completed");
        server.On("GET", "/scans/42", _ => Json(new
        {
            info = new { status = "completed", name = "empty" },
            hosts = Array.Empty<object>(),
            history = new[] { new { history_id = 7, uuid = Fixtures.RunUuid, status = "completed" } },
        }));
        var (h, orchestrator) = await CreateAsync(server);
        await using var cleanup = h;

        var result = await orchestrator.RunAsync(Fixtures.Job(), CancellationToken.None);

        Assert.Equal(ScanOutcome.Completed, result.Outcome);
        var report = Assert.IsType<NessusAutomation.Export.ScanReport>(result.Report);
        Assert.Empty(report.Findings);
        Assert.Equal(0, report.HostCount);
        Assert.Empty(report.Warnings);
    }

    [Fact]
    public async Task Missing_hosts_field_is_reported_as_a_warning_not_silently_empty()
    {
        var server = new FakeNessusServer().HappyPath("completed");
        server.On("GET", "/scans/42", _ => Json(Fixtures.ScanDetailsBody("completed", includeHosts: false)));
        var (h, orchestrator) = await CreateAsync(server);
        await using var cleanup = h;

        var result = await orchestrator.RunAsync(Fixtures.Job(), CancellationToken.None);

        var report = Assert.IsType<NessusAutomation.Export.ScanReport>(result.Report);
        Assert.Contains(report.Warnings, w => w.Contains("no 'hosts' array", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Host_retrieval_failure_propagates_instead_of_returning_partial_results()
    {
        var server = new FakeNessusServer().HappyPath("completed")
            .On("GET", "/scans/42/hosts/2", _ => Status(HttpStatusCode.InternalServerError));
        var (h, orchestrator) = await CreateAsync(server);
        await using var cleanup = h;

        var ex = await Assert.ThrowsAsync<NessusApiException>(() => orchestrator.RunAsync(Fixtures.Job(), CancellationToken.None));
        Assert.Equal(HttpStatusCode.InternalServerError, ex.StatusCode);
    }

    [Fact]
    public async Task Minimum_severity_and_skipped_plugin_details_reduce_requests()
    {
        var (h, orchestrator) = await CreateAsync(new FakeNessusServer().HappyPath("completed"));
        await using var cleanup = h;

        var job = Fixtures.Job(results: new ResultOptions { MinimumSeverity = 3, IncludePluginDetails = false });
        var result = await orchestrator.RunAsync(job, CancellationToken.None);

        var finding = Assert.Single(result.Report!.Findings);
        Assert.Equal(201000, finding.PluginId);
        Assert.Null(finding.Solution);
        Assert.DoesNotContain(h.Server.Requests, r => r.Path.Contains("/plugins/", StringComparison.Ordinal));
    }

    [Fact]
    public void Status_classification_covers_documented_states()
    {
        Assert.Equal(ScanStatusCategory.Completed, ScanStatus.Classify("completed"));
        foreach (var s in new[] { "aborted", "canceled", "cancelled", "stopped", "imported" })
        {
            Assert.Equal(ScanStatusCategory.Failed, ScanStatus.Classify(s));
        }

        foreach (var s in new[] { "empty", "pending", "initializing", "running", "processing", "publishing", "resuming", "pausing", "stopping" })
        {
            Assert.Equal(ScanStatusCategory.InProgress, ScanStatus.Classify(s));
        }

        Assert.Equal(ScanStatusCategory.Paused, ScanStatus.Classify("PAUSED"));
        Assert.Equal(ScanStatusCategory.Unknown, ScanStatus.Classify("something-new"));
        Assert.Equal(ScanStatusCategory.Unknown, ScanStatus.Classify(null));
    }

    [Fact]
    public void Create_body_matches_documented_shape()
    {
        var body = NessusClient.BuildCreateScanBody(new CreateScanRequest("tmpl-uuid", "Lab", null, "192.0.2.10", 15, 3));
        using var doc = JsonDocument.Parse(body.ToJsonString());
        var root = doc.RootElement;

        Assert.Equal(["uuid", "settings"], root.EnumerateObject().Select(p => p.Name));
        Assert.Equal(["name", "text_targets", "enabled", "policy_id", "folder_id"], root.GetProperty("settings").EnumerateObject().Select(p => p.Name));
    }
}
