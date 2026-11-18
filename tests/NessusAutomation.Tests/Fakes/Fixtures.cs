using System.Net;
using NessusAutomation.Api;
using NessusAutomation.Configuration;
using NessusAutomation.Security;
using static NessusAutomation.Tests.Fakes.FakeNessusServer;

namespace NessusAutomation.Tests.Fakes;

/// <summary>
/// Sanitised fixture data. Addresses come from RFC 5737 documentation ranges
/// (192.0.2.0/24) and names from the reserved .test / .example domains.
/// </summary>
public static class Fixtures
{
    public const string BaseUrl = "https://nessus.lab.test:8834/";
    public const string Username = "lab-auditor";
    public const string Password = "Fixture-Passw0rd!";
    public const string SessionToken = "fixture-session-token-6f1c2a";
    public const string AccessKey = "fixture-access-key-0123456789abcdef";
    public const string SecretKey = "fixture-secret-key-fedcba9876543210";
    public const string BasicTemplateUuid = "731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65";
    public const string RunUuid = "run-3c5f0b8e-0000-4000-8000-000000000001";
    public const int ScanId = 42;
    public const int HistoryId = 7;

    public static NessusConnectionOptions Connection(
        NessusCredentials? credentials = null,
        int maxAttempts = 3,
        TimeSpan? requestTimeout = null) => new()
    {
        BaseUri = new Uri(BaseUrl),
        Credentials = credentials ?? new NessusCredentials.UserPassword(Username, Password),
        RequestTimeout = requestTimeout ?? TimeSpan.FromSeconds(5),
        Retry = new RetryOptions { MaxAttempts = maxAttempts, BaseDelay = TimeSpan.Zero, MaxDelay = TimeSpan.Zero },
    };

    public static IReadOnlyList<ScanTarget> Targets(params string[] targets) =>
        TargetScopeValidator.ValidateTargets(targets, TargetScopeValidator.ParseScope(["192.0.2.0/24", "web01.lab.test"]));

    public static ScanJobOptions Job(ScanSelection? selection = null, PollingOptions? polling = null, ResultOptions? results = null) => new()
    {
        Name = "Fixture lab scan",
        Description = "Unit-test fixture",
        Selection = selection ?? new ScanSelection.Template("basic"),
        Targets = Targets("192.0.2.10", "192.0.2.16/30"),
        Polling = polling ?? FastPolling(),
        Results = results ?? new ResultOptions(),
    };

    public static PollingOptions FastPolling(TimeSpan? deadline = null) => new()
    {
        Interval = TimeSpan.FromMilliseconds(5),
        Deadline = deadline ?? TimeSpan.FromSeconds(10),
        MaxConsecutiveFailures = 3,
    };

    public static object ScanDetailsBody(string status, string? historyStatus = null, bool includeHosts = true, string runUuid = RunUuid) => new
    {
        info = new { status, name = "Fixture lab scan" },
        hosts = includeHosts
            ? new object[]
            {
                new { host_id = 1, hostname = "192.0.2.10" },
                new { host_id = 2, hostname = "web01.lab.test" },
            }
            : null,
        history = new object[]
        {
            new { history_id = 3, uuid = "older-run", status = "completed" },
            new { history_id = HistoryId, uuid = runUuid, status = historyStatus ?? status },
        },
    };

    /// <summary>Registers the endpoints of a complete, successful scan lifecycle.</summary>
    public static FakeNessusServer HappyPath(this FakeNessusServer server, params string[] pollStatuses)
    {
        var statuses = pollStatuses.Length == 0 ? ["pending", "running", "completed"] : pollStatuses;
        server
            .On("POST", "/session", _ => Json(new { token = SessionToken }))
            .On("DELETE", "/session", _ => Status(HttpStatusCode.OK))
            .On("GET", "/editor/scan/templates", _ => Json(new
            {
                templates = new object[]
                {
                    new { uuid = BasicTemplateUuid, name = "basic", title = "Basic Network Scan", unsupported = false },
                    new { uuid = "ad629e16-03b6-8c1d-cef6-ef8c9dd3c658d24bd260ef5f9e66", name = "advanced", title = "Advanced Scan", unsupported = false },
                    new { uuid = "e785c1bd-0000-0000-0000-000000000000", name = "pci", title = "PCI Quarterly", unsupported = true },
                },
            }))
            .On("GET", "/policies", _ => Json(new
            {
                policies = new object[]
                {
                    new { id = 15, name = "Lab hardened baseline", template_uuid = "ad629e16-03b6-8c1d-cef6-ef8c9dd3c658d24bd260ef5f9e66" },
                },
            }))
            .On("POST", "/scans", _ => Json(new { scan = new { id = ScanId, uuid = "template-schedule-uuid", name = "Fixture lab scan" } }))
            .On("POST", $"/scans/{ScanId}/launch", _ => Json(new { scan_uuid = RunUuid }))
            .On("POST", $"/scans/{ScanId}/stop", _ => Status(HttpStatusCode.OK));

        var poll = 0;
        server.On("GET", $"/scans/{ScanId}", r =>
        {
            if (r.Query.Contains("history_id", StringComparison.Ordinal))
            {
                return Json(ScanDetailsBody("completed"));
            }

            var status = statuses[Math.Min(poll++, statuses.Length - 1)];
            return Json(ScanDetailsBody(status));
        });

        server
            .On("GET", $"/scans/{ScanId}/hosts/1", _ => Json(new
            {
                info = new Dictionary<string, object> { ["host-ip"] = "192.0.2.10", ["host-fqdn"] = "db01.lab.test" },
                vulnerabilities = new object[]
                {
                    new { plugin_id = 57582, plugin_name = "SSL Self-Signed Certificate", plugin_family = "General", severity = 2, count = 1 },
                    new { plugin_id = 19506, plugin_name = "Nessus Scan Information", plugin_family = "Settings", severity = 0, count = 1 },
                    new { plugin_id = 201000, plugin_name = "Example Remote Code Execution", plugin_family = "Misc.", severity = 4, count = 1 },
                },
            }))
            .On("GET", $"/scans/{ScanId}/hosts/2", _ => Json(new
            {
                info = new Dictionary<string, object> { ["host-ip"] = "192.0.2.20" },
                vulnerabilities = new object[]
                {
                    new { plugin_id = 57582, plugin_name = "SSL Self-Signed Certificate", plugin_family = "General", severity = 2, count = 2 },
                },
            }))
            .On("GET", $"/scans/{ScanId}/hosts/1/plugins/57582", _ => Json(PluginBody("The SSL certificate chain ends in an unrecognized self-signed certificate.", "Purchase or generate a proper SSL certificate for this service.", "Medium", "6.5", [])))
            .On("GET", $"/scans/{ScanId}/hosts/1/plugins/19506", _ => Json(PluginBody("Information about this scan.", null, "None", null, [])))
            .On("GET", $"/scans/{ScanId}/hosts/1/plugins/201000", _ => Json(PluginBody("=HYPERLINK(\"http://attacker.example\")", "Upgrade to version 2.0, \"patched\",\nthen restart.", "Critical", "9.8", ["CVE-2099-0001", "CVE-2099-0002"])));

        return server;
    }

    public static object PluginBody(string synopsis, string? solution, string riskFactor, string? cvss3, string[] cves) => new
    {
        info = new
        {
            plugindescription = new
            {
                pluginid = "0",
                pluginattributes = new
                {
                    synopsis,
                    solution,
                    risk_information = new { risk_factor = riskFactor, cvss3_base_score = cvss3 },
                    ref_information = new
                    {
                        @ref = new object[] { new { name = "cve", values = new { value = cves } } },
                    },
                },
            },
        },
    };
}

/// <summary>Builds a client against a fake server and captures redacted log output.</summary>
public sealed class Harness : IAsyncDisposable
{
    public Harness(FakeNessusServer? server = null, NessusConnectionOptions? options = null)
    {
        Server = server ?? new FakeNessusServer();
        Options = options ?? Fixtures.Connection();
        Log = new RedactingLog(LogWriter, Redactor);
        Client = new NessusClient(Options, Server, Redactor, Log);
    }

    public FakeNessusServer Server { get; }

    public NessusConnectionOptions Options { get; }

    public SecretRedactor Redactor { get; } = new();

    public StringWriter LogWriter { get; } = new();

    public IAppLog Log { get; }

    public NessusClient Client { get; }

    public string LogText => LogWriter.ToString();

    public async Task<NessusClient> AuthenticatedAsync()
    {
        await Client.AuthenticateAsync(CancellationToken.None);
        return Client;
    }

    public ValueTask DisposeAsync() => Client.DisposeAsync();
}
