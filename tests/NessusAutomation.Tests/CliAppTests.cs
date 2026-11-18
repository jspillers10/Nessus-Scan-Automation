using System.Net;
using System.Text.Json;
using NessusAutomation.Cli;
using NessusAutomation.Configuration;
using NessusAutomation.Tests.Fakes;
using static NessusAutomation.Tests.Fakes.FakeNessusServer;

namespace NessusAutomation.Tests;

public sealed class CliAppTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("nessus-cli-tests").FullName;
    private readonly StringWriter _stdout = new();
    private readonly StringWriter _stderr = new();
    private readonly List<TlsOptions> _tlsRequested = [];

    private Dictionary<string, string?> Env { get; } = new()
    {
        ["NESSUS_URL"] = Fixtures.BaseUrl,
        ["NESSUS_USERNAME"] = Fixtures.Username,
        ["NESSUS_PASSWORD"] = Fixtures.Password,
    };

    public void Dispose()
    {
        _stdout.Dispose();
        _stderr.Dispose();
        Directory.Delete(_dir, recursive: true);
    }

    private string Prefix => Path.Combine(_dir, "lab");

    private string[] ScanArgs(params string[] extra) =>
    [
        "scan", "--target", "192.0.2.10", "--target", "web01.lab.test", "--scope", "192.0.2.0/24", "--scope", "web01.lab.test",
        "--name", "Fixture lab scan", "--template", "basic", "--output", Prefix, "--poll-interval", "5ms", "--timeout", "10s",
        .. extra,
    ];

    private async Task<int> RunAsync(FakeNessusServer server, params string[] args)
    {
        var app = new CliApp(_stdout, _stderr, name => Env.GetValueOrDefault(name), (tls, _) =>
        {
            _tlsRequested.Add(tls);
            return server;
        });
        return await app.RunAsync(args, CancellationToken.None);
    }

    [Fact]
    public async Task Help_prints_usage()
    {
        Assert.Equal(0, await RunAsync(new FakeNessusServer(), "help"));
        Assert.Contains("--confirm-authorized", _stdout.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Scan_requires_explicit_confirmation_and_makes_no_requests_without_it()
    {
        var server = new FakeNessusServer().HappyPath();
        Assert.Equal(2, await RunAsync(server, ScanArgs()));
        Assert.Empty(server.Requests);
        Assert.Contains("--confirm-authorized", _stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Dry_run_prints_payload_and_creates_nothing()
    {
        var server = new FakeNessusServer().HappyPath();
        Assert.Equal(0, await RunAsync(server, ScanArgs("--dry-run")));

        Assert.Equal(0, server.Count("POST", "/scans"));
        Assert.Equal(1, server.Count("DELETE", "/session"));
        var output = _stdout.ToString();
        Assert.Contains(Fixtures.BasicTemplateUuid, output, StringComparison.Ordinal);
        Assert.Contains("\"text_targets\": \"192.0.2.10,web01.lab.test\"", output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Full_scan_exports_json_and_csv_and_logs_out()
    {
        var server = new FakeNessusServer().HappyPath();
        Assert.Equal(0, await RunAsync(server, ScanArgs("--confirm-authorized")));

        var json = File.ReadAllText(Prefix + ".findings.json");
        using var doc = JsonDocument.Parse(json);
        Assert.Equal(4, doc.RootElement.GetProperty("finding_count").GetInt32());
        Assert.True(File.Exists(Prefix + ".findings.csv"));
        Assert.Equal(1, server.Count("DELETE", "/session"));

        var stdout = _stdout.ToString();
        Assert.Contains("Findings:  4", stdout, StringComparison.Ordinal);
        Assert.Contains("[Critical] 192.0.2.10 plugin 201000", stdout, StringComparison.Ordinal);
        Assert.DoesNotContain(Fixtures.Password, _stderr.ToString() + stdout + json, StringComparison.Ordinal);
        Assert.DoesNotContain(Fixtures.SessionToken, _stderr.ToString() + stdout + json, StringComparison.Ordinal);
        Assert.Equal(TlsValidationMode.System, Assert.Single(_tlsRequested).Mode);
    }

    [Fact]
    public async Task Existing_exports_are_not_overwritten_without_flag()
    {
        File.WriteAllText(Prefix + ".findings.json", "{}");
        var server = new FakeNessusServer().HappyPath();
        Assert.Equal(2, await RunAsync(server, ScanArgs("--confirm-authorized")));
        Assert.Empty(server.Requests);
    }

    [Fact]
    public async Task Out_of_scope_target_is_rejected_before_any_request()
    {
        var server = new FakeNessusServer().HappyPath();
        var args = ScanArgs("--confirm-authorized", "--target", "198.51.100.1");
        Assert.Equal(2, await RunAsync(server, args));
        Assert.Empty(server.Requests);
        Assert.Contains("198.51.100.1' is outside the authorised scope", _stderr.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("aborted", 5)]
    [InlineData("canceled", 5)]
    [InlineData("paused", 7)]
    public async Task Unsuccessful_scans_map_to_exit_codes_and_write_no_exports(string status, int exitCode)
    {
        var server = new FakeNessusServer().HappyPath("running", status);
        Assert.Equal(exitCode, await RunAsync(server, ScanArgs("--confirm-authorized")));
        Assert.False(File.Exists(Prefix + ".findings.json"));
        Assert.False(File.Exists(Prefix + ".findings.csv"));
    }

    [Fact]
    public async Task Deadline_maps_to_exit_code_6()
    {
        var server = new FakeNessusServer().HappyPath("running");
        var args = ScanArgs("--confirm-authorized").Select(a => a == "10s" ? "100ms" : a).ToArray();
        Assert.Equal(6, await RunAsync(server, args));
        Assert.Contains("did not finish", _stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Authentication_failure_maps_to_exit_code_3_and_hides_password()
    {
        var server = new FakeNessusServer()
            .On("POST", "/session", _ => Json($$"""{"error":"bad password {{Fixtures.Password}}"}""", HttpStatusCode.Unauthorized));
        Assert.Equal(3, await RunAsync(server, "templates"));
        Assert.DoesNotContain(Fixtures.Password, _stderr.ToString(), StringComparison.Ordinal);
        Assert.Contains("Authentication failed", _stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Ambiguous_create_maps_to_exit_code_8()
    {
        var server = new FakeNessusServer().HappyPath().On("POST", "/scans", _ => Status(HttpStatusCode.BadGateway));
        Assert.Equal(8, await RunAsync(server, ScanArgs("--confirm-authorized")));
        Assert.Equal(1, server.Count("POST", "/scans"));
        Assert.Contains("check Nessus before re-running", _stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Malformed_response_maps_to_exit_code_4()
    {
        var server = new FakeNessusServer().HappyPath().On("GET", "/editor/scan/templates", _ => Json("{\"templates\": 5}"));
        Assert.Equal(4, await RunAsync(server, "templates"));
        Assert.Contains("malformed response", _stderr.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("--password")]
    [InlineData("--secret-key=abc")]
    [InlineData("--access-key")]
    [InlineData("--token")]
    public async Task Secrets_on_the_command_line_are_refused(string option)
    {
        var server = new FakeNessusServer().HappyPath();
        Assert.Equal(2, await RunAsync(server, "templates", option, "value"));
        Assert.Contains("secrets must not be passed on the command line", _stderr.ToString(), StringComparison.Ordinal);
        Assert.Empty(server.Requests);
    }

    [Fact]
    public async Task Api_key_environment_variables_are_used_when_set()
    {
        Env.Remove("NESSUS_USERNAME");
        Env.Remove("NESSUS_PASSWORD");
        Env["NESSUS_ACCESS_KEY"] = Fixtures.AccessKey;
        Env["NESSUS_SECRET_KEY"] = Fixtures.SecretKey;
        var server = new FakeNessusServer().HappyPath();

        Assert.Equal(0, await RunAsync(server, "policies"));
        Assert.Contains("Lab hardened baseline", _stdout.ToString(), StringComparison.Ordinal);
        Assert.Equal(0, server.Count("POST", "/session"));
        Assert.DoesNotContain(Fixtures.SecretKey, _stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Ambiguous_or_missing_credentials_are_configuration_errors()
    {
        Env["NESSUS_ACCESS_KEY"] = Fixtures.AccessKey;
        Env["NESSUS_SECRET_KEY"] = Fixtures.SecretKey;
        Assert.Equal(2, await RunAsync(new FakeNessusServer(), "templates"));
        Assert.Contains("unset one pair", _stderr.ToString(), StringComparison.Ordinal);

        Env.Clear();
        Env["NESSUS_URL"] = Fixtures.BaseUrl;
        Assert.Equal(2, await RunAsync(new FakeNessusServer(), "templates"));
        Assert.Contains("No Nessus credentials found", _stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Insecure_flag_is_explicit_reported_and_exclusive_with_ca_cert()
    {
        var server = new FakeNessusServer().HappyPath();
        Assert.Equal(0, await RunAsync(server, "templates", "--insecure-skip-tls-verify"));
        Assert.Equal(TlsValidationMode.InsecureSkipVerify, Assert.Single(_tlsRequested).Mode);
        Assert.Contains("TLS certificate verification was DISABLED", _stderr.ToString(), StringComparison.Ordinal);

        Assert.Equal(2, await RunAsync(server, "templates", "--insecure-skip-tls-verify", "--ca-cert", "lab.pem"));
    }

    [Fact]
    public async Task Http_url_is_rejected()
    {
        Assert.Equal(2, await RunAsync(new FakeNessusServer(), "templates", "--url", "http://nessus.lab.test:8834"));
        Assert.Contains("must use https://", _stderr.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Validate_is_offline_and_needs_no_credentials()
    {
        Env.Clear();
        Assert.Equal(0, await RunAsync(new FakeNessusServer(), [.. ScanArgs().Skip(1).Prepend("validate")]));
        Assert.Empty(_tlsRequested);
        Assert.Contains("No network requests were made", _stdout.ToString(), StringComparison.Ordinal);
        Assert.Contains("Address count:   2", _stdout.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Results_command_exports_a_completed_scan()
    {
        var server = new FakeNessusServer().HappyPath();
        Assert.Equal(0, await RunAsync(server, "results", "--scan-id", "42", "--history-id", "7", "--output", Prefix, "--min-severity", "medium"));

        using var doc = JsonDocument.Parse(File.ReadAllText(Prefix + ".findings.json"));
        Assert.Equal(3, doc.RootElement.GetProperty("finding_count").GetInt32());
        Assert.Equal(0, server.Count("POST", "/scans"));
    }

    [Fact]
    public async Task Results_command_refuses_incomplete_scans()
    {
        var server = new FakeNessusServer().HappyPath();
        server.On("GET", "/scans/42", _ => Json(Fixtures.ScanDetailsBody("running")));
        Assert.Equal(5, await RunAsync(server, "results", "--scan-id", "42", "--output", Prefix));
        Assert.False(File.Exists(Prefix + ".findings.json"));
    }

    [Theory]
    [InlineData("30s", 30_000)]
    [InlineData("15m", 900_000)]
    [InlineData("2h", 7_200_000)]
    [InlineData("250ms", 250)]
    [InlineData("45", 45_000)]
    public void Durations_parse(string input, double expectedMs) =>
        Assert.Equal(expectedMs, CliArguments.ParseDuration(input, "x").TotalMilliseconds);

    [Fact]
    public async Task Unknown_options_and_repeated_single_options_are_rejected()
    {
        Assert.Equal(2, await RunAsync(new FakeNessusServer(), "templates", "--bogus"));
        Assert.Equal(2, await RunAsync(new FakeNessusServer(), "templates", "--url", "https://a.test", "--url", "https://b.test"));
    }
}
