using System.Net;
using NessusAutomation.Api;
using NessusAutomation.Configuration;
using NessusAutomation.Tests.Fakes;
using static NessusAutomation.Tests.Fakes.FakeNessusServer;

namespace NessusAutomation.Tests;

public class NessusClientTests
{
    [Fact]
    public async Task Authenticate_with_password_posts_credentials_and_uses_session_token()
    {
        await using var h = new Harness(new FakeNessusServer().HappyPath());
        var client = await h.AuthenticatedAsync();
        await client.GetScanTemplatesAsync(CancellationToken.None);

        var login = Assert.Single(h.Server.Requests, r => r.Path == "/session");
        Assert.Equal("POST", login.Method);
        Assert.Equal(Fixtures.Username, login.BodyJson.GetProperty("username").GetString());
        Assert.Equal(Fixtures.Password, login.BodyJson.GetProperty("password").GetString());
        Assert.Null(login.Header("X-Cookie"));

        var templates = Assert.Single(h.Server.Requests, r => r.Path == "/editor/scan/templates");
        Assert.Equal($"token={Fixtures.SessionToken}", templates.Header("X-Cookie"));
        Assert.Null(templates.Header("X-ApiKeys"));
        Assert.True(client.IsAuthenticated);
    }

    [Fact]
    public async Task Authenticate_failure_returns_authentication_error_without_leaking_password()
    {
        var server = new FakeNessusServer()
            .On("POST", "/session", _ => Json($$"""{"error":"Invalid Credentials for {{Fixtures.Password}}"}""", HttpStatusCode.Unauthorized));
        await using var h = new Harness(server);

        var ex = await Assert.ThrowsAsync<NessusApiException>(() => h.Client.AuthenticateAsync(CancellationToken.None));

        Assert.Equal(NessusErrorKind.Authentication, ex.Kind);
        Assert.Equal(HttpStatusCode.Unauthorized, ex.StatusCode);
        Assert.DoesNotContain(Fixtures.Password, ex.Message, StringComparison.Ordinal);
        Assert.Contains("Authentication failed", ex.Message, StringComparison.Ordinal);
        Assert.Equal(1, server.Count("POST", "/session"));
        Assert.False(h.Client.IsAuthenticated);
    }

    [Fact]
    public async Task Authenticate_success_without_token_is_an_authentication_error()
    {
        var server = new FakeNessusServer().On("POST", "/session", _ => Json("""{"unexpected":true}"""));
        await using var h = new Harness(server);

        var ex = await Assert.ThrowsAsync<NessusApiException>(() => h.Client.AuthenticateAsync(CancellationToken.None));

        Assert.Equal(NessusErrorKind.Authentication, ex.Kind);
        Assert.Contains("no session token", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Api_keys_are_sent_in_X_ApiKeys_header_and_no_session_is_created()
    {
        var server = new FakeNessusServer().HappyPath();
        var options = Fixtures.Connection(new NessusCredentials.ApiKeys(Fixtures.AccessKey, Fixtures.SecretKey));
        var h = new Harness(server, options);
        await h.AuthenticatedAsync();
        await h.Client.GetPoliciesAsync(CancellationToken.None);
        await h.DisposeAsync();

        var request = Assert.Single(server.Requests);
        Assert.Equal("/policies", request.Path);
        Assert.Equal($"accessKey={Fixtures.AccessKey}; secretKey={Fixtures.SecretKey}", request.Header("X-ApiKeys"));
        Assert.Equal(0, server.Count("POST", "/session"));
        Assert.Equal(0, server.Count("DELETE", "/session"));
    }

    [Fact]
    public async Task Dispose_closes_the_session_exactly_once()
    {
        var server = new FakeNessusServer().HappyPath();
        var h = new Harness(server);
        await h.AuthenticatedAsync();

        await h.Client.DisposeAsync();
        await h.Client.DisposeAsync();

        var logout = Assert.Single(server.Requests, r => r.Method == "DELETE");
        Assert.Equal("/session", logout.Path);
        Assert.Equal($"token={Fixtures.SessionToken}", logout.Header("X-Cookie"));
        Assert.False(h.Client.IsAuthenticated);
    }

    [Fact]
    public async Task Requests_before_authentication_are_rejected_locally()
    {
        await using var h = new Harness(new FakeNessusServer().HappyPath());
        await Assert.ThrowsAsync<InvalidOperationException>(() => h.Client.GetPoliciesAsync(CancellationToken.None));
        Assert.Empty(h.Server.Requests);
    }

    [Fact]
    public async Task Http_error_surfaces_status_and_redacted_server_message()
    {
        var server = new FakeNessusServer().HappyPath()
            .On("GET", "/policies", _ => Json($$"""{"error":"backend failure token={{Fixtures.SessionToken}}"}""", HttpStatusCode.InternalServerError));
        await using var h = new Harness(server);
        await h.AuthenticatedAsync();

        var ex = await Assert.ThrowsAsync<NessusApiException>(() => h.Client.GetPoliciesAsync(CancellationToken.None));

        Assert.Equal(NessusErrorKind.Http, ex.Kind);
        Assert.Equal(HttpStatusCode.InternalServerError, ex.StatusCode);
        Assert.False(ex.IsTransient);
        Assert.Contains("backend failure", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(Fixtures.SessionToken, ex.Message, StringComparison.Ordinal);
        Assert.Equal(1, server.Count("GET", "/policies"));
    }

    [Fact]
    public async Task Expired_session_is_reported_as_authentication_error()
    {
        var server = new FakeNessusServer().HappyPath()
            .On("GET", "/policies", _ => Json("""{"error":"Invalid Credentials"}""", HttpStatusCode.Unauthorized));
        await using var h = new Harness(server);
        await h.AuthenticatedAsync();

        var ex = await Assert.ThrowsAsync<NessusApiException>(() => h.Client.GetPoliciesAsync(CancellationToken.None));
        Assert.Equal(NessusErrorKind.Authentication, ex.Kind);
        Assert.Contains("session may have expired", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("{not json")]
    [InlineData("<html>proxy error</html>")]
    public async Task Malformed_json_is_a_distinct_error(string body)
    {
        var server = new FakeNessusServer().HappyPath()
            .On("GET", "/editor/scan/templates", _ => Json(body));
        await using var h = new Harness(server);
        await h.AuthenticatedAsync();

        var ex = await Assert.ThrowsAsync<NessusApiException>(() => h.Client.GetScanTemplatesAsync(CancellationToken.None));
        Assert.Equal(NessusErrorKind.MalformedResponse, ex.Kind);
        Assert.Contains("not valid JSON", ex.Message, StringComparison.Ordinal);
        Assert.Equal(1, server.Count("GET", "/editor/scan/templates"));
    }

    [Theory]
    [InlineData("""{"scan":{"name":"x"}}""", "scan.id")]
    [InlineData("""{"scan":{"id":"not-a-number"}}""", "scan.id")]
    [InlineData("""{"other":{}}""", "scan")]
    public async Task Create_scan_response_missing_required_fields_is_malformed(string body, string field)
    {
        var server = new FakeNessusServer().HappyPath().On("POST", "/scans", _ => Json(body));
        await using var h = new Harness(server);
        await h.AuthenticatedAsync();

        var ex = await Assert.ThrowsAsync<NessusApiException>(() =>
            h.Client.CreateScanAsync(new CreateScanRequest("uuid", "n", null, "192.0.2.10", null, null), CancellationToken.None));
        Assert.Equal(NessusErrorKind.MalformedResponse, ex.Kind);
        Assert.Contains($"'{field}'", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Scan_details_without_info_status_is_malformed()
    {
        var server = new FakeNessusServer().HappyPath()
            .On("GET", "/scans/42", _ => Json("""{"info":{"name":"x"},"hosts":[]}"""));
        await using var h = new Harness(server);
        await h.AuthenticatedAsync();

        var ex = await Assert.ThrowsAsync<NessusApiException>(() => h.Client.GetScanDetailsAsync(42, null, CancellationToken.None));
        Assert.Contains("'info.status'", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Host_details_missing_vulnerabilities_array_is_malformed()
    {
        var server = new FakeNessusServer().HappyPath()
            .On("GET", "/scans/42/hosts/1", _ => Json("""{"info":{}}"""));
        await using var h = new Harness(server);
        await h.AuthenticatedAsync();

        var ex = await Assert.ThrowsAsync<NessusApiException>(() => h.Client.GetHostDetailsAsync(42, 1, null, CancellationToken.None));
        Assert.Equal(NessusErrorKind.MalformedResponse, ex.Kind);
        Assert.Contains("'vulnerabilities'", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Null_policies_list_means_no_saved_policies()
    {
        var server = new FakeNessusServer().HappyPath().On("GET", "/policies", _ => Json("""{"policies":null}"""));
        await using var h = new Harness(server);
        await h.AuthenticatedAsync();

        Assert.Empty(await h.Client.GetPoliciesAsync(CancellationToken.None));
    }

    [Theory]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    [InlineData(HttpStatusCode.BadGateway)]
    [InlineData(HttpStatusCode.GatewayTimeout)]
    [InlineData(HttpStatusCode.TooManyRequests)]
    public async Task Transient_errors_on_reads_are_retried_until_success(HttpStatusCode status)
    {
        var server = new FakeNessusServer().HappyPath();
        server.OnSequence("GET", "/policies",
            _ => Status(status),
            _ => Status(status),
            _ => Json("""{"policies":[{"id":1,"name":"p","template_uuid":"t"}]}"""));
        await using var h = new Harness(server);
        await h.AuthenticatedAsync();

        var policies = await h.Client.GetPoliciesAsync(CancellationToken.None);

        Assert.Single(policies);
        Assert.Equal(3, server.Count("GET", "/policies"));
        Assert.Contains("retry 1/2", h.LogText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Retries_stop_after_max_attempts()
    {
        var server = new FakeNessusServer().HappyPath().On("GET", "/policies", _ => Status(HttpStatusCode.ServiceUnavailable));
        await using var h = new Harness(server, Fixtures.Connection(maxAttempts: 4));
        await h.AuthenticatedAsync();

        var ex = await Assert.ThrowsAsync<NessusApiException>(() => h.Client.GetPoliciesAsync(CancellationToken.None));

        Assert.True(ex.IsTransient);
        Assert.Equal(4, ex.Attempts);
        Assert.Equal(4, server.Count("GET", "/policies"));
    }

    [Theory]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.BadRequest)]
    [InlineData(HttpStatusCode.InternalServerError)]
    public async Task Non_transient_errors_are_not_retried(HttpStatusCode status)
    {
        var server = new FakeNessusServer().HappyPath().On("GET", "/policies", _ => Status(status));
        await using var h = new Harness(server);
        await h.AuthenticatedAsync();

        await Assert.ThrowsAsync<NessusApiException>(() => h.Client.GetPoliciesAsync(CancellationToken.None));
        Assert.Equal(1, server.Count("GET", "/policies"));
    }

    [Fact]
    public async Task Create_scan_is_never_retried_and_5xx_marks_outcome_unknown()
    {
        var server = new FakeNessusServer().HappyPath().On("POST", "/scans", _ => Status(HttpStatusCode.ServiceUnavailable));
        await using var h = new Harness(server);
        await h.AuthenticatedAsync();

        var ex = await Assert.ThrowsAsync<NessusApiException>(() =>
            h.Client.CreateScanAsync(new CreateScanRequest("uuid", "n", null, "192.0.2.10", null, null), CancellationToken.None));

        Assert.Equal(1, server.Count("POST", "/scans"));
        Assert.True(ex.OutcomeUnknown);
    }

    [Fact]
    public async Task Launch_is_never_retried()
    {
        var server = new FakeNessusServer().HappyPath().On("POST", "/scans/42/launch", _ => Status(HttpStatusCode.BadGateway));
        await using var h = new Harness(server);
        await h.AuthenticatedAsync();

        await Assert.ThrowsAsync<NessusApiException>(() => h.Client.LaunchScanAsync(42, CancellationToken.None));
        Assert.Equal(1, server.Count("POST", "/scans/42/launch"));
    }

    [Fact]
    public async Task Request_timeout_on_create_is_not_retried_and_outcome_is_unknown()
    {
        var server = new FakeNessusServer().HappyPath()
            .OnAsync("POST", "/scans", async (_, ct) =>
            {
                await Task.Delay(Timeout.Infinite, ct);
                return Status(HttpStatusCode.OK);
            });
        await using var h = new Harness(server, Fixtures.Connection(requestTimeout: TimeSpan.FromMilliseconds(100)));
        await h.AuthenticatedAsync();

        var ex = await Assert.ThrowsAsync<NessusApiException>(() =>
            h.Client.CreateScanAsync(new CreateScanRequest("uuid", "n", null, "192.0.2.10", null, null), CancellationToken.None));

        Assert.Equal(NessusErrorKind.Timeout, ex.Kind);
        Assert.True(ex.OutcomeUnknown);
        Assert.Equal(1, server.Count("POST", "/scans"));
    }

    [Fact]
    public async Task Request_timeout_on_read_is_retried()
    {
        var calls = 0;
        var server = new FakeNessusServer().HappyPath()
            .OnAsync("GET", "/policies", async (_, ct) =>
            {
                if (Interlocked.Increment(ref calls) == 1)
                {
                    await Task.Delay(Timeout.Infinite, ct);
                }

                return Json("""{"policies":[]}""");
            });
        await using var h = new Harness(server, Fixtures.Connection(requestTimeout: TimeSpan.FromMilliseconds(100)));
        await h.AuthenticatedAsync();

        Assert.Empty(await h.Client.GetPoliciesAsync(CancellationToken.None));
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task Caller_cancellation_is_not_reported_as_timeout()
    {
        using var cts = new CancellationTokenSource();
        var server = new FakeNessusServer().HappyPath()
            .OnAsync("GET", "/policies", async (_, ct) =>
            {
                await cts.CancelAsync();
                await Task.Delay(Timeout.Infinite, ct);
                return Status(HttpStatusCode.OK);
            });
        await using var h = new Harness(server);
        await h.AuthenticatedAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => h.Client.GetPoliciesAsync(cts.Token));
        Assert.Equal(1, server.Count("GET", "/policies"));
    }

    [Fact]
    public async Task Transport_failure_on_read_is_retried_then_reported()
    {
        var server = new FakeNessusServer().HappyPath()
            .On("GET", "/policies", _ => throw new HttpRequestException(HttpRequestError.ConnectionError, "connection refused"));
        await using var h = new Harness(server);
        await h.AuthenticatedAsync();

        var ex = await Assert.ThrowsAsync<NessusApiException>(() => h.Client.GetPoliciesAsync(CancellationToken.None));
        Assert.Equal(NessusErrorKind.Transport, ex.Kind);
        Assert.Equal(3, server.Count("GET", "/policies"));
    }

    [Fact]
    public async Task Tls_failure_is_not_retried_and_suggests_ca_cert()
    {
        var server = new FakeNessusServer()
            .On("POST", "/session", _ => throw new HttpRequestException(HttpRequestError.SecureConnectionError, "The remote certificate is invalid"));
        await using var h = new Harness(server);

        var ex = await Assert.ThrowsAsync<NessusApiException>(() => h.Client.AuthenticateAsync(CancellationToken.None));
        Assert.Equal(NessusErrorKind.Transport, ex.Kind);
        Assert.False(ex.IsTransient);
        Assert.Contains("--ca-cert", ex.Message, StringComparison.Ordinal);
        Assert.Equal(1, server.Count("POST", "/session"));
    }

    [Fact]
    public async Task Connection_refused_on_create_is_not_outcome_unknown()
    {
        var server = new FakeNessusServer().HappyPath()
            .On("POST", "/scans", _ => throw new HttpRequestException(HttpRequestError.ConnectionError, "refused"));
        await using var h = new Harness(server);
        await h.AuthenticatedAsync();

        var ex = await Assert.ThrowsAsync<NessusApiException>(() =>
            h.Client.CreateScanAsync(new CreateScanRequest("uuid", "n", null, "192.0.2.10", null, null), CancellationToken.None));
        Assert.False(ex.OutcomeUnknown);
        Assert.Equal(1, server.Count("POST", "/scans"));
    }

    [Fact]
    public async Task Plugin_details_parse_solution_risk_and_cves()
    {
        await using var h = new Harness(new FakeNessusServer().HappyPath());
        await h.AuthenticatedAsync();

        var details = await h.Client.GetPluginDetailsAsync(42, 1, 201000, 7, CancellationToken.None);

        Assert.Equal("Critical", details.RiskFactor);
        Assert.Equal("9.8", details.Cvss3BaseScore);
        Assert.Equal(["CVE-2099-0001", "CVE-2099-0002"], details.Cves);
        Assert.StartsWith("Upgrade to version 2.0", details.Solution, StringComparison.Ordinal);
        Assert.Equal("?history_id=7", h.Server.Requests[^1].Query);
    }
}
