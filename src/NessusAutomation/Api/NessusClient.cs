using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using NessusAutomation.Configuration;
using NessusAutomation.Http;
using NessusAutomation.Security;

namespace NessusAutomation.Api;

/// <summary>
/// Thin, typed client for the Nessus REST API.
/// </summary>
/// <remarks>
/// <list type="bullet">
/// <item>Every request has its own timeout and honours the caller's cancellation token.</item>
/// <item>Only retry-safe requests (reads, login, logout) are retried, and only for transient
/// failures. Scan creation, launch and stop are attempted exactly once.</item>
/// <item>Error messages are passed through <see cref="SecretRedactor"/> and never include
/// request bodies or authentication headers.</item>
/// </list>
/// </remarks>
public sealed class NessusClient : IAsyncDisposable
{
    private const string SessionPath = "session";
    private const int MaxErrorDetailLength = 300;

    private static readonly HashSet<HttpStatusCode> TransientStatusCodes =
    [
        HttpStatusCode.RequestTimeout,
        HttpStatusCode.TooManyRequests,
        HttpStatusCode.BadGateway,
        HttpStatusCode.ServiceUnavailable,
        HttpStatusCode.GatewayTimeout,
    ];

    private readonly HttpClient _http;
    private readonly NessusConnectionOptions _options;
    private readonly SecretRedactor _redactor;
    private readonly IAppLog _log;
    private readonly TimeProvider _time;
    private string? _sessionToken;
    private bool _apiKeysActive;
    private bool _disposed;

    /// <param name="handler">Transport; production code uses <see cref="NessusHttpHandlerFactory"/>, tests inject a fake.</param>
    public NessusClient(
        NessusConnectionOptions options,
        HttpMessageHandler handler,
        SecretRedactor redactor,
        IAppLog log,
        TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(handler);
        options.Validate();

        _options = options;
        _redactor = redactor ?? throw new ArgumentNullException(nameof(redactor));
        _log = log ?? throw new ArgumentNullException(nameof(log));
        _time = time ?? TimeProvider.System;

        switch (options.Credentials)
        {
            case NessusCredentials.UserPassword up:
                _redactor.Register(up.Password);
                break;
            case NessusCredentials.ApiKeys keys:
                _redactor.Register(keys.AccessKey);
                _redactor.Register(keys.SecretKey);
                break;
        }

        _http = new HttpClient(handler, disposeHandler: true)
        {
            BaseAddress = options.BaseUri,
            // Per-request timeouts are enforced with linked tokens so they can be told apart from user cancellation.
            Timeout = Timeout.InfiniteTimeSpan,
            MaxResponseContentBufferSize = 128L * 1024 * 1024,
        };
        _http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("nessus-scan-automation", "1.0"));
    }

    /// <summary>Creates a client with the production handler and the configured TLS policy.</summary>
    public static NessusClient Create(NessusConnectionOptions options, SecretRedactor redactor, IAppLog log)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        return new NessusClient(options, NessusHttpHandlerFactory.Create(options.Tls, log), redactor, log);
    }

    public bool IsAuthenticated => _sessionToken is not null || _apiKeysActive;

    public bool TlsVerificationDisabled => _options.Tls.Mode == TlsValidationMode.InsecureSkipVerify;

    /// <summary>
    /// Username/password: <c>POST /session</c> exchanges credentials for a token sent as
    /// <c>X-Cookie: token=...</c>. API keys: sent as <c>X-ApiKeys</c> on each request; no
    /// session is created.
    /// </summary>
    public async Task AuthenticateAsync(CancellationToken cancellationToken)
    {
        switch (_options.Credentials)
        {
            case NessusCredentials.ApiKeys:
                _apiKeysActive = true;
                _log.Info("Authentication: using API keys (X-ApiKeys); no session will be created.");
                return;

            case NessusCredentials.UserPassword up:
                var body = new JsonObject { ["username"] = up.Username, ["password"] = up.Password };
                var root = await SendAsync(HttpMethod.Post, SessionPath, body, retrySafe: true, authenticated: false, cancellationToken).ConfigureAwait(false)
                    ?? throw new NessusApiException(NessusErrorKind.Authentication, "POST /session returned an empty body; no session token was issued.", "POST", "/session");
                string token;
                try
                {
                    token = new ResponseParser("POST", "/session").ParseToken(root);
                }
                catch (NessusApiException ex) when (ex.Kind == NessusErrorKind.MalformedResponse)
                {
                    throw new NessusApiException(NessusErrorKind.Authentication, "POST /session succeeded but returned no session token.", "POST", "/session", innerException: ex);
                }

                _redactor.Register(token);
                _sessionToken = token;
                _log.Info($"Authentication: session established for user '{up.Username}'.");
                return;

            default:
                throw new InvalidOperationException("Unsupported credential type.");
        }
    }

    /// <summary>Ends the session with <c>DELETE /session</c>. Safe to call repeatedly; failures are logged, not thrown.</summary>
    public async Task LogoutAsync()
    {
        if (_sessionToken is null)
        {
            _apiKeysActive = false;
            return;
        }

        try
        {
            // Independent of the caller's token so cleanup still happens after Ctrl+C.
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            await SendAsync(HttpMethod.Delete, SessionPath, null, retrySafe: false, authenticated: true, cts.Token).ConfigureAwait(false);
            _log.Info("Authentication: session closed.");
        }
        catch (Exception ex) when (ex is NessusApiException or OperationCanceledException)
        {
            _log.Warn($"Could not close the Nessus session cleanly: {_redactor.Redact(ex.Message)}");
        }
        finally
        {
            _sessionToken = null;
        }
    }

    /// <summary><c>GET /editor/scan/templates</c>.</summary>
    public async Task<IReadOnlyList<ScanTemplate>> GetScanTemplatesAsync(CancellationToken cancellationToken)
    {
        const string path = "editor/scan/templates";
        var root = await GetRequiredAsync(path, cancellationToken).ConfigureAwait(false);
        return new ResponseParser("GET", "/" + path).ParseTemplates(root);
    }

    /// <summary><c>GET /policies</c>.</summary>
    public async Task<IReadOnlyList<ScanPolicy>> GetPoliciesAsync(CancellationToken cancellationToken)
    {
        const string path = "policies";
        var root = await GetRequiredAsync(path, cancellationToken).ConfigureAwait(false);
        return new ResponseParser("GET", "/" + path).ParsePolicies(root);
    }

    /// <summary><c>POST /scans</c>. Never retried: a repeated request could create a duplicate scan.</summary>
    public async Task<CreatedScan> CreateScanAsync(CreateScanRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        const string path = "scans";
        var root = await SendAsync(HttpMethod.Post, path, BuildCreateScanBody(request), retrySafe: false, authenticated: true, cancellationToken).ConfigureAwait(false)
            ?? throw EmptyBody("POST", path);
        return new ResponseParser("POST", "/" + path).ParseCreatedScan(root);
    }

    /// <summary><c>POST /scans/{id}/launch</c>. Never retried. Returns the run's <c>scan_uuid</c> when supplied.</summary>
    public async Task<string?> LaunchScanAsync(int scanId, CancellationToken cancellationToken)
    {
        var path = $"scans/{scanId.ToString(CultureInfo.InvariantCulture)}/launch";
        var root = await SendAsync(HttpMethod.Post, path, null, retrySafe: false, authenticated: true, cancellationToken).ConfigureAwait(false);
        return root is { } r ? ResponseParser.ParseLaunch(r) : null;
    }

    /// <summary><c>POST /scans/{id}/stop</c>. Never retried.</summary>
    public async Task StopScanAsync(int scanId, CancellationToken cancellationToken)
    {
        var path = $"scans/{scanId.ToString(CultureInfo.InvariantCulture)}/stop";
        await SendAsync(HttpMethod.Post, path, null, retrySafe: false, authenticated: true, cancellationToken).ConfigureAwait(false);
    }

    /// <summary><c>GET /scans/{id}[?history_id=]</c>.</summary>
    public async Task<ScanDetails> GetScanDetailsAsync(int scanId, int? historyId, CancellationToken cancellationToken)
    {
        var path = WithHistory($"scans/{scanId.ToString(CultureInfo.InvariantCulture)}", historyId);
        var root = await GetRequiredAsync(path, cancellationToken).ConfigureAwait(false);
        return new ResponseParser("GET", "/" + path).ParseScanDetails(root);
    }

    /// <summary><c>GET /scans/{id}/hosts/{host_id}[?history_id=]</c>.</summary>
    public async Task<HostDetails> GetHostDetailsAsync(int scanId, int hostId, int? historyId, CancellationToken cancellationToken)
    {
        var path = WithHistory(FormattableString.Invariant($"scans/{scanId}/hosts/{hostId}"), historyId);
        var root = await GetRequiredAsync(path, cancellationToken).ConfigureAwait(false);
        return new ResponseParser("GET", "/" + path).ParseHostDetails(root);
    }

    /// <summary><c>GET /scans/{id}/hosts/{host_id}/plugins/{plugin_id}[?history_id=]</c>.</summary>
    public async Task<PluginDetails> GetPluginDetailsAsync(int scanId, int hostId, int pluginId, int? historyId, CancellationToken cancellationToken)
    {
        var path = WithHistory(FormattableString.Invariant($"scans/{scanId}/hosts/{hostId}/plugins/{pluginId}"), historyId);
        var root = await GetRequiredAsync(path, cancellationToken).ConfigureAwait(false);
        return new ResponseParser("GET", "/" + path).ParsePluginDetails(root, pluginId);
    }

    /// <summary>The exact JSON body sent by <see cref="CreateScanAsync"/>.</summary>
    public static JsonObject BuildCreateScanBody(CreateScanRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var settings = new JsonObject
        {
            ["name"] = request.Name,
            ["text_targets"] = request.TextTargets,
            // Not scheduled: the scan only runs when explicitly launched.
            ["enabled"] = false,
        };

        if (!string.IsNullOrWhiteSpace(request.Description))
        {
            settings["description"] = request.Description;
        }

        if (request.PolicyId is { } policyId)
        {
            settings["policy_id"] = policyId;
        }

        if (request.FolderId is { } folderId)
        {
            settings["folder_id"] = folderId;
        }

        return new JsonObject
        {
            ["uuid"] = request.TemplateUuid,
            ["settings"] = settings,
        };
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        await LogoutAsync().ConfigureAwait(false);
        _disposed = true;
        _http.Dispose();
    }

    private static string WithHistory(string path, int? historyId) =>
        historyId is { } h ? FormattableString.Invariant($"{path}?history_id={h}") : path;

    private static NessusApiException EmptyBody(string method, string path) =>
        new(NessusErrorKind.MalformedResponse, $"{method} /{path}: malformed response: body was empty.", method, "/" + path);

    private async Task<JsonElement> GetRequiredAsync(string path, CancellationToken cancellationToken) =>
        await SendAsync(HttpMethod.Get, path, null, retrySafe: true, authenticated: true, cancellationToken).ConfigureAwait(false)
        ?? throw EmptyBody("GET", path);

    private async Task<JsonElement?> SendAsync(
        HttpMethod method,
        string relativePath,
        JsonNode? body,
        bool retrySafe,
        bool authenticated,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (authenticated && !IsAuthenticated)
        {
            throw new InvalidOperationException("AuthenticateAsync must be called before using the Nessus API.");
        }

        var maxAttempts = retrySafe ? _options.Retry.MaxAttempts : 1;
        for (var attempt = 1; ; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return await SendOnceAsync(method, relativePath, body, retrySafe, attempt, cancellationToken).ConfigureAwait(false);
            }
            catch (NessusApiException ex) when (ex.IsTransient && attempt < maxAttempts)
            {
                var delay = ComputeRetryDelay(attempt, ex.RetryAfter);
                _log.Warn($"{method} /{StripQuery(relativePath)} failed ({ex.Message}); retry {attempt}/{maxAttempts - 1} in {delay.TotalSeconds:0.##}s.");
                await Task.Delay(delay, _time, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private async Task<JsonElement?> SendOnceAsync(
        HttpMethod method,
        string relativePath,
        JsonNode? body,
        bool retrySafe,
        int attempt,
        CancellationToken cancellationToken)
    {
        var displayPath = "/" + relativePath;
        var methodName = method.Method;

        using var request = new HttpRequestMessage(method, relativePath);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        ApplyAuthentication(request, relativePath);
        if (body is not null)
        {
            request.Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
        }

        using var attemptCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        attemptCts.CancelAfter(_options.RequestTimeout);

        HttpResponseMessage response;
        string content;
        try
        {
            response = await _http.SendAsync(request, HttpCompletionOption.ResponseContentRead, attemptCts.Token).ConfigureAwait(false);
            content = await response.Content.ReadAsStringAsync(attemptCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            throw new NessusApiException(
                NessusErrorKind.Timeout,
                $"{methodName} {displayPath} timed out after {_options.RequestTimeout.TotalSeconds:0.##}s.",
                methodName,
                displayPath,
                isTransient: true,
                outcomeUnknown: !retrySafe,
                attempts: attempt,
                innerException: ex);
        }
        catch (HttpRequestException ex)
        {
            // Failures before the request left this machine cannot have created anything server-side.
            var notSent = ex.HttpRequestError is HttpRequestError.NameResolutionError or HttpRequestError.ConnectionError or HttpRequestError.SecureConnectionError or HttpRequestError.ProxyTunnelError;
            var tls = ex.HttpRequestError == HttpRequestError.SecureConnectionError;
            var hint = tls
                ? " TLS handshake or certificate validation failed; if the server uses a lab CA, pass --ca-cert <file>."
                : string.Empty;
            throw new NessusApiException(
                NessusErrorKind.Transport,
                _redactor.Redact($"{methodName} {displayPath} failed: {ex.Message}{hint}"),
                methodName,
                displayPath,
                isTransient: !tls,
                outcomeUnknown: !retrySafe && !notSent,
                attempts: attempt,
                innerException: null);
        }

        using (response)
        {
            if (response.IsSuccessStatusCode)
            {
                if (string.IsNullOrWhiteSpace(content))
                {
                    return null;
                }

                try
                {
                    using var document = JsonDocument.Parse(content);
                    return document.RootElement.Clone();
                }
                catch (JsonException)
                {
                    throw new NessusApiException(
                        NessusErrorKind.MalformedResponse,
                        $"{methodName} {displayPath}: malformed response: body is not valid JSON (HTTP {(int)response.StatusCode}, {content.Length} bytes).",
                        methodName,
                        displayPath,
                        response.StatusCode,
                        attempts: attempt);
                }
            }

            var status = response.StatusCode;
            var detail = ExtractErrorDetail(content);
            var statusText = $"HTTP {(int)status} {response.ReasonPhrase}".TrimEnd();

            if (status is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            {
                var message = relativePath == SessionPath && method == HttpMethod.Post
                    ? $"Authentication failed ({statusText}): Nessus rejected the supplied credentials.{detail}"
                    : $"{methodName} {displayPath} was rejected ({statusText}). The credentials may lack permission or the session may have expired.{detail}";
                throw new NessusApiException(NessusErrorKind.Authentication, _redactor.Redact(message), methodName, displayPath, status, attempts: attempt);
            }

            var transient = TransientStatusCodes.Contains(status);
            throw new NessusApiException(
                NessusErrorKind.Http,
                _redactor.Redact($"{methodName} {displayPath} failed with {statusText}.{detail}"),
                methodName,
                displayPath,
                status,
                isTransient: transient,
                // A 5xx after a create/launch request may still have taken effect server-side.
                outcomeUnknown: !retrySafe && (int)status >= 500,
                attempts: attempt)
            {
                RetryAfter = GetRetryAfter(response),
            };
        }
    }

    private void ApplyAuthentication(HttpRequestMessage request, string relativePath)
    {
        if (_sessionToken is not null)
        {
            request.Headers.TryAddWithoutValidation("X-Cookie", $"token={_sessionToken}");
        }
        else if (_apiKeysActive && _options.Credentials is NessusCredentials.ApiKeys keys && relativePath != SessionPath)
        {
            request.Headers.TryAddWithoutValidation("X-ApiKeys", $"accessKey={keys.AccessKey}; secretKey={keys.SecretKey}");
        }
    }

    private TimeSpan ComputeRetryDelay(int attempt, TimeSpan? retryAfter)
    {
        var max = _options.Retry.MaxDelay;
        if (retryAfter is { } ra && ra > TimeSpan.Zero)
        {
            return ra < max ? ra : max;
        }

        var exponential = _options.Retry.BaseDelay * Math.Pow(2, attempt - 1);
#pragma warning disable CA5394 // Jitter only spreads retries; it has no security role.
        var jitter = TimeSpan.FromMilliseconds(exponential.TotalMilliseconds * 0.2 * Random.Shared.NextDouble());
#pragma warning restore CA5394
        var delay = exponential + jitter;
        return delay < max ? delay : max;
    }

    private TimeSpan? GetRetryAfter(HttpResponseMessage response)
    {
        var header = response.Headers.RetryAfter;
        if (header?.Delta is { } delta)
        {
            return delta;
        }

        if (header?.Date is { } date)
        {
            var wait = date - _time.GetUtcNow();
            return wait > TimeSpan.Zero ? wait : TimeSpan.Zero;
        }

        return null;
    }

    private static string ExtractErrorDetail(string content)
    {
        if (string.IsNullOrWhiteSpace(content))
        {
            return string.Empty;
        }

        string text;
        try
        {
            using var document = JsonDocument.Parse(content);
            text = document.RootElement.ValueKind == JsonValueKind.Object
                && document.RootElement.TryGetProperty("error", out var error)
                && error.ValueKind == JsonValueKind.String
                    ? error.GetString() ?? string.Empty
                    : content;
        }
        catch (JsonException)
        {
            text = content;
        }

        text = text.ReplaceLineEndings(" ").Trim();
        if (text.Length > MaxErrorDetailLength)
        {
            text = text[..MaxErrorDetailLength] + "...";
        }

        return text.Length == 0 ? string.Empty : $" Server said: {text}";
    }

    private static string StripQuery(string path)
    {
        var index = path.IndexOf('?', StringComparison.Ordinal);
        return index < 0 ? path : path[..index];
    }
}
