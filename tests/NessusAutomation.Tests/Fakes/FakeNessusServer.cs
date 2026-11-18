using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;

namespace NessusAutomation.Tests.Fakes;

public sealed record RecordedRequest(string Method, string Path, string Query, IReadOnlyDictionary<string, string> Headers, string? Body)
{
    public JsonElement BodyJson => JsonDocument.Parse(Body ?? "null").RootElement;

    public string? Header(string name) => Headers.TryGetValue(name, out var v) ? v : null;
}

/// <summary>
/// In-memory stand-in for the Nessus REST API. Routes are matched on method + absolute
/// path; unmatched requests return 404 so missing expectations fail loudly.
/// </summary>
public sealed class FakeNessusServer : HttpMessageHandler
{
    private readonly List<(string Method, string Path, Func<RecordedRequest, CancellationToken, Task<HttpResponseMessage>> Handler)> _routes = [];
    private readonly ConcurrentQueue<RecordedRequest> _requests = new();

    public IReadOnlyList<RecordedRequest> Requests => _requests.ToList();

    public int Count(string method, string path) => Requests.Count(r => r.Method == method && r.Path == path);

    public FakeNessusServer On(string method, string path, Func<RecordedRequest, HttpResponseMessage> handler) =>
        OnAsync(method, path, (r, _) => Task.FromResult(handler(r)));

    public FakeNessusServer OnAsync(string method, string path, Func<RecordedRequest, CancellationToken, Task<HttpResponseMessage>> handler)
    {
        // Later registrations win so tests can override fixture defaults.
        _routes.Insert(0, (method, path, handler));
        return this;
    }

    /// <summary>Responds with each factory in turn; the last one repeats.</summary>
    public FakeNessusServer OnSequence(string method, string path, params Func<RecordedRequest, HttpResponseMessage>[] responses)
    {
        var index = 0;
        return On(method, path, r =>
        {
            var current = Math.Min(Interlocked.Increment(ref index) - 1, responses.Length - 1);
            return responses[current](r);
        });
    }

    public static HttpResponseMessage Json(string json, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    public static HttpResponseMessage Json(object value, HttpStatusCode status = HttpStatusCode.OK) =>
        Json(JsonSerializer.Serialize(value), status);

    public static HttpResponseMessage Status(HttpStatusCode status, string body = "") =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var headers = request.Headers.ToDictionary(h => h.Key, h => string.Join(", ", h.Value), StringComparer.OrdinalIgnoreCase);
        var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
        var uri = request.RequestUri!;
        var recorded = new RecordedRequest(request.Method.Method, uri.AbsolutePath, uri.Query, headers, body);
        _requests.Enqueue(recorded);

        foreach (var route in _routes)
        {
            if (route.Method == recorded.Method && route.Path == recorded.Path)
            {
                var response = await route.Handler(recorded, cancellationToken);
                response.RequestMessage = request;
                return response;
            }
        }

        return Json("""{"error":"no fake route"}""", HttpStatusCode.NotFound);
    }
}
