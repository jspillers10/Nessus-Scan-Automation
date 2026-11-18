using System.Net;

namespace NessusAutomation.Api;

public enum NessusErrorKind
{
    /// <summary>401/403 or a login that returned no token.</summary>
    Authentication,

    /// <summary>Non-success HTTP status other than authentication failures.</summary>
    Http,

    /// <summary>Body was not valid JSON or lacked a required field.</summary>
    MalformedResponse,

    /// <summary>A single request attempt exceeded the configured request timeout.</summary>
    Timeout,

    /// <summary>Connection, DNS or TLS failure before a response was received.</summary>
    Transport,
}

/// <summary>
/// A failed Nessus API call. Messages are redacted before construction and never include
/// request bodies or authentication headers.
/// </summary>
public sealed class NessusApiException : Exception
{
    public NessusApiException(
        NessusErrorKind kind,
        string message,
        string method,
        string path,
        HttpStatusCode? statusCode = null,
        bool isTransient = false,
        bool outcomeUnknown = false,
        int attempts = 1,
        Exception? innerException = null)
        : base(message, innerException)
    {
        Kind = kind;
        Method = method;
        Path = path;
        StatusCode = statusCode;
        IsTransient = isTransient;
        OutcomeUnknown = outcomeUnknown;
        Attempts = attempts;
    }

    public NessusApiException()
        : this(NessusErrorKind.Http, "Nessus API request failed.", string.Empty, string.Empty)
    {
    }

    public NessusApiException(string message)
        : this(NessusErrorKind.Http, message, string.Empty, string.Empty)
    {
    }

    public NessusApiException(string message, Exception innerException)
        : this(NessusErrorKind.Http, message, string.Empty, string.Empty, innerException: innerException)
    {
    }

    public NessusErrorKind Kind { get; }

    public string Method { get; } = string.Empty;

    public string Path { get; } = string.Empty;

    public HttpStatusCode? StatusCode { get; }

    /// <summary>The failure class is one that may succeed if repeated later (timeouts, 429, 502-504).</summary>
    public bool IsTransient { get; }

    /// <summary>
    /// True when a non-idempotent request may have been processed even though no
    /// response was received (e.g. timeout after the request was sent). Callers must not
    /// blindly repeat the operation.
    /// </summary>
    public bool OutcomeUnknown { get; }

    public int Attempts { get; }

    /// <summary>Server-requested back-off from a <c>Retry-After</c> header, if any.</summary>
    public TimeSpan? RetryAfter { get; init; }
}
