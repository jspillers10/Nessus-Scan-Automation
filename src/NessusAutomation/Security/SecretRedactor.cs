using System.Collections.Concurrent;
using System.Text.RegularExpressions;

namespace NessusAutomation.Security;

/// <summary>
/// Removes credentials and session material from text before it reaches logs,
/// exception messages, or exported diagnostics.
/// </summary>
/// <remarks>
/// Two layers are applied: exact values registered at runtime (passwords, API keys,
/// session tokens) and pattern-based masking for credential-shaped fragments that may
/// be echoed back by a server or proxy.
/// </remarks>
public sealed partial class SecretRedactor
{
    public const string Mask = "***REDACTED***";

    // Very short values would cause ordinary text to be masked; pattern rules still
    // cover them when they appear in a recognisable credential context.
    private const int MinimumExactMatchLength = 4;

    private readonly ConcurrentDictionary<string, byte> _secrets = new(StringComparer.Ordinal);

    public void Register(string? secret)
    {
        if (!string.IsNullOrEmpty(secret) && secret.Length >= MinimumExactMatchLength)
        {
            _secrets.TryAdd(secret, 0);
        }
    }

    public string Redact(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return text ?? string.Empty;
        }

        var result = text;

        // Longest first so a secret that contains another secret is masked whole.
        foreach (var secret in _secrets.Keys.OrderByDescending(s => s.Length))
        {
            result = result.Replace(secret, Mask, StringComparison.Ordinal);
        }

        result = JsonSecretField().Replace(result, m => $"{m.Groups["prefix"].Value}{Mask}\"");
        result = KeyValueSecret().Replace(result, m => $"{m.Groups["key"].Value}{Mask}");
        result = AuthorizationHeader().Replace(result, m => $"{m.Groups["prefix"].Value}{Mask}");
        return result;
    }

    // "password": "...", "token": "...", "accessKey": "..." etc. in JSON bodies.
    [GeneratedRegex(@"(?<prefix>""(?:password|token|accessKey|secretKey|access_key|secret_key|api_key|apiKey)""\s*:\s*"")(?:\\.|[^""\\])*""",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex JsonSecretField();

    // token=..., accessKey=...; secretKey=... as used in X-Cookie / X-ApiKeys headers.
    [GeneratedRegex(@"(?<key>\b(?:token|accessKey|secretKey|password)\s*=\s*)[^;,\s""'&]+",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex KeyValueSecret();

    [GeneratedRegex(@"(?<prefix>\bAuthorization\s*:\s*\w+\s+)\S+",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex AuthorizationHeader();
}
