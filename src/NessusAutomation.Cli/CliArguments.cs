using System.Globalization;
using System.Text.RegularExpressions;
using NessusAutomation.Configuration;

namespace NessusAutomation.Cli;

/// <summary>Parsed command line: a command name plus <c>--option value</c> pairs and flags.</summary>
internal sealed partial class CliArguments
{
    private static readonly HashSet<string> CommonValueOptions = ["url", "ca-cert", "request-timeout", "retries"];
    private static readonly HashSet<string> CommonFlags = ["insecure-skip-tls-verify", "help"];

    private static readonly Dictionary<string, (HashSet<string> Values, HashSet<string> Flags)> Commands = new(StringComparer.Ordinal)
    {
        ["scan"] = (
            ["target", "scope", "scope-file", "max-addresses", "name", "description", "template", "policy-id", "folder-id",
             "output", "poll-interval", "timeout", "max-poll-failures", "min-severity"],
            ["confirm-authorized", "dry-run", "overwrite", "wait-while-paused", "stop-on-abort", "skip-plugin-details"]),
        ["validate"] = (
            ["target", "scope", "scope-file", "max-addresses", "name", "description", "template", "policy-id", "folder-id",
             "output", "poll-interval", "timeout", "max-poll-failures", "min-severity"],
            ["overwrite", "wait-while-paused", "stop-on-abort", "skip-plugin-details", "confirm-authorized", "dry-run"]),
        ["results"] = (["scan-id", "history-id", "output", "min-severity"], ["overwrite", "skip-plugin-details"]),
        ["templates"] = ([], []),
        ["policies"] = ([], []),
        ["help"] = ([], []),
    };

    // Secrets must come from the environment so they never land in shell history or process listings.
    private static readonly HashSet<string> ForbiddenSecretOptions =
        ["password", "username", "user", "access-key", "secret-key", "accesskey", "secretkey", "token", "api-key", "apikey"];

    private readonly Dictionary<string, List<string>> _values = new(StringComparer.Ordinal);
    private readonly HashSet<string> _flags = new(StringComparer.Ordinal);

    private CliArguments(string command) => Command = command;

    public string Command { get; }

    public static CliArguments Parse(IReadOnlyList<string> args)
    {
        if (args.Count == 0 || args[0] is "-h" or "--help")
        {
            return new CliArguments("help");
        }

        var command = args[0];
        if (!Commands.TryGetValue(command, out var spec))
        {
            throw new CliUsageException($"Unknown command '{command}'. Commands: scan, validate, results, templates, policies, help.");
        }

        var parsed = new CliArguments(command);
        for (var i = 1; i < args.Count; i++)
        {
            var token = args[i];
            if (token is "-h")
            {
                parsed._flags.Add("help");
                continue;
            }

            if (!token.StartsWith("--", StringComparison.Ordinal) || token.Length == 2)
            {
                throw new CliUsageException($"Unexpected argument '{token}'. Options take the form --name value.");
            }

            var name = token[2..];
            string? inlineValue = null;
            var eq = name.IndexOf('=', StringComparison.Ordinal);
            if (eq >= 0)
            {
                inlineValue = name[(eq + 1)..];
                name = name[..eq];
            }

            if (ForbiddenSecretOptions.Contains(name.ToLowerInvariant()))
            {
                throw new CliUsageException(
                    $"--{name} is not accepted: secrets must not be passed on the command line. " +
                    "Set NESSUS_USERNAME/NESSUS_PASSWORD or NESSUS_ACCESS_KEY/NESSUS_SECRET_KEY in the environment.");
            }

            if (spec.Flags.Contains(name) || CommonFlags.Contains(name))
            {
                if (inlineValue is not null)
                {
                    throw new CliUsageException($"--{name} is a flag and does not take a value.");
                }

                parsed._flags.Add(name);
                continue;
            }

            if (spec.Values.Contains(name) || CommonValueOptions.Contains(name))
            {
                var value = inlineValue;
                if (value is null)
                {
                    if (i + 1 >= args.Count || args[i + 1].StartsWith("--", StringComparison.Ordinal))
                    {
                        throw new CliUsageException($"--{name} requires a value.");
                    }

                    value = args[++i];
                }

                if (!parsed._values.TryGetValue(name, out var list))
                {
                    parsed._values[name] = list = [];
                }

                list.Add(value);
                continue;
            }

            throw new CliUsageException($"Unknown option --{name} for '{command}'. Run 'nessus-auto help'.");
        }

        return parsed;
    }

    public bool Has(string flag) => _flags.Contains(flag);

    public IReadOnlyList<string> All(string name) => _values.TryGetValue(name, out var list) ? list : [];

    public string? Single(string name)
    {
        var values = All(name);
        return values.Count switch
        {
            0 => null,
            1 => values[0],
            _ => throw new CliUsageException($"--{name} may only be given once."),
        };
    }

    public int? Int(string name)
    {
        var value = Single(name);
        if (value is null)
        {
            return null;
        }

        return int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n)
            ? n
            : throw new CliUsageException($"--{name} must be an integer, got '{value}'.");
    }

    public TimeSpan? Duration(string name)
    {
        var value = Single(name);
        return value is null ? null : ParseDuration(value, name);
    }

    /// <summary>Parses <c>500ms</c>, <c>30s</c>, <c>15m</c>, <c>4h</c> or bare seconds.</summary>
    public static TimeSpan ParseDuration(string value, string name)
    {
        var match = DurationPattern().Match(value.Trim());
        if (!match.Success)
        {
            throw new CliUsageException($"--{name} must be a duration such as 30s, 15m or 4h; got '{value}'.");
        }

        var number = double.Parse(match.Groups["n"].Value, NumberStyles.Float, CultureInfo.InvariantCulture);
        return match.Groups["u"].Value switch
        {
            "ms" => TimeSpan.FromMilliseconds(number),
            "m" => TimeSpan.FromMinutes(number),
            "h" => TimeSpan.FromHours(number),
            _ => TimeSpan.FromSeconds(number),
        };
    }

    [GeneratedRegex(@"^(?<n>\d+(\.\d+)?)(?<u>ms|s|m|h)?$", RegexOptions.CultureInvariant)]
    private static partial Regex DurationPattern();
}

internal sealed class CliUsageException : Exception
{
    public CliUsageException(string message)
        : base(message)
    {
    }

    public CliUsageException()
    {
    }

    public CliUsageException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

internal static class ExitCodes
{
    public const int Success = 0;
    public const int UnexpectedError = 1;
    public const int UsageOrConfiguration = 2;
    public const int AuthenticationFailed = 3;
    public const int ApiError = 4;
    public const int ScanFailed = 5;
    public const int DeadlineExceeded = 6;
    public const int ScanPaused = 7;
    public const int OutcomeUnknown = 8;
    public const int Cancelled = 130;
}

/// <summary>Reads credentials from environment variables only.</summary>
internal static class CredentialSource
{
    public const string UrlVariable = "NESSUS_URL";
    public const string UsernameVariable = "NESSUS_USERNAME";
    public const string PasswordVariable = "NESSUS_PASSWORD";
    public const string AccessKeyVariable = "NESSUS_ACCESS_KEY";
    public const string SecretKeyVariable = "NESSUS_SECRET_KEY";

    public static NessusCredentials Resolve(Func<string, string?> env)
    {
        var user = Clean(env(UsernameVariable));
        var password = env(PasswordVariable);
        var access = Clean(env(AccessKeyVariable));
        var secret = Clean(env(SecretKeyVariable));

        var hasUserPair = user is not null || !string.IsNullOrEmpty(password);
        var hasKeyPair = access is not null || secret is not null;

        if (hasUserPair && hasKeyPair)
        {
            throw new ConfigurationException(
                $"Both {UsernameVariable}/{PasswordVariable} and {AccessKeyVariable}/{SecretKeyVariable} are set; unset one pair so the authentication method is unambiguous.");
        }

        if (hasKeyPair)
        {
            if (access is null || secret is null)
            {
                throw new ConfigurationException($"{AccessKeyVariable} and {SecretKeyVariable} must both be set.");
            }

            return new NessusCredentials.ApiKeys(access, secret);
        }

        if (hasUserPair)
        {
            if (user is null || string.IsNullOrEmpty(password))
            {
                throw new ConfigurationException($"{UsernameVariable} and {PasswordVariable} must both be set.");
            }

            return new NessusCredentials.UserPassword(user, password);
        }

        throw new ConfigurationException(
            $"No Nessus credentials found. Set {AccessKeyVariable} and {SecretKeyVariable} (API keys), or {UsernameVariable} and {PasswordVariable}.");
    }

    private static string? Clean(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
