using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Text.RegularExpressions;

namespace NessusAutomation.Configuration;

/// <summary>A single, normalised scan target or authorised-scope entry.</summary>
public sealed record ScanTarget
{
    private ScanTarget(string value, IPNetwork? network, string? hostname)
    {
        Value = value;
        Network = network;
        Hostname = hostname;
    }

    /// <summary>Normalised text sent to Nessus.</summary>
    public string Value { get; }

    /// <summary>Set for IP addresses (as /32 or /128) and CIDR blocks.</summary>
    public IPNetwork? Network { get; }

    /// <summary>Set for DNS names (lower-cased, no trailing dot).</summary>
    public string? Hostname { get; }

    /// <summary>Number of addresses covered (1 for hostnames).</summary>
    public BigInteger AddressCount => Network is { } n
        ? BigInteger.One << ((n.BaseAddress.AddressFamily == AddressFamily.InterNetwork ? 32 : 128) - n.PrefixLength)
        : BigInteger.One;

    public override string ToString() => Value;

    internal static ScanTarget FromNetwork(IPNetwork network)
    {
        var full = network.BaseAddress.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        var text = network.PrefixLength == full ? network.BaseAddress.ToString() : network.ToString();
        return new ScanTarget(text, network, null);
    }

    internal static ScanTarget FromHostname(string hostname) => new(hostname, null, hostname);
}

/// <summary>
/// Parses scan targets and enforces that every target sits inside the explicitly
/// authorised scope supplied by the operator.
/// </summary>
/// <remarks>
/// Accepted forms: a single IPv4/IPv6 address, a CIDR block written with its network
/// address (e.g. <c>10.20.0.0/28</c>), or a DNS hostname. Ranges, wildcards, URLs and
/// comma/whitespace separated lists are rejected so that the text sent to Nessus is
/// exactly what was reviewed. Hostnames cannot be resolved offline, so a hostname target
/// is only allowed when the same hostname appears in the scope.
/// </remarks>
public static partial class TargetScopeValidator
{
    public const int DefaultMaxAddresses = 256;
    private const int MaxTargetLength = 253;

    public static bool TryParse(string? raw, out ScanTarget? target, out string? error)
    {
        target = null;
        error = null;
        var value = raw?.Trim() ?? string.Empty;

        if (value.Length == 0)
        {
            error = "Target is empty.";
            return false;
        }

        if (value.Length > MaxTargetLength)
        {
            error = $"'{Truncate(value)}' is longer than {MaxTargetLength} characters.";
            return false;
        }

        if (value.Any(c => char.IsWhiteSpace(c) || char.IsControl(c) || c == ','))
        {
            error = $"'{Truncate(value)}' contains whitespace, a comma or a control character; supply one target per --target.";
            return false;
        }

        if (value.Contains('/', StringComparison.Ordinal))
        {
            var slash = value.IndexOf('/', StringComparison.Ordinal);
            if (!IPAddress.TryParse(value.AsSpan(0, slash), out var written) || !int.TryParse(value.AsSpan(slash + 1), out _)
                || (written.AddressFamily == AddressFamily.InterNetwork && !IPv4Like().IsMatch(value[..slash])))
            {
                error = $"'{value}' is not a valid CIDR block.";
                return false;
            }

            // IPNetwork.TryParse may accept and silently mask host bits; require the written
            // address to be the network address so the reviewed text is what gets scanned.
            if (!IPNetwork.TryParse(value, out var network) || !network.BaseAddress.Equals(written))
            {
                error = $"'{value}' is not a valid CIDR block. Use the network address (host bits must be zero), e.g. 10.0.0.0/24.";
                return false;
            }

            if (network.PrefixLength == 0)
            {
                error = $"'{value}' covers the entire address space.";
                return false;
            }

            target = ScanTarget.FromNetwork(network);
            return true;
        }

        if (value.Contains(':', StringComparison.Ordinal) || IPv4Like().IsMatch(value))
        {
            if (!IPAddress.TryParse(value, out var address) || (address.AddressFamily == AddressFamily.InterNetwork && !IPv4Like().IsMatch(value)))
            {
                error = $"'{value}' is not a valid IP address.";
                return false;
            }

            var bits = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
            target = ScanTarget.FromNetwork(new IPNetwork(address, bits));
            return true;
        }

        var hostname = value.TrimEnd('.').ToLowerInvariant();
        if (!Hostname().IsMatch(hostname))
        {
            error = $"'{Truncate(value)}' is not an IP address, CIDR block or valid DNS hostname (ranges, wildcards and URLs are not accepted).";
            return false;
        }

        target = ScanTarget.FromHostname(hostname);
        return true;
    }

    /// <summary>Parses the authorised scope. Throws <see cref="ConfigurationException"/> listing every invalid entry.</summary>
    public static IReadOnlyList<ScanTarget> ParseScope(IEnumerable<string> entries)
    {
        var scope = new List<ScanTarget>();
        var errors = new List<string>();
        foreach (var entry in entries)
        {
            if (TryParse(entry, out var parsed, out var error))
            {
                scope.Add(parsed!);
            }
            else
            {
                errors.Add($"Scope: {error}");
            }
        }

        if (errors.Count > 0)
        {
            throw new ConfigurationException(errors);
        }

        if (scope.Count == 0)
        {
            throw new ConfigurationException("An authorised scope is required (--scope or --scope-file).");
        }

        return scope;
    }

    /// <summary>
    /// Validates targets against the authorised scope and an address budget. Returns the
    /// de-duplicated, normalised targets or throws <see cref="ConfigurationException"/>.
    /// </summary>
    public static IReadOnlyList<ScanTarget> ValidateTargets(
        IEnumerable<string> rawTargets,
        IReadOnlyList<ScanTarget> scope,
        int maxAddresses = DefaultMaxAddresses)
    {
        ArgumentNullException.ThrowIfNull(scope);
        if (scope.Count == 0)
        {
            throw new ConfigurationException("An authorised scope is required (--scope or --scope-file).");
        }

        if (maxAddresses < 1)
        {
            throw new ConfigurationException("--max-addresses must be at least 1.");
        }

        var errors = new List<string>();
        var targets = new List<ScanTarget>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var raw in rawTargets)
        {
            if (!TryParse(raw, out var target, out var error))
            {
                errors.Add($"Target: {error}");
                continue;
            }

            if (target!.Network is { } net && IsDisallowedAddress(net))
            {
                errors.Add($"Target: '{target.Value}' is an unspecified, broadcast or multicast address.");
                continue;
            }

            if (!scope.Any(s => IsWithin(target, s)))
            {
                errors.Add($"Target: '{target.Value}' is outside the authorised scope.");
                continue;
            }

            if (seen.Add(target.Value))
            {
                targets.Add(target);
            }
        }

        if (errors.Count == 0 && targets.Count == 0)
        {
            errors.Add("At least one --target is required.");
        }

        var total = targets.Aggregate(BigInteger.Zero, (sum, t) => sum + t.AddressCount);
        if (errors.Count == 0 && total > maxAddresses)
        {
            errors.Add($"Targets cover {total} addresses, above the limit of {maxAddresses}. Narrow the targets or raise --max-addresses deliberately.");
        }

        if (errors.Count > 0)
        {
            throw new ConfigurationException(errors);
        }

        return targets;
    }

    internal static bool IsWithin(ScanTarget target, ScanTarget scopeEntry)
    {
        if (target.Hostname is not null)
        {
            return string.Equals(target.Hostname, scopeEntry.Hostname, StringComparison.Ordinal);
        }

        if (target.Network is not { } t || scopeEntry.Network is not { } s)
        {
            return false;
        }

        return t.BaseAddress.AddressFamily == s.BaseAddress.AddressFamily
            && s.PrefixLength <= t.PrefixLength
            && s.Contains(t.BaseAddress);
    }

    private static bool IsDisallowedAddress(IPNetwork network)
    {
        var address = network.BaseAddress;
        if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) || address.Equals(IPAddress.Broadcast))
        {
            return true;
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var first = address.GetAddressBytes()[0];
            return first is >= 224 and <= 239;
        }

        return address.IsIPv6Multicast;
    }

    private static string Truncate(string value) => value.Length <= 64 ? value : value[..64] + "...";

    [GeneratedRegex(@"^\d{1,3}(\.\d{1,3}){3}$", RegexOptions.CultureInvariant)]
    private static partial Regex IPv4Like();

    // RFC 1123 hostname: labels of 1-63 alphanumerics/hyphens, not starting or ending with a hyphen.
    // A purely numeric final label is rejected so malformed IPs (e.g. 10.0.0) are not treated as names.
    [GeneratedRegex(@"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$(?<![.]\d+)(?<!^\d+)", RegexOptions.CultureInvariant)]
    private static partial Regex Hostname();
}
