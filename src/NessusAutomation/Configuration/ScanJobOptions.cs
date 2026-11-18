namespace NessusAutomation.Configuration;

/// <summary>
/// How the scan configuration is chosen. Nessus distinguishes Tenable-provided
/// <em>templates</em> (identified by UUID, listed by <c>GET /editor/scan/templates</c>)
/// from user-saved <em>policies</em> (identified by integer ID, listed by <c>GET /policies</c>).
/// </summary>
public abstract record ScanSelection
{
    private ScanSelection()
    {
    }

    /// <summary>A Tenable template matched by its short <c>name</c> (e.g. <c>basic</c>) or exact <c>uuid</c>.</summary>
    public sealed record Template(string NameOrUuid) : ScanSelection;

    /// <summary>A saved policy by numeric ID. Its <c>template_uuid</c> is sent as the scan's <c>uuid</c>.</summary>
    public sealed record Policy(int PolicyId) : ScanSelection;
}

public sealed record PollingOptions
{
    public TimeSpan Interval { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>Overall deadline measured from launch.</summary>
    public TimeSpan Deadline { get; init; } = TimeSpan.FromHours(4);

    /// <summary>When false (default), a paused scan ends the run instead of waiting indefinitely.</summary>
    public bool WaitWhilePaused { get; init; }

    /// <summary>Consecutive transient polling failures tolerated before giving up.</summary>
    public int MaxConsecutiveFailures { get; init; } = 5;

    /// <summary>When true, send <c>POST /scans/{id}/stop</c> if the deadline passes or the run is cancelled.</summary>
    public bool StopScanOnAbort { get; init; }

    public void Validate()
    {
        var errors = new List<string>();
        if (Interval < TimeSpan.FromMilliseconds(1) || Interval > TimeSpan.FromHours(1))
        {
            errors.Add("Poll interval must be between 1 millisecond and 1 hour.");
        }

        if (Deadline <= TimeSpan.Zero || Deadline > TimeSpan.FromDays(7))
        {
            errors.Add("Scan timeout must be greater than zero and at most 7 days.");
        }

        if (Deadline < Interval)
        {
            errors.Add("Scan timeout must be at least as long as the poll interval.");
        }

        if (MaxConsecutiveFailures < 1)
        {
            errors.Add("Max consecutive poll failures must be at least 1.");
        }

        if (errors.Count > 0)
        {
            throw new ConfigurationException(errors);
        }
    }
}

/// <summary>Controls how findings are collected once a scan has completed.</summary>
public sealed record ResultOptions
{
    /// <summary>Fetch plugin details (solution, synopsis, risk, CVEs) once per unique plugin.</summary>
    public bool IncludePluginDetails { get; init; } = true;

    /// <summary>Lowest Nessus severity to export: 0 info, 1 low, 2 medium, 3 high, 4 critical.</summary>
    public int MinimumSeverity { get; init; }

    public void Validate()
    {
        if (MinimumSeverity is < 0 or > 4)
        {
            throw new ConfigurationException("Minimum severity must be between 0 (info) and 4 (critical).");
        }
    }
}

/// <summary>Everything needed to create, launch, monitor and export one scan.</summary>
public sealed record ScanJobOptions
{
    public required string Name { get; init; }

    public string? Description { get; init; }

    public required ScanSelection Selection { get; init; }

    /// <summary>Targets already validated against the authorised scope.</summary>
    public required IReadOnlyList<ScanTarget> Targets { get; init; }

    public int? FolderId { get; init; }

    public PollingOptions Polling { get; init; } = new();

    public ResultOptions Results { get; init; } = new();

    public void Validate()
    {
        var errors = new List<string>();
        if (string.IsNullOrWhiteSpace(Name))
        {
            errors.Add("A scan name is required (--name).");
        }
        else if (Name.Length > 200 || Name.Any(char.IsControl))
        {
            errors.Add("Scan name must be at most 200 characters with no control characters.");
        }

        if (Description is { Length: > 1000 })
        {
            errors.Add("Description must be at most 1000 characters.");
        }

        if (Targets.Count == 0)
        {
            errors.Add("At least one validated target is required.");
        }

        if (Selection is ScanSelection.Template t && string.IsNullOrWhiteSpace(t.NameOrUuid))
        {
            errors.Add("Template name or UUID must not be empty.");
        }

        if (Selection is ScanSelection.Policy p && p.PolicyId <= 0)
        {
            errors.Add("Policy ID must be a positive integer.");
        }

        if (FolderId is <= 0)
        {
            errors.Add("Folder ID must be a positive integer.");
        }

        if (errors.Count > 0)
        {
            throw new ConfigurationException(errors);
        }

        Polling.Validate();
        Results.Validate();
    }
}
