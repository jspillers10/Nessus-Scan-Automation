namespace NessusAutomation.Orchestration;

public enum ScanStatusCategory
{
    InProgress,
    Completed,
    Failed,
    Paused,
    Unknown,
}

/// <summary>
/// Maps Nessus scan status strings to lifecycle categories.
/// </summary>
/// <remarks>
/// Values are taken from Tenable's published scan-status lists (Tenable Vulnerability
/// Management / Nessus share the same vocabulary for these states). Unrecognised values are
/// reported as <see cref="ScanStatusCategory.Unknown"/>; the poller keeps waiting on them
/// but is still bounded by the overall deadline.
/// </remarks>
public static class ScanStatus
{
    private static readonly Dictionary<string, ScanStatusCategory> Map = new(StringComparer.OrdinalIgnoreCase)
    {
        ["completed"] = ScanStatusCategory.Completed,

        ["aborted"] = ScanStatusCategory.Failed,
        ["canceled"] = ScanStatusCategory.Failed,
        ["cancelled"] = ScanStatusCategory.Failed,
        ["stopped"] = ScanStatusCategory.Failed,
        // An imported scan cannot be run, so reaching it after a launch is not success.
        ["imported"] = ScanStatusCategory.Failed,

        ["paused"] = ScanStatusCategory.Paused,

        ["empty"] = ScanStatusCategory.InProgress,
        ["pending"] = ScanStatusCategory.InProgress,
        ["initializing"] = ScanStatusCategory.InProgress,
        ["running"] = ScanStatusCategory.InProgress,
        ["processing"] = ScanStatusCategory.InProgress,
        ["publishing"] = ScanStatusCategory.InProgress,
        ["resuming"] = ScanStatusCategory.InProgress,
        ["pausing"] = ScanStatusCategory.InProgress,
        ["stopping"] = ScanStatusCategory.InProgress,
    };

    public static ScanStatusCategory Classify(string? status) =>
        status is not null && Map.TryGetValue(status.Trim(), out var category) ? category : ScanStatusCategory.Unknown;
}
