namespace NessusAutomation.Export;

public static class Severity
{
    public static string Label(int severity) => severity switch
    {
        0 => "Info",
        1 => "Low",
        2 => "Medium",
        3 => "High",
        4 => "Critical",
        _ => $"Unknown({severity})",
    };

    public static int Parse(string value) => value.Trim().ToUpperInvariant() switch
    {
        "0" or "INFO" => 0,
        "1" or "LOW" => 1,
        "2" or "MEDIUM" => 2,
        "3" or "HIGH" => 3,
        "4" or "CRITICAL" => 4,
        _ => throw new Configuration.ConfigurationException($"Unknown severity '{value}'. Use info, low, medium, high or critical."),
    };
}

/// <summary>One plugin result on one host.</summary>
/// <param name="FindingKey">Stable identifier across scans: lower-cased host + plugin ID.</param>
public sealed record Finding(
    string FindingKey,
    int ScanId,
    int? HistoryId,
    int HostId,
    string Host,
    string? HostIp,
    string? HostFqdn,
    int PluginId,
    string? PluginName,
    string? PluginFamily,
    int Severity,
    string SeverityLabel,
    int? Count,
    string? RiskFactor,
    string? Cvss3BaseScore,
    string? CvssBaseScore,
    IReadOnlyList<string> Cves,
    string? Synopsis,
    string? Solution);

public sealed record ScanReportMetadata(
    int ScanId,
    int? HistoryId,
    string? ScanUuid,
    string? ScanName,
    string Status,
    string ServerHost,
    IReadOnlyList<string>? Targets,
    string? Selection,
    DateTimeOffset GeneratedAtUtc,
    bool PluginDetailsIncluded,
    int MinimumSeverity);

/// <summary>
/// Results of a successful retrieval. A report always means retrieval succeeded; zero
/// <see cref="Findings"/> means Nessus reported nothing at or above the minimum severity.
/// Retrieval failures surface as exceptions and never produce a report.
/// </summary>
public sealed record ScanReport(
    ScanReportMetadata Metadata,
    int HostCount,
    IReadOnlyList<Finding> Findings,
    IReadOnlyList<string> Warnings)
{
    public IReadOnlyDictionary<string, int> SeverityCounts =>
        Enumerable.Range(0, 5).Reverse().ToDictionary(
            s => Severity.Label(s),
            s => Findings.Count(f => f.Severity == s));
}
