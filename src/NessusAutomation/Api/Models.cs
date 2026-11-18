namespace NessusAutomation.Api;

/// <summary>Entry from <c>GET /editor/scan/templates</c>.</summary>
public sealed record ScanTemplate(string Uuid, string Name, string? Title, bool Unsupported);

/// <summary>Entry from <c>GET /policies</c>.</summary>
public sealed record ScanPolicy(int Id, string? Name, string? TemplateUuid);

/// <summary>The <c>scan</c> object returned by <c>POST /scans</c>.</summary>
public sealed record CreatedScan(int Id, string? Uuid, string? Name);

/// <summary>Body for <c>POST /scans</c>. Only fields documented by Tenable are sent.</summary>
public sealed record CreateScanRequest(
    string TemplateUuid,
    string Name,
    string? Description,
    string TextTargets,
    int? PolicyId,
    int? FolderId);

public sealed record ScanHistoryEntry(int HistoryId, string? Uuid, string? Status);

public sealed record ScanHost(int HostId, string Hostname);

/// <summary>Subset of <c>GET /scans/{id}</c> used for polling and result collection.</summary>
public sealed record ScanDetails(
    string Status,
    string? Name,
    IReadOnlyList<ScanHost> Hosts,
    bool HostsFieldPresent,
    IReadOnlyList<ScanHistoryEntry> History);

public sealed record HostVulnerability(int PluginId, string? PluginName, string? PluginFamily, int Severity, int? Count);

/// <summary>Subset of <c>GET /scans/{id}/hosts/{host_id}</c>.</summary>
public sealed record HostDetails(string? HostIp, string? HostFqdn, IReadOnlyList<HostVulnerability> Vulnerabilities);

/// <summary>
/// Subset of <c>GET /scans/{id}/hosts/{host_id}/plugins/{plugin_id}</c>
/// (<c>info.plugindescription.pluginattributes</c>). Every field is optional because the
/// API does not populate them for every plugin.
/// </summary>
public sealed record PluginDetails(
    int PluginId,
    string? Synopsis,
    string? Solution,
    string? RiskFactor,
    string? Cvss3BaseScore,
    string? CvssBaseScore,
    IReadOnlyList<string> Cves);
