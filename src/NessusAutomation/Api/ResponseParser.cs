using System.Globalization;
using System.Text.Json;

namespace NessusAutomation.Api;

/// <summary>
/// Converts Nessus JSON into typed models, failing with
/// <see cref="NessusErrorKind.MalformedResponse"/> and the exact field path when a
/// required value is missing or has the wrong type.
/// </summary>
internal sealed class ResponseParser
{
    private readonly string _method;
    private readonly string _path;

    public ResponseParser(string method, string path)
    {
        _method = method;
        _path = path;
    }

    public string ParseToken(JsonElement root) => RequireString(root, "token", "token");

    public IReadOnlyList<ScanTemplate> ParseTemplates(JsonElement root)
    {
        var templates = new List<ScanTemplate>();
        foreach (var (item, path) in RequireArray(root, "templates", "templates", allowNull: false))
        {
            templates.Add(new ScanTemplate(
                RequireString(item, "uuid", $"{path}.uuid"),
                RequireString(item, "name", $"{path}.name"),
                OptionalString(item, "title"),
                OptionalBool(item, "unsupported") ?? false));
        }

        return templates;
    }

    public IReadOnlyList<ScanPolicy> ParsePolicies(JsonElement root)
    {
        // Nessus reports "policies": null when no policies have been saved.
        var policies = new List<ScanPolicy>();
        foreach (var (item, path) in RequireArray(root, "policies", "policies", allowNull: true))
        {
            policies.Add(new ScanPolicy(
                RequireInt(item, "id", $"{path}.id"),
                OptionalString(item, "name"),
                OptionalString(item, "template_uuid")));
        }

        return policies;
    }

    public CreatedScan ParseCreatedScan(JsonElement root)
    {
        var scan = RequireObject(root, "scan", "scan");
        return new CreatedScan(
            RequireInt(scan, "id", "scan.id"),
            OptionalString(scan, "uuid"),
            OptionalString(scan, "name"));
    }

    public static string? ParseLaunch(JsonElement root) => OptionalString(root, "scan_uuid");

    public ScanDetails ParseScanDetails(JsonElement root)
    {
        var info = RequireObject(root, "info", "info");
        var status = RequireString(info, "status", "info.status");

        var hostsPresent = root.TryGetProperty("hosts", out var hostsElement) && hostsElement.ValueKind == JsonValueKind.Array;
        var hosts = new List<ScanHost>();
        foreach (var (item, path) in RequireArray(root, "hosts", "hosts", allowNull: true, allowMissing: true))
        {
            hosts.Add(new ScanHost(
                RequireInt(item, "host_id", $"{path}.host_id"),
                RequireString(item, "hostname", $"{path}.hostname")));
        }

        var history = new List<ScanHistoryEntry>();
        foreach (var (item, path) in RequireArray(root, "history", "history", allowNull: true, allowMissing: true))
        {
            history.Add(new ScanHistoryEntry(
                RequireInt(item, "history_id", $"{path}.history_id"),
                OptionalString(item, "uuid"),
                OptionalString(item, "status")));
        }

        return new ScanDetails(status, OptionalString(info, "name"), hosts, hostsPresent, history);
    }

    public HostDetails ParseHostDetails(JsonElement root)
    {
        string? ip = null;
        string? fqdn = null;
        if (root.TryGetProperty("info", out var info) && info.ValueKind == JsonValueKind.Object)
        {
            ip = OptionalString(info, "host-ip");
            fqdn = OptionalString(info, "host-fqdn");
        }

        var vulns = new List<HostVulnerability>();
        foreach (var (item, path) in RequireArray(root, "vulnerabilities", "vulnerabilities", allowNull: true))
        {
            vulns.Add(new HostVulnerability(
                RequireInt(item, "plugin_id", $"{path}.plugin_id"),
                OptionalString(item, "plugin_name"),
                OptionalString(item, "plugin_family"),
                RequireInt(item, "severity", $"{path}.severity"),
                OptionalInt(item, "count")));
        }

        return new HostDetails(ip, fqdn, vulns);
    }

    public PluginDetails ParsePluginDetails(JsonElement root, int pluginId)
    {
        var info = RequireObject(root, "info", "info");
        var description = RequireObject(info, "plugindescription", "info.plugindescription");

        string? synopsis = null, solution = null, riskFactor = null, cvss3 = null, cvss2 = null;
        var cves = new List<string>();

        if (description.TryGetProperty("pluginattributes", out var attrs) && attrs.ValueKind == JsonValueKind.Object)
        {
            synopsis = OptionalString(attrs, "synopsis");
            solution = OptionalString(attrs, "solution");

            if (attrs.TryGetProperty("risk_information", out var risk) && risk.ValueKind == JsonValueKind.Object)
            {
                riskFactor = OptionalString(risk, "risk_factor");
                cvss3 = OptionalScalar(risk, "cvss3_base_score");
                cvss2 = OptionalScalar(risk, "cvss_base_score");
            }

            if (attrs.TryGetProperty("ref_information", out var refs) && refs.ValueKind == JsonValueKind.Object
                && refs.TryGetProperty("ref", out var refList) && refList.ValueKind == JsonValueKind.Array)
            {
                foreach (var reference in refList.EnumerateArray())
                {
                    if (reference.ValueKind != JsonValueKind.Object
                        || !string.Equals(OptionalString(reference, "name"), "cve", StringComparison.OrdinalIgnoreCase)
                        || !reference.TryGetProperty("values", out var values) || values.ValueKind != JsonValueKind.Object
                        || !values.TryGetProperty("value", out var valueList))
                    {
                        continue;
                    }

                    if (valueList.ValueKind == JsonValueKind.Array)
                    {
                        cves.AddRange(valueList.EnumerateArray().Where(v => v.ValueKind == JsonValueKind.String).Select(v => v.GetString()!));
                    }
                    else if (valueList.ValueKind == JsonValueKind.String)
                    {
                        cves.Add(valueList.GetString()!);
                    }
                }
            }
        }

        return new PluginDetails(pluginId, synopsis, solution, riskFactor, cvss3, cvss2, cves.Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.Ordinal).ToList());
    }

    private NessusApiException Malformed(string detail) =>
        new(NessusErrorKind.MalformedResponse, $"{_method} {_path}: malformed response: {detail}", _method, _path);

    private JsonElement RequireObject(JsonElement parent, string name, string path)
    {
        if (parent.ValueKind != JsonValueKind.Object || !parent.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.Object)
        {
            throw Malformed($"required object '{path}' is missing or not an object.");
        }

        return value;
    }

    private IEnumerable<(JsonElement Item, string Path)> RequireArray(JsonElement parent, string name, string path, bool allowNull, bool allowMissing = false)
    {
        if (parent.ValueKind != JsonValueKind.Object)
        {
            throw Malformed("response body is not a JSON object.");
        }

        if (!parent.TryGetProperty(name, out var value))
        {
            if (allowMissing)
            {
                return [];
            }

            throw Malformed($"required array '{path}' is missing.");
        }

        if (value.ValueKind == JsonValueKind.Null && allowNull)
        {
            return [];
        }

        if (value.ValueKind != JsonValueKind.Array)
        {
            throw Malformed($"'{path}' is not an array.");
        }

        return value.EnumerateArray().Select((item, i) =>
            item.ValueKind == JsonValueKind.Object ? (item, $"{path}[{i}]") : throw Malformed($"'{path}[{i}]' is not an object."));
    }

    private string RequireString(JsonElement parent, string name, string path)
    {
        if (parent.ValueKind == JsonValueKind.Object && parent.TryGetProperty(name, out var value)
            && value.ValueKind == JsonValueKind.String && !string.IsNullOrEmpty(value.GetString()))
        {
            return value.GetString()!;
        }

        throw Malformed($"required string '{path}' is missing or empty.");
    }

    private int RequireInt(JsonElement parent, string name, string path) =>
        OptionalInt(parent, name) ?? throw Malformed($"required integer '{path}' is missing or not an integer.");

    private static int? OptionalInt(JsonElement parent, string name)
    {
        if (!parent.TryGetProperty(name, out var value))
        {
            return null;
        }

        return value.ValueKind switch
        {
            JsonValueKind.Number when value.TryGetInt32(out var n) => n,
            JsonValueKind.String when int.TryParse(value.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) => n,
            _ => null,
        };
    }

    private static string? OptionalString(JsonElement parent, string name) =>
        parent.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static string? OptionalScalar(JsonElement parent, string name)
    {
        if (!parent.TryGetProperty(name, out var value))
        {
            return null;
        }

        return value.ValueKind switch
        {
            JsonValueKind.String => value.GetString(),
            JsonValueKind.Number => value.GetRawText(),
            _ => null,
        };
    }

    private static bool? OptionalBool(JsonElement parent, string name) =>
        parent.TryGetProperty(name, out var value) && value.ValueKind is JsonValueKind.True or JsonValueKind.False ? value.GetBoolean() : null;
}
