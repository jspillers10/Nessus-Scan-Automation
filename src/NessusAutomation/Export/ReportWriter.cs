using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using NessusAutomation.Configuration;
using NessusAutomation.Security;

namespace NessusAutomation.Export;

public sealed record ExportPaths(string JsonPath, string CsvPath)
{
    public static ExportPaths FromPrefix(string prefix)
    {
        if (string.IsNullOrWhiteSpace(prefix))
        {
            throw new ConfigurationException("An output path prefix is required (--output), e.g. out/lab-scan.");
        }

        var full = Path.GetFullPath(prefix);
        return new ExportPaths(full + ".findings.json", full + ".findings.csv");
    }

    /// <summary>Fails early so a long scan does not end with an unwritable or clobbered output.</summary>
    public void EnsureWritable(bool overwrite)
    {
        foreach (var path in new[] { JsonPath, CsvPath })
        {
            if (File.Exists(path) && !overwrite)
            {
                throw new ConfigurationException($"Output file already exists: {path}. Choose another --output or pass --overwrite.");
            }

            var directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                throw new ConfigurationException($"Output directory does not exist: {directory}");
            }
        }
    }
}

/// <summary>Writes JSON and CSV vulnerability exports.</summary>
public static class ReportWriter
{
    public static readonly IReadOnlyList<string> CsvColumns =
    [
        "finding_key", "scan_id", "history_id", "host_id", "host", "host_ip", "host_fqdn",
        "plugin_id", "plugin_name", "plugin_family", "severity", "severity_label", "count",
        "risk_factor", "cvss3_base_score", "cvss_base_score", "cves", "synopsis", "solution",
    ];

    private static readonly JsonWriterOptions JsonOptions = new()
    {
        Indented = true,
        // Keep non-ASCII plugin text readable; output is a file, not HTML.
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    private static readonly UTF8Encoding Utf8NoBom = new(encoderShouldEmitUTF8Identifier: false);

    /// <summary>Writes both files via temp files + rename so a failure never leaves a partial export.</summary>
    public static void WriteAll(ScanReport report, ExportPaths paths, SecretRedactor redactor)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentNullException.ThrowIfNull(paths);
        WriteAtomically(paths.JsonPath, stream => WriteJson(report, stream, redactor));
        WriteAtomically(paths.CsvPath, stream => WriteCsv(report, stream));
    }

    public static void WriteJson(ScanReport report, Stream stream, SecretRedactor redactor)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentNullException.ThrowIfNull(redactor);
        using var w = new Utf8JsonWriter(stream, JsonOptions);
        var m = report.Metadata;

        w.WriteStartObject();
        w.WriteString("schema", "nessus-scan-automation/findings/v1");
        w.WriteString("retrieval_status", "succeeded");

        w.WriteStartObject("scan");
        w.WriteNumber("scan_id", m.ScanId);
        WriteNullableNumber(w, "history_id", m.HistoryId);
        w.WriteString("scan_uuid", m.ScanUuid);
        w.WriteString("name", m.ScanName);
        w.WriteString("status", m.Status);
        w.WriteString("server", m.ServerHost);
        w.WriteString("selection", m.Selection);
        if (m.Targets is null)
        {
            w.WriteNull("targets");
        }
        else
        {
            w.WriteStartArray("targets");
            foreach (var t in m.Targets)
            {
                w.WriteStringValue(t);
            }

            w.WriteEndArray();
        }

        w.WriteEndObject();

        w.WriteString("generated_at_utc", m.GeneratedAtUtc.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture));
        w.WriteBoolean("plugin_details_included", m.PluginDetailsIncluded);
        w.WriteString("minimum_severity", Severity.Label(m.MinimumSeverity));
        w.WriteNumber("host_count", report.HostCount);
        w.WriteNumber("finding_count", report.Findings.Count);

        w.WriteStartObject("severity_counts");
        foreach (var (label, count) in report.SeverityCounts)
        {
            w.WriteNumber(label.ToLowerInvariant(), count);
        }

        w.WriteEndObject();

        w.WriteStartArray("warnings");
        foreach (var warning in report.Warnings)
        {
            w.WriteStringValue(redactor.Redact(warning));
        }

        w.WriteEndArray();

        w.WriteStartArray("findings");
        foreach (var f in report.Findings)
        {
            w.WriteStartObject();
            w.WriteString("finding_key", f.FindingKey);
            w.WriteNumber("scan_id", f.ScanId);
            WriteNullableNumber(w, "history_id", f.HistoryId);
            w.WriteNumber("host_id", f.HostId);
            w.WriteString("host", f.Host);
            w.WriteString("host_ip", f.HostIp);
            w.WriteString("host_fqdn", f.HostFqdn);
            w.WriteNumber("plugin_id", f.PluginId);
            w.WriteString("plugin_name", f.PluginName);
            w.WriteString("plugin_family", f.PluginFamily);
            w.WriteNumber("severity", f.Severity);
            w.WriteString("severity_label", f.SeverityLabel);
            WriteNullableNumber(w, "count", f.Count);
            w.WriteString("risk_factor", f.RiskFactor);
            w.WriteString("cvss3_base_score", f.Cvss3BaseScore);
            w.WriteString("cvss_base_score", f.CvssBaseScore);
            w.WriteStartArray("cves");
            foreach (var cve in f.Cves)
            {
                w.WriteStringValue(cve);
            }

            w.WriteEndArray();
            w.WriteString("synopsis", f.Synopsis);
            w.WriteString("solution", f.Solution);
            w.WriteEndObject();
        }

        w.WriteEndArray();
        w.WriteEndObject();
        w.Flush();
    }

    public static void WriteCsv(ScanReport report, Stream stream)
    {
        ArgumentNullException.ThrowIfNull(report);
        using var writer = new StreamWriter(stream, Utf8NoBom, leaveOpen: true) { NewLine = "\r\n" };
        writer.WriteLine(string.Join(',', CsvColumns));

        foreach (var f in report.Findings)
        {
            string?[] row =
            [
                Text(f.FindingKey), Num(f.ScanId), Num(f.HistoryId), Num(f.HostId), Text(f.Host), Text(f.HostIp), Text(f.HostFqdn),
                Num(f.PluginId), Text(f.PluginName), Text(f.PluginFamily), Num(f.Severity), Text(f.SeverityLabel), Num(f.Count),
                Text(f.RiskFactor), Text(f.Cvss3BaseScore), Text(f.CvssBaseScore), Text(string.Join(';', f.Cves)),
                Text(f.Synopsis), Text(f.Solution),
            ];
            writer.WriteLine(string.Join(',', row.Select(EscapeCsvField)));
        }

        writer.Flush();
    }

    /// <summary>RFC 4180 quoting: fields containing a comma, quote, CR or LF are quoted and quotes doubled.</summary>
    public static string EscapeCsvField(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        var needsQuotes = value.AsSpan().IndexOfAny(",\"\r\n") >= 0 || value[0] == ' ' || value[^1] == ' ';
        return needsQuotes ? $"\"{value.Replace("\"", "\"\"", StringComparison.Ordinal)}\"" : value;
    }

    /// <summary>
    /// Neutralises spreadsheet formula injection: plugin text is attacker-influenced (it can
    /// echo banners from scanned hosts), so text cells starting with = + - @ tab or CR are
    /// prefixed with an apostrophe. Numeric columns are written unmodified.
    /// </summary>
    public static string? NeutraliseFormula(string? value) =>
        !string.IsNullOrEmpty(value) && value[0] is '=' or '+' or '-' or '@' or '\t' or '\r' ? "'" + value : value;

    private static string? Text(string? value) => NeutraliseFormula(value);

    private static string? Num(int? value) => value?.ToString(CultureInfo.InvariantCulture);

    private static void WriteNullableNumber(Utf8JsonWriter w, string name, int? value)
    {
        if (value is { } v)
        {
            w.WriteNumber(name, v);
        }
        else
        {
            w.WriteNull(name);
        }
    }

    private static void WriteAtomically(string path, Action<Stream> write)
    {
        var temp = path + ".tmp-" + Guid.NewGuid().ToString("N")[..8];
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                write(stream);
            }

            File.Move(temp, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temp))
            {
                File.Delete(temp);
            }
        }
    }
}
