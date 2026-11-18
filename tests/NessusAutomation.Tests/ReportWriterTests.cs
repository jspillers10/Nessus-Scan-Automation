using System.Text;
using System.Text.Json;
using NessusAutomation.Configuration;
using NessusAutomation.Export;
using NessusAutomation.Security;

namespace NessusAutomation.Tests;

public sealed class ReportWriterTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("nessus-export-tests").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private static Finding Finding(int pluginId, int severity, string? name = "Plugin", string? solution = "Patch it.", string host = "192.0.2.10") => new(
        FindingKey: $"{host}|{pluginId}",
        ScanId: 42,
        HistoryId: 7,
        HostId: 1,
        Host: host,
        HostIp: "192.0.2.10",
        HostFqdn: null,
        PluginId: pluginId,
        PluginName: name,
        PluginFamily: "General",
        Severity: severity,
        SeverityLabel: Severity.Label(severity),
        Count: 1,
        RiskFactor: "High",
        Cvss3BaseScore: "7.5",
        CvssBaseScore: null,
        Cves: ["CVE-2099-0001", "CVE-2099-0002"],
        Synopsis: "Synopsis",
        Solution: solution);

    private static ScanReport Report(IReadOnlyList<Finding> findings, IReadOnlyList<string>? warnings = null) => new(
        new ScanReportMetadata(42, 7, "run-uuid", "Lab scan", "completed", "nessus.lab.test:8834", ["192.0.2.10"], "template 'basic'",
            new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero), true, 0),
        2,
        findings,
        warnings ?? []);

    [Fact]
    public void Json_export_contains_identifiers_counts_and_remediation()
    {
        using var stream = new MemoryStream();
        ReportWriter.WriteJson(Report([Finding(201000, 4), Finding(57582, 2)]), stream, new SecretRedactor());
        using var doc = JsonDocument.Parse(stream.ToArray());
        var root = doc.RootElement;

        Assert.Equal("succeeded", root.GetProperty("retrieval_status").GetString());
        Assert.Equal(42, root.GetProperty("scan").GetProperty("scan_id").GetInt32());
        Assert.Equal(7, root.GetProperty("scan").GetProperty("history_id").GetInt32());
        Assert.Equal("2026-01-02T03:04:05Z", root.GetProperty("generated_at_utc").GetString());
        Assert.Equal(2, root.GetProperty("finding_count").GetInt32());
        Assert.Equal(1, root.GetProperty("severity_counts").GetProperty("critical").GetInt32());
        Assert.Equal(1, root.GetProperty("severity_counts").GetProperty("medium").GetInt32());

        var first = root.GetProperty("findings")[0];
        Assert.Equal("192.0.2.10|201000", first.GetProperty("finding_key").GetString());
        Assert.Equal(201000, first.GetProperty("plugin_id").GetInt32());
        Assert.Equal("Critical", first.GetProperty("severity_label").GetString());
        Assert.Equal("Patch it.", first.GetProperty("solution").GetString());
        Assert.Equal(2, first.GetProperty("cves").GetArrayLength());
        Assert.Equal(JsonValueKind.Null, first.GetProperty("host_fqdn").ValueKind);
    }

    [Fact]
    public void Empty_results_are_explicitly_successful_with_zero_findings()
    {
        using var stream = new MemoryStream();
        ReportWriter.WriteJson(Report([]), stream, new SecretRedactor());
        using var doc = JsonDocument.Parse(stream.ToArray());

        Assert.Equal("succeeded", doc.RootElement.GetProperty("retrieval_status").GetString());
        Assert.Equal(0, doc.RootElement.GetProperty("finding_count").GetInt32());
        Assert.Equal(0, doc.RootElement.GetProperty("findings").GetArrayLength());

        using var csv = new MemoryStream();
        ReportWriter.WriteCsv(Report([]), csv);
        Assert.Equal(string.Join(',', ReportWriter.CsvColumns) + "\r\n", Encoding.UTF8.GetString(csv.ToArray()));
    }

    [Fact]
    public void Warnings_in_json_are_redacted()
    {
        var redactor = new SecretRedactor();
        redactor.Register("leaky-session-token");
        using var stream = new MemoryStream();
        ReportWriter.WriteJson(Report([], ["server echoed leaky-session-token"]), stream, redactor);
        var text = Encoding.UTF8.GetString(stream.ToArray());
        Assert.DoesNotContain("leaky-session-token", text, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("plain", "plain")]
    [InlineData("a,b", "\"a,b\"")]
    [InlineData("say \"hi\"", "\"say \"\"hi\"\"\"")]
    [InlineData("line1\nline2", "\"line1\nline2\"")]
    [InlineData("cr\r\nlf", "\"cr\r\nlf\"")]
    [InlineData(" padded ", "\" padded \"")]
    [InlineData("", "")]
    [InlineData(null, "")]
    public void Csv_fields_are_rfc4180_escaped(string? input, string expected) =>
        Assert.Equal(expected, ReportWriter.EscapeCsvField(input));

    [Theory]
    [InlineData("=1+1", "'=1+1")]
    [InlineData("+cmd", "'+cmd")]
    [InlineData("-2", "'-2")]
    [InlineData("@SUM(A1)", "'@SUM(A1)")]
    [InlineData("\tTab", "'\tTab")]
    [InlineData("Safe text", "Safe text")]
    public void Csv_text_cells_are_protected_from_formula_injection(string input, string expected) =>
        Assert.Equal(expected, ReportWriter.NeutraliseFormula(input));

    [Fact]
    public void Csv_rows_round_trip_with_embedded_commas_quotes_and_newlines()
    {
        var finding = Finding(201000, 4, name: "=HYPERLINK(\"http://attacker.example\")", solution: "Upgrade, then \"restart\"\nservice.");
        using var stream = new MemoryStream();
        ReportWriter.WriteCsv(Report([finding]), stream);
        var csv = Encoding.UTF8.GetString(stream.ToArray());

        var rows = ParseCsv(csv);
        Assert.Equal(2, rows.Count);
        Assert.Equal(ReportWriter.CsvColumns, rows[0]);
        var row = rows[1];
        Assert.Equal(ReportWriter.CsvColumns.Count, row.Count);
        Assert.Equal("'=HYPERLINK(\"http://attacker.example\")", row[ReportWriter.CsvColumns.ToList().IndexOf("plugin_name")]);
        Assert.Equal("Upgrade, then \"restart\"\nservice.", row[ReportWriter.CsvColumns.ToList().IndexOf("solution")]);
        Assert.Equal("CVE-2099-0001;CVE-2099-0002", row[ReportWriter.CsvColumns.ToList().IndexOf("cves")]);
        Assert.Equal("4", row[ReportWriter.CsvColumns.ToList().IndexOf("severity")]);
        Assert.Equal("", row[ReportWriter.CsvColumns.ToList().IndexOf("cvss_base_score")]);
    }

    [Fact]
    public void WriteAll_writes_both_files_and_refuses_to_clobber_without_overwrite()
    {
        var paths = ExportPaths.FromPrefix(Path.Combine(_dir, "lab"));
        paths.EnsureWritable(overwrite: false);
        ReportWriter.WriteAll(Report([Finding(1, 1)]), paths, new SecretRedactor());

        Assert.True(File.Exists(paths.JsonPath));
        Assert.True(File.Exists(paths.CsvPath));
        Assert.Empty(Directory.GetFiles(_dir, "*.tmp-*"));
        Assert.Throws<ConfigurationException>(() => paths.EnsureWritable(overwrite: false));
        paths.EnsureWritable(overwrite: true);
    }

    [Fact]
    public void Missing_output_directory_is_rejected_early()
    {
        var paths = ExportPaths.FromPrefix(Path.Combine(_dir, "does-not-exist", "lab"));
        Assert.Throws<ConfigurationException>(() => paths.EnsureWritable(overwrite: false));
    }

    /// <summary>Minimal RFC 4180 reader used only to verify the writer.</summary>
    private static List<List<string>> ParseCsv(string text)
    {
        var rows = new List<List<string>>();
        var row = new List<string>();
        var field = new StringBuilder();
        var quoted = false;
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (quoted)
            {
                if (c == '"' && i + 1 < text.Length && text[i + 1] == '"')
                {
                    field.Append('"');
                    i++;
                }
                else if (c == '"')
                {
                    quoted = false;
                }
                else
                {
                    field.Append(c);
                }
            }
            else if (c == '"')
            {
                quoted = true;
            }
            else if (c == ',')
            {
                row.Add(field.ToString());
                field.Clear();
            }
            else if (c == '\r' && i + 1 < text.Length && text[i + 1] == '\n')
            {
                row.Add(field.ToString());
                field.Clear();
                rows.Add(row);
                row = [];
                i++;
            }
            else
            {
                field.Append(c);
            }
        }

        return rows;
    }
}
