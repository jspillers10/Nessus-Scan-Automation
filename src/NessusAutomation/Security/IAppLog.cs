namespace NessusAutomation.Security;

/// <summary>Minimal logging surface. Implementations must redact secrets.</summary>
public interface IAppLog
{
    void Info(string message);

    void Warn(string message);

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Naming", "CA1716", Justification = "Error is the clearest name; this library is consumed from C# only.")]
    void Error(string message);
}

/// <summary>Writes timestamped, redacted log lines to a <see cref="TextWriter"/> (stderr in the CLI).</summary>
public sealed class RedactingLog : IAppLog
{
    private readonly TextWriter _writer;
    private readonly SecretRedactor _redactor;
    private readonly TimeProvider _time;
    private readonly Lock _gate = new();

    public RedactingLog(TextWriter writer, SecretRedactor redactor, TimeProvider? time = null)
    {
        _writer = writer;
        _redactor = redactor;
        _time = time ?? TimeProvider.System;
    }

    public void Info(string message) => Write("INFO", message);

    public void Warn(string message) => Write("WARN", message);

    public void Error(string message) => Write("ERROR", message);

    private void Write(string level, string message)
    {
        var line = $"{_time.GetUtcNow():yyyy-MM-ddTHH:mm:ssZ} [{level}] {_redactor.Redact(message)}";
        lock (_gate)
        {
            _writer.WriteLine(line);
            _writer.Flush();
        }
    }
}
