using NessusAutomation.Export;

namespace NessusAutomation.Orchestration;

public enum ScanOutcome
{
    Completed,
    Failed,
    Paused,
    DeadlineExceeded,
    Cancelled,
}

public enum ScanStage
{
    ResolveSelection,
    Create,
    Launch,
}

/// <summary>Outcome of <see cref="ScanOrchestrator.WaitForCompletionAsync"/>.</summary>
public sealed record PollResult(ScanOutcome Outcome, string? LastStatus, int? HistoryId);

/// <summary>Outcome of a full create → launch → poll → collect run.</summary>
public sealed record ScanRunResult(
    ScanOutcome Outcome,
    int ScanId,
    string? ScanUuid,
    int? HistoryId,
    string? FinalStatus,
    ScanReport? Report,
    bool StopRequested,
    string Message);

/// <summary>
/// A create/launch step failed. <see cref="ScanId"/> is set when a scan object exists on
/// the server so the operator can inspect or delete it instead of re-running blindly.
/// </summary>
public sealed class ScanLifecycleException : Exception
{
    public ScanLifecycleException(ScanStage stage, int? scanId, string message, Exception? innerException)
        : base(message, innerException)
    {
        Stage = stage;
        ScanId = scanId;
    }

    public ScanLifecycleException()
    {
    }

    public ScanLifecycleException(string message)
        : base(message)
    {
    }

    public ScanLifecycleException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    public ScanStage Stage { get; }

    public int? ScanId { get; }
}

/// <summary>Resolved template/policy that will be sent in <c>POST /scans</c>.</summary>
public sealed record ResolvedSelection(string TemplateUuid, int? PolicyId, string Description);
