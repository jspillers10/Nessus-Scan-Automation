using NessusAutomation.Cli;

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    // First Ctrl+C requests graceful cancellation (session logout, optional scan stop);
    // a second one terminates the process immediately.
    if (!cts.IsCancellationRequested)
    {
        e.Cancel = true;
        Console.Error.WriteLine("Cancellation requested; cleaning up. Press Ctrl+C again to force exit.");
        cts.Cancel();
    }
};

var app = new CliApp(Console.Out, Console.Error, Environment.GetEnvironmentVariable);
return await app.RunAsync(args, cts.Token).ConfigureAwait(false);
