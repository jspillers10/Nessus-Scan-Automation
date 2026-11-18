namespace NessusAutomation.Configuration;

/// <summary>Raised for invalid user-supplied configuration. Never contains secret values.</summary>
public sealed class ConfigurationException : Exception
{
    public ConfigurationException(string message)
        : base(message)
    {
    }

    public ConfigurationException(IReadOnlyList<string> errors)
        : base(string.Join(Environment.NewLine, errors))
    {
        Errors = errors;
    }

    public ConfigurationException()
    {
    }

    public ConfigurationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    public IReadOnlyList<string> Errors { get; } = [];
}

/// <summary>Credentials for the Nessus REST API. Exactly one mechanism is used per client.</summary>
public abstract record NessusCredentials
{
    private NessusCredentials()
    {
    }

    /// <summary>Username/password exchanged for a session token via <c>POST /session</c>.</summary>
    public sealed record UserPassword(string Username, string Password) : NessusCredentials
    {
        // Records generate ToString with every property; never print the password.
        public override string ToString() => $"UserPassword(Username={Username}, Password=***)";
    }

    /// <summary>API keys sent in the <c>X-ApiKeys</c> header. No session is created.</summary>
    public sealed record ApiKeys(string AccessKey, string SecretKey) : NessusCredentials
    {
        public override string ToString() => "ApiKeys(AccessKey=***, SecretKey=***)";
    }
}

public enum TlsValidationMode
{
    /// <summary>Operating-system trust store and hostname validation (default).</summary>
    System,

    /// <summary>Chain must terminate at a caller-supplied CA/self-signed certificate; hostname still validated.</summary>
    CustomRoot,

    /// <summary>No certificate validation. Lab use only; scoped to a single client instance.</summary>
    InsecureSkipVerify,
}

public sealed record TlsOptions
{
    public TlsValidationMode Mode { get; init; } = TlsValidationMode.System;

    /// <summary>PEM or DER file holding one or more trusted root certificates (for <see cref="TlsValidationMode.CustomRoot"/>).</summary>
    public string? CaCertificatePath { get; init; }
}

public sealed record RetryOptions
{
    /// <summary>Total attempts for retry-safe requests, including the first.</summary>
    public int MaxAttempts { get; init; } = 3;

    public TimeSpan BaseDelay { get; init; } = TimeSpan.FromSeconds(1);

    public TimeSpan MaxDelay { get; init; } = TimeSpan.FromSeconds(15);
}

public sealed record NessusConnectionOptions
{
    public required Uri BaseUri { get; init; }

    public required NessusCredentials Credentials { get; init; }

    /// <summary>Upper bound for a single HTTP request attempt.</summary>
    public TimeSpan RequestTimeout { get; init; } = TimeSpan.FromSeconds(60);

    public TlsOptions Tls { get; init; } = new();

    public RetryOptions Retry { get; init; } = new();

    /// <summary>
    /// Validates a Nessus base URL. HTTPS is required because credentials and session
    /// tokens are sent on every request.
    /// </summary>
    public static Uri ParseBaseUri(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ConfigurationException("A Nessus server URL is required (--url or NESSUS_URL), e.g. https://nessus.lab.example:8834.");
        }

        if (!Uri.TryCreate(value.Trim(), UriKind.Absolute, out var uri))
        {
            throw new ConfigurationException($"'{value}' is not a valid absolute URL.");
        }

        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new ConfigurationException("The Nessus URL must use https://. Plain HTTP would expose credentials and session tokens.");
        }

        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            throw new ConfigurationException("Do not embed credentials in the URL. Use NESSUS_USERNAME/NESSUS_PASSWORD or NESSUS_ACCESS_KEY/NESSUS_SECRET_KEY.");
        }

        if (!string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
        {
            throw new ConfigurationException("The Nessus URL must not contain a query string or fragment.");
        }

        // Normalise so relative API paths append cleanly ("https://host:8834/" + "scans").
        var builder = new UriBuilder(uri);
        if (!builder.Path.EndsWith('/'))
        {
            builder.Path += "/";
        }

        return builder.Uri;
    }

    public void Validate()
    {
        var errors = new List<string>();

        if (RequestTimeout <= TimeSpan.Zero || RequestTimeout > TimeSpan.FromMinutes(10))
        {
            errors.Add("Request timeout must be between 1 second and 10 minutes.");
        }

        if (Retry.MaxAttempts is < 1 or > 10)
        {
            errors.Add("Retry attempts must be between 1 and 10.");
        }

        if (Retry.BaseDelay < TimeSpan.Zero || Retry.MaxDelay < Retry.BaseDelay)
        {
            errors.Add("Retry delays must be non-negative and MaxDelay must be >= BaseDelay.");
        }

        switch (Tls.Mode)
        {
            case TlsValidationMode.CustomRoot when string.IsNullOrWhiteSpace(Tls.CaCertificatePath):
                errors.Add("A CA certificate path is required when trusting a custom root.");
                break;
            case TlsValidationMode.CustomRoot when !File.Exists(Tls.CaCertificatePath):
                errors.Add($"CA certificate file not found: {Tls.CaCertificatePath}");
                break;
            case TlsValidationMode.System or TlsValidationMode.InsecureSkipVerify when Tls.CaCertificatePath is not null:
                errors.Add("A CA certificate path is only valid in custom-root mode.");
                break;
        }

        switch (Credentials)
        {
            case NessusCredentials.UserPassword up when string.IsNullOrEmpty(up.Username) || string.IsNullOrEmpty(up.Password):
                errors.Add("Username and password must both be non-empty.");
                break;
            case NessusCredentials.ApiKeys keys when string.IsNullOrEmpty(keys.AccessKey) || string.IsNullOrEmpty(keys.SecretKey):
                errors.Add("Access key and secret key must both be non-empty.");
                break;
        }

        if (errors.Count > 0)
        {
            throw new ConfigurationException(errors);
        }
    }
}
