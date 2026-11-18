using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using NessusAutomation.Configuration;
using NessusAutomation.Security;

namespace NessusAutomation.Http;

/// <summary>
/// Builds the per-client HTTP handler. Certificate policy lives on the handler instance
/// only; nothing here touches process-wide settings such as
/// <c>ServicePointManager.ServerCertificateValidationCallback</c>.
/// </summary>
public static class NessusHttpHandlerFactory
{
    public static SocketsHttpHandler Create(TlsOptions tls, IAppLog log)
    {
        ArgumentNullException.ThrowIfNull(tls);
        ArgumentNullException.ThrowIfNull(log);

        var handler = new SocketsHttpHandler
        {
            // A redirect would resend the X-Cookie / X-ApiKeys header to another location.
            AllowAutoRedirect = false,
            UseCookies = false,
            UseProxy = true,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            ConnectTimeout = TimeSpan.FromSeconds(15),
        };

        switch (tls.Mode)
        {
            case TlsValidationMode.System:
                // Leave RemoteCertificateValidationCallback null: platform chain + hostname validation.
                break;

            case TlsValidationMode.CustomRoot:
                var roots = LoadCertificates(tls.CaCertificatePath!);
                handler.SslOptions.RemoteCertificateValidationCallback =
                    (_, certificate, _, errors) => ValidateAgainstCustomRoots(certificate as X509Certificate2, errors, roots);
                log.Info($"TLS: trusting {roots.Count} custom root certificate(s) from {tls.CaCertificatePath}; hostname validation remains enabled.");
                break;

            case TlsValidationMode.InsecureSkipVerify:
                // Deliberate, opt-in lab bypass. It is attached to this handler only, never to a
                // process-wide callback, and is announced on stderr every time a client is built.
#pragma warning disable CA5359
                handler.SslOptions.RemoteCertificateValidationCallback = (_, _, _, _) => true;
#pragma warning restore CA5359
                log.Warn("TLS CERTIFICATE VERIFICATION IS DISABLED for this Nessus client (--insecure-skip-tls-verify). " +
                         "Credentials could be intercepted by anyone able to impersonate the server. Use only on an isolated lab network; prefer --ca-cert.");
                break;

            default:
                throw new ConfigurationException($"Unsupported TLS mode {tls.Mode}.");
        }

        return handler;
    }

    /// <summary>
    /// Accepts a server certificate only if the hostname matched and the chain builds to
    /// one of <paramref name="roots"/>. The operating-system store is deliberately not
    /// consulted in this mode, so the supplied roots are the only trust anchors. Revocation is not checked because lab CAs rarely
    /// publish CRL/OCSP endpoints.
    /// </summary>
    internal static bool ValidateAgainstCustomRoots(X509Certificate2? certificate, SslPolicyErrors errors, X509Certificate2Collection roots)
    {
        if (certificate is null)
        {
            return false;
        }

        if (errors.HasFlag(SslPolicyErrors.RemoteCertificateNotAvailable) || errors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch))
        {
            return false;
        }

        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.AddRange(roots);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        return chain.Build(certificate);
    }

    internal static X509Certificate2Collection LoadCertificates(string path)
    {
        var collection = new X509Certificate2Collection();
        try
        {
            var text = File.ReadAllText(path);
            if (text.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))
            {
                collection.ImportFromPem(text);
            }
            else
            {
                collection.Add(X509CertificateLoader.LoadCertificateFromFile(path));
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException)
        {
            throw new ConfigurationException($"Could not load CA certificate(s) from {path}: {ex.Message}", ex);
        }

        if (collection.Count == 0)
        {
            throw new ConfigurationException($"No certificates found in {path}.");
        }

        return collection;
    }
}
