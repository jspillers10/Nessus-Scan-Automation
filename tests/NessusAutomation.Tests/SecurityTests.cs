using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using NessusAutomation.Configuration;
using NessusAutomation.Http;
using NessusAutomation.Security;

namespace NessusAutomation.Tests;

public class SecretRedactorTests
{
    [Fact]
    public void Registered_secrets_are_masked_wherever_they_appear()
    {
        var redactor = new SecretRedactor();
        redactor.Register("Fixture-Passw0rd!");
        redactor.Register("fixture-session-token-6f1c2a");

        var text = redactor.Redact("login with Fixture-Passw0rd! gave fixture-session-token-6f1c2a");

        Assert.Equal($"login with {SecretRedactor.Mask} gave {SecretRedactor.Mask}", text);
    }

    [Theory]
    [InlineData("X-Cookie: token=abc123def456", "token=abc123def456")]
    [InlineData("X-ApiKeys: accessKey=AAAA1111; secretKey=BBBB2222", "AAAA1111")]
    [InlineData("X-ApiKeys: accessKey=AAAA1111; secretKey=BBBB2222", "BBBB2222")]
    [InlineData("""{"username":"u","password":"hunter2!"}""", "hunter2!")]
    [InlineData("""{"token": "deadbeefcafe"}""", "deadbeefcafe")]
    [InlineData("Authorization: Bearer eyJhbGciOi.payload.sig", "eyJhbGciOi")]
    public void Credential_shaped_fragments_are_masked_without_registration(string input, string secret)
    {
        var output = new SecretRedactor().Redact(input);
        Assert.DoesNotContain(secret, output, StringComparison.Ordinal);
        Assert.Contains(SecretRedactor.Mask, output, StringComparison.Ordinal);
    }

    [Fact]
    public void Ordinary_text_is_unchanged_and_tiny_values_are_not_registered()
    {
        var redactor = new SecretRedactor();
        redactor.Register("ab");
        const string text = "Scan 42 status: running on 192.0.2.10 (about 2 hosts)";
        Assert.Equal(text, redactor.Redact(text));
    }

    [Fact]
    public void Log_lines_are_redacted()
    {
        var redactor = new SecretRedactor();
        redactor.Register("s3cr3t-value");
        using var writer = new StringWriter();
        var log = new RedactingLog(writer, redactor);

        log.Error("request failed for s3cr3t-value with token=zzz999");

        var line = writer.ToString();
        Assert.DoesNotContain("s3cr3t-value", line, StringComparison.Ordinal);
        Assert.DoesNotContain("zzz999", line, StringComparison.Ordinal);
        Assert.Contains("[ERROR]", line, StringComparison.Ordinal);
    }
}

public sealed class TlsHandlerTests : IDisposable
{
    private readonly StringWriter _logWriter = new();
    private readonly RedactingLog _log;
    private readonly string _tempDir = Directory.CreateTempSubdirectory("nessus-tls-tests").FullName;

    public TlsHandlerTests() => _log = new RedactingLog(_logWriter, new SecretRedactor());

    public void Dispose()
    {
        _logWriter.Dispose();
        Directory.Delete(_tempDir, recursive: true);
    }

    [Fact]
    public void Default_handler_uses_platform_validation_and_does_not_follow_redirects()
    {
        using var handler = NessusHttpHandlerFactory.Create(new TlsOptions(), _log);
        Assert.Null(handler.SslOptions.RemoteCertificateValidationCallback);
        Assert.False(handler.AllowAutoRedirect);
        Assert.False(handler.UseCookies);
    }

    [Fact]
    public void Insecure_mode_is_scoped_to_its_handler_and_announced()
    {
        using var insecure = NessusHttpHandlerFactory.Create(new TlsOptions { Mode = TlsValidationMode.InsecureSkipVerify }, _log);
        using var secure = NessusHttpHandlerFactory.Create(new TlsOptions(), _log);

        Assert.NotNull(insecure.SslOptions.RemoteCertificateValidationCallback);
        Assert.Null(secure.SslOptions.RemoteCertificateValidationCallback);
#pragma warning disable SYSLIB0014 // Asserting the legacy global hook is untouched.
        Assert.Null(ServicePointManager.ServerCertificateValidationCallback);
#pragma warning restore SYSLIB0014
        Assert.Contains("TLS CERTIFICATE VERIFICATION IS DISABLED", _logWriter.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Custom_root_accepts_chain_to_supplied_ca_only()
    {
        using var labCa = CreateCa("CN=Lab Test Root");
        using var otherCa = CreateCa("CN=Unrelated Root");
        using var leaf = CreateLeaf(labCa, "nessus.lab.test");
        using var rogue = CreateLeaf(otherCa, "nessus.lab.test");

        var roots = new X509Certificate2Collection { X509CertificateLoader.LoadCertificate(labCa.Export(X509ContentType.Cert)) };

        Assert.True(NessusHttpHandlerFactory.ValidateAgainstCustomRoots(leaf, SslPolicyErrors.RemoteCertificateChainErrors, roots));
        Assert.False(NessusHttpHandlerFactory.ValidateAgainstCustomRoots(rogue, SslPolicyErrors.RemoteCertificateChainErrors, roots));
        Assert.False(NessusHttpHandlerFactory.ValidateAgainstCustomRoots(leaf, SslPolicyErrors.RemoteCertificateNameMismatch | SslPolicyErrors.RemoteCertificateChainErrors, roots));
        Assert.False(NessusHttpHandlerFactory.ValidateAgainstCustomRoots(null, SslPolicyErrors.RemoteCertificateNotAvailable, roots));
    }

    [Fact]
    public void Custom_root_mode_loads_pem_and_installs_handler_scoped_callback()
    {
        using var labCa = CreateCa("CN=Lab Test Root");
        var path = Path.Combine(_tempDir, "lab-ca.pem");
        File.WriteAllText(path, labCa.ExportCertificatePem());

        using var handler = NessusHttpHandlerFactory.Create(new TlsOptions { Mode = TlsValidationMode.CustomRoot, CaCertificatePath = path }, _log);

        Assert.NotNull(handler.SslOptions.RemoteCertificateValidationCallback);
        Assert.Contains("hostname validation remains enabled", _logWriter.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Unreadable_ca_file_is_a_configuration_error()
    {
        var path = Path.Combine(_tempDir, "empty.pem");
        File.WriteAllText(path, "not a certificate");
        Assert.Throws<ConfigurationException>(() =>
            NessusHttpHandlerFactory.Create(new TlsOptions { Mode = TlsValidationMode.CustomRoot, CaCertificatePath = path }, _log));
    }

    private static X509Certificate2 CreateCa(string subject)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
    }

    private static X509Certificate2 CreateLeaf(X509Certificate2 issuer, string dnsName)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest($"CN={dnsName}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName(dnsName);
        request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        var serial = RandomNumberGenerator.GetBytes(8);
        return request.Create(issuer, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddDays(7), serial);
    }
}
