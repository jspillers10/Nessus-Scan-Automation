using NessusAutomation.Configuration;

namespace NessusAutomation.Tests;

public class TargetScopeValidatorTests
{
    private static readonly IReadOnlyList<ScanTarget> Scope =
        TargetScopeValidator.ParseScope(["192.0.2.0/24", "198.51.100.7", "2001:db8::/120", "web01.lab.test"]);

    [Theory]
    [InlineData("192.0.2.10", "192.0.2.10")]
    [InlineData("192.0.2.16/28", "192.0.2.16/28")]
    [InlineData("192.0.2.0/24", "192.0.2.0/24")]
    [InlineData("198.51.100.7", "198.51.100.7")]
    [InlineData("198.51.100.7/32", "198.51.100.7")]
    [InlineData("2001:db8::10", "2001:db8::10")]
    [InlineData("WEB01.lab.test.", "web01.lab.test")]
    public void Targets_inside_scope_are_accepted_and_normalised(string target, string expected)
    {
        var result = TargetScopeValidator.ValidateTargets([target], Scope);
        Assert.Equal(expected, Assert.Single(result).Value);
    }

    [Theory]
    [InlineData("192.0.3.1", "outside the authorised scope")]
    [InlineData("192.0.2.0/23", "outside the authorised scope")]
    [InlineData("198.51.100.8", "outside the authorised scope")]
    [InlineData("db01.lab.test", "outside the authorised scope")]
    [InlineData("lab.test", "outside the authorised scope")]
    [InlineData("2001:db8::1:0", "outside the authorised scope")]
    [InlineData("192.0.2.5/24", "host bits must be zero")]
    [InlineData("2001:db8::5/120", "host bits must be zero")]
    [InlineData("192.0.2/24", "not a valid CIDR block")]
    [InlineData("192.0.2.1-192.0.2.20", "not an IP address, CIDR block or valid DNS hostname")]
    [InlineData("192.0.2.1,192.0.2.2", "comma")]
    [InlineData("192.0.2.1 192.0.2.2", "whitespace")]
    [InlineData("*.lab.test", "not an IP address")]
    [InlineData("https://web01.lab.test", "not a valid CIDR block")]
    [InlineData("192.0.2.256", "not a valid IP address")]
    [InlineData("10.0.0", "not an IP address")]
    [InlineData("0.0.0.0/0", "entire address space")]
    [InlineData("", "empty")]
    public void Invalid_or_out_of_scope_targets_are_rejected(string target, string expected)
    {
        var ex = Assert.Throws<ConfigurationException>(() => TargetScopeValidator.ValidateTargets([target], Scope));
        Assert.Contains(expected, ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("0.0.0.0")]
    [InlineData("255.255.255.255")]
    [InlineData("224.0.0.1")]
    [InlineData("ff02::1")]
    public void Special_addresses_are_rejected_even_if_scope_covers_them(string target)
    {
        var wide = TargetScopeValidator.ParseScope(["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"]);
        var ex = Assert.Throws<ConfigurationException>(() => TargetScopeValidator.ValidateTargets([target], wide));
        Assert.Contains("unspecified, broadcast or multicast", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Address_budget_is_enforced()
    {
        var ex = Assert.Throws<ConfigurationException>(() =>
            TargetScopeValidator.ValidateTargets(["192.0.2.0/24", "198.51.100.7"], Scope, maxAddresses: 256));
        Assert.Contains("257 addresses", ex.Message, StringComparison.Ordinal);

        Assert.Equal(2, TargetScopeValidator.ValidateTargets(["192.0.2.0/24", "198.51.100.7"], Scope, maxAddresses: 257).Count);
    }

    [Fact]
    public void Duplicate_targets_are_collapsed_and_every_error_is_reported()
    {
        Assert.Single(TargetScopeValidator.ValidateTargets(["192.0.2.10", "192.0.2.10"], Scope));

        var ex = Assert.Throws<ConfigurationException>(() => TargetScopeValidator.ValidateTargets(["192.0.3.1", "bad target", "192.0.2.10"], Scope));
        Assert.Equal(2, ex.Errors.Count);
    }

    [Fact]
    public void Scope_and_targets_are_required()
    {
        Assert.Throws<ConfigurationException>(() => TargetScopeValidator.ParseScope([]));
        var ex = Assert.Throws<ConfigurationException>(() => TargetScopeValidator.ValidateTargets([], Scope));
        Assert.Contains("At least one --target", ex.Message, StringComparison.Ordinal);
    }
}

public class ConnectionOptionsTests
{
    [Theory]
    [InlineData("https://nessus.lab.test:8834", "https://nessus.lab.test:8834/")]
    [InlineData("https://nessus.lab.test:8834/", "https://nessus.lab.test:8834/")]
    [InlineData("https://nessus.lab.test/nessus", "https://nessus.lab.test/nessus/")]
    public void Valid_urls_are_normalised(string input, string expected) =>
        Assert.Equal(expected, NessusConnectionOptions.ParseBaseUri(input).ToString());

    [Theory]
    [InlineData(null, "required")]
    [InlineData("http://nessus.lab.test:8834", "https://")]
    [InlineData("https://admin:pw@nessus.lab.test:8834", "Do not embed credentials")]
    [InlineData("https://nessus.lab.test:8834/?x=1", "query string")]
    [InlineData("nessus.lab.test", "valid absolute URL")]
    public void Invalid_urls_are_rejected(string? input, string expected)
    {
        var ex = Assert.Throws<ConfigurationException>(() => NessusConnectionOptions.ParseBaseUri(input));
        Assert.Contains(expected, ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Custom_root_requires_an_existing_file_and_insecure_mode_rejects_ca_path()
    {
        var baseOptions = Fakes.Fixtures.Connection();
        Assert.Throws<ConfigurationException>(() => (baseOptions with { Tls = new TlsOptions { Mode = TlsValidationMode.CustomRoot } }).Validate());
        Assert.Throws<ConfigurationException>(() => (baseOptions with { Tls = new TlsOptions { Mode = TlsValidationMode.CustomRoot, CaCertificatePath = "missing.pem" } }).Validate());
        Assert.Throws<ConfigurationException>(() => (baseOptions with { Tls = new TlsOptions { Mode = TlsValidationMode.InsecureSkipVerify, CaCertificatePath = "x.pem" } }).Validate());
    }

    [Fact]
    public void Credential_records_never_print_secrets()
    {
        var up = new NessusCredentials.UserPassword("lab-auditor", "Fixture-Passw0rd!");
        var keys = new NessusCredentials.ApiKeys("access-123456", "secret-654321");
        Assert.DoesNotContain("Fixture-Passw0rd!", up.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("access-123456", keys.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("secret-654321", keys.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void Polling_and_job_options_are_validated()
    {
        Assert.Throws<ConfigurationException>(() => new PollingOptions { Deadline = TimeSpan.Zero }.Validate());
        Assert.Throws<ConfigurationException>(() => new PollingOptions { Interval = TimeSpan.FromMinutes(5), Deadline = TimeSpan.FromMinutes(1) }.Validate());
        Assert.Throws<ConfigurationException>(() => (Fakes.Fixtures.Job() with { Name = " " }).Validate());
        Assert.Throws<ConfigurationException>(() => (Fakes.Fixtures.Job() with { Selection = new ScanSelection.Policy(0) }).Validate());
        Assert.Throws<ConfigurationException>(() => (Fakes.Fixtures.Job() with { Results = new ResultOptions { MinimumSeverity = 5 } }).Validate());
    }
}
