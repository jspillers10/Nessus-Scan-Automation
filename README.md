# Nessus Scan Automation

Automated vulnerability scanning using the Nessus REST API.

This project provides a lightweight C# implementation for interacting with Nessus programmatically. It handles authentication, scan creation, scan execution, and vulnerability retrieval through the API.

The goal is to demonstrate security automation and vulnerability management workflows using Nessus.

---

## Features

- Authenticate to Nessus using the `/session` API endpoint
- Create vulnerability scans programmatically
- Launch scans automatically
- Poll scan status until completion
- Retrieve discovered vulnerabilities
- Simple session and token management
- Modular design for extending Nessus API functionality

---

## Architecture

The project is structured around two core classes.

### NessusSession

Handles low-level communication with the Nessus API.

**Responsibilities**

- Authentication
- Session token management
- HTTP requests
- JSON parsing
- Connection handling

**Key Methods**

- `Authenticate()`
- `MakeRequest()`
- `LogOut()`
- `Dispose()`

---

### NessusManager

Provides higher-level functionality built on top of `NessusSession`.

**Responsibilities**

- Retrieving scan policy templates
- Creating scans
- Launching scans
- Retrieving scan results

**Key Methods**

- `GetScanPolicies()`
- `CreateScan()`
- `StartScan()`
- `GetScan()`

---

## Workflow

1. Authenticate with Nessus
2. Retrieve available scan policy templates
3. Select the basic scan template
4. Create a new scan targeting an IP or CIDR range
5. Launch the scan
6. Poll Nessus until the scan completes
7. Output discovered vulnerabilities

---

## Example Usage

```csharp
using (NessusSession session = new NessusSession("192.168.1.14", "admin", "password"))
{
    using (NessusManager manager = new NessusManager(session))
    {
        JObject policies = manager.GetScanPolicies();
    }
}
```

---

## Example Output

### Scan Status

```
Scan status: running
Scan status: running
Scan status: running
```

### Vulnerability Example

```json
{
  "plugin_name": "SSL Version 2 and 3 Protocol Detection",
  "severity": 2,
  "plugin_family": "Service detection"
}
```

```json
{
  "plugin_name": "SSL Self-Signed Certificate",
  "severity": 2,
  "plugin_family": "General"
}
```

---

## Requirements

- Nessus installed and running
- API access enabled
- C# / .NET runtime
- Newtonsoft.Json

---

## Security Notes

For testing purposes the script disables SSL certificate validation to support self-signed certificates in lab environments.

```csharp
ServicePointManager.ServerCertificateValidationCallback =
    (Object obj, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) => true;
```

This is convenient for local testing but **should not be used in production environments**.

---

## Use Cases

This project demonstrates how vulnerability management can be automated for:

- Security scanning pipelines
- Asset monitoring
- Scheduled vulnerability assessments
- Security engineering automation
- Integration with dashboards or SIEM workflows

---

## Future Improvements

- Scan scheduling
- Export results to JSON / CSV
- Severity filtering
- Dashboard integration
- Multi-target scanning
- CI/CD security pipeline integration
