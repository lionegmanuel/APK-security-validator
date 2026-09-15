# APK Security Validator

Automated static security analysis and risk assessment tool for Android APK files, built with PowerShell, Jadx, Apktool, and Android SDK tools.

It performs structural decompilation, manifest inspection, permission scoring, certificate verification, and optional VirusTotal hash reputation lookups to evaluate package safety before deployment.

---

## Key Capabilities

- **Manifest & Permissions Analysis:** Inspects requested Android permissions and flags high-risk capabilities (SMS, background location, accessibility services, overlay windows, camera/mic abuse).
- **Certificate & Signature Verification:** Analyzes signing certificates via `apksigner` (v1, v2, v3, v4 signature schemes, debug certificate detection, expiration checks).
- **Static String & Endpoint Extraction:** Scans decompiled Smali/Java resources for hardcoded IPs, suspicious domains, exposed API endpoints, and potential sensitive tokens.
- **VirusTotal Integration (Hash-based):** Queries VirusTotal reputation via SHA-256 hash without uploading the binary itself, preserving confidentiality.
- **Structured Reporting:** Exports both a comprehensive JSON report (`report.json`) for automated CI/CD pipelines and a human-readable text audit (`report.txt`).

---

## Requirements

The tool leverages standard Android reverse engineering utilities:
- PowerShell 7+ or Windows PowerShell 5.1
- Java Runtime Environment (JRE/JDK 17+)
- `apktool`
- `aapt` / Android SDK Build-Tools
- `apksigner`

Verify installed tooling:
```powershell
java -version
apktool -version
aapt v
apksigner --version
```

---

## Quick Start

Run analysis on a target APK:
```powershell
.\apk-definitive-validator.ps1 -ApkPath "C:\path\to\application.apk"
```

Specify a custom output directory:
```powershell
.\apk-definitive-validator.ps1 -ApkPath "C:\path\to\application.apk" -OutDir ".\custom-audit-output"
```

Enable VirusTotal hash verification:
```powershell
$env:VT_API_KEY = "your_virustotal_api_key"
.\apk-definitive-validator.ps1 -ApkPath "C:\path\to\application.apk" -EnableVirusTotal -VirusTotalApiKey $env:VT_API_KEY
```

---

## Output Artifacts

Each analysis run generates:
1. `report.json`: Full technical breakdown of components (Activities, Services, Receivers, Providers), exported flags, permission severity, and threat indicators.
2. `report.txt`: Executive summary with an overall Risk Score and security highlights.

---

## License

MIT License. Designed for security researchers, developers, and QA engineers.
