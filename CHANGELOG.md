# Changelog

## 1.1.1
- Fixed missing System.IO imports in GitHub Actions builds.
- Replaced unsupported MigraDoc Color.FromHex with Color.Parse.
- Fixed Inno Setup discovery in PowerShell.
- Build scripts now fail correctly on dotnet/Inno errors.

## 1.1.0
- Added named cheat-signature entries.
- PDF now prints detected cheat name, family, exact detection method, artifact path and SHA-256.
- Kept legacy unnamed hash compatibility.
- Added automatic public GitHub Release publishing on version tags.
- Added installer and portable SHA-256 release files.
- Added Mongolian public release guide.

## 1.0.0

- Modern WPF dark UI
- Quick, Full, and Forensic modes
- Explicit consent and cancellation
- Process and CS2 module hash/signature inspection
- Browser relevant metadata collector
- Prefetch, UserAssist, BAM, and Recent Items collectors
- Recycle Bin metadata parser
- Registered drivers and startup-entry collector
- Live TCP connections and cumulative network counters
- High-risk location executable/archive metadata scanner
- Evidence correlation, risk scoring, and four reliable verdict states
- PDF, JSON, and SHA-256 report bundle
- Self-contained Windows x64 build and Inno Setup scripts
- GitHub Actions free Windows build workflow
