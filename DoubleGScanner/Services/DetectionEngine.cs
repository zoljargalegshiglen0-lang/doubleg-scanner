using DoubleGScanner.Models;

namespace DoubleGScanner.Services;

public static class DetectionEngine
{
    public static IReadOnlyList<ScanFinding> Analyze(IReadOnlyList<EvidenceRecord> evidence, RuleSet rules)
    {
        var findings = new List<ScanFinding>();

        foreach (EvidenceRecord item in evidence)
        {
            if (TryAddDefenderFinding(item, findings)) continue;
            if (TryAddVulnerableDriverHashFinding(item, rules, findings)) continue;
            if (TryAddExactHashFinding(item, rules, findings)) continue;

            string combined = string.Join(" ", item.Name, item.Path, item.Url, item.Detail,
                item.Metadata.GetValueOrDefault("ArchiveIndicators"),
                item.Metadata.GetValueOrDefault("StaticIndicators"));

            KnownCheatNameEntry? namedCheat = RuleMatcher.FindKnownCheatName(combined, rules);
            if (namedCheat is not null)
                AddNamedCheatFinding(item, namedCheat, findings);

            AddGenericFindings(item, combined, rules, findings);
        }

        AddCorrelation(evidence, findings, rules);

        return findings
            .GroupBy(x => $"{x.RuleId}|{x.Path}|{x.DetectedCheatName}|{x.Timestamp:O}", StringComparer.OrdinalIgnoreCase)
            .Select(group => group.OrderByDescending(x => x.Score).First())
            .OrderByDescending(x => x.Score)
            .ThenByDescending(x => x.Timestamp)
            .ToArray();
    }

    public static (ScanVerdict Verdict, int Risk) Verdict(
        IReadOnlyList<ScanFinding> findings,
        IReadOnlyList<ScanCoverage> coverage,
        ScanMode mode)
    {
        int failed = coverage.Count(x => x.Status is CoverageStatus.Failed or CoverageStatus.Unavailable);
        int partial = coverage.Count(x => x.Status == CoverageStatus.Partial);
        int risk = Math.Min(200, findings.Sum(x => x.Score));

        if (mode is ScanMode.Full or ScanMode.Forensic)
        {
            string[] requiredDiskForensicModules =
            {
                "NTFS MFT metadata",
                "USN change journal",
                "Unallocated-space signature scan"
            };

            bool missingRequiredDiskModule = coverage.Any(item =>
                requiredDiskForensicModules.Contains(
                    item.Module,
                    StringComparer.OrdinalIgnoreCase) &&
                item.Status is CoverageStatus.Unavailable or
                    CoverageStatus.Failed or
                    CoverageStatus.Skipped);

            if (missingRequiredDiskModule)
                return (ScanVerdict.Incomplete, risk);
        }

        if (mode == ScanMode.Forensic)
        {
            bool missingKernelIntegrity = coverage.Any(item =>
                item.Module.Equals(
                    "Kernel & driver integrity",
                    StringComparison.OrdinalIgnoreCase) &&
                item.Status is CoverageStatus.Unavailable or
                    CoverageStatus.Failed or
                    CoverageStatus.Skipped);

            if (missingKernelIntegrity)
                return (ScanVerdict.Incomplete, risk);
        }

        if (mode == ScanMode.Quick)
        {
            string[] requiredQuickModules =
            {
                "System profile",
                "Running processes",
                "CS2 loaded modules",
                "Downloaded and local file scan"
            };

            int requiredQuickFailures = coverage.Count(item =>
                requiredQuickModules.Contains(
                    item.Module,
                    StringComparer.OrdinalIgnoreCase) &&
                item.Status is CoverageStatus.Failed or CoverageStatus.Unavailable);

            if (requiredQuickFailures >= 2)
                return (ScanVerdict.Incomplete, risk);
        }
        else if (failed >= 3 || failed + partial >= 6)
        {
            return (ScanVerdict.Incomplete, risk);
        }

        if (findings.Any(x => x.Severity == FindingSeverity.Critical && x.Score >= 80))
            return (ScanVerdict.Detected, risk);

        if (findings.Any(x => x.Severity == FindingSeverity.High) || risk >= 50)
            return (ScanVerdict.Review, risk);

        return (ScanVerdict.NotDetected, risk);
    }

    private static bool TryAddDefenderFinding(EvidenceRecord item, List<ScanFinding> findings)
    {
        if (item.Kind != EvidenceKind.Antivirus ||
            !item.Metadata.TryGetValue("ThreatName", out string? threat) ||
            string.IsNullOrWhiteSpace(threat)) return false;

        findings.Add(new ScanFinding
        {
            RuleId = "DGS-DEFENDER-001",
            Severity = FindingSeverity.Critical,
            Score = 100,
            Title = $"Microsoft Defender detected: {threat}",
            Summary = "Microsoft Defender reported a threat during the read-only custom scan.",
            EvidenceSource = item.Source,
            Path = item.Path,
            HashSha256 = item.HashSha256,
            Timestamp = item.Timestamp,
            DetectedCheatName = threat,
            CheatFamily = "Microsoft Defender detection",
            DetectionMethod = "Microsoft Defender custom scan (-DisableRemediation)",
            Reasons = new[] { "Antivirus engine detection", "DoubleG Scanner did not delete or quarantine the file" }
        });
        return true;
    }

    private static bool TryAddVulnerableDriverHashFinding(
        EvidenceRecord item,
        RuleSet rules,
        List<ScanFinding> findings)
    {
        if (item.Kind != EvidenceKind.KernelDriver)
            return false;

        KnownVulnerableDriverEntry? match =
            RuleMatcher.FindKnownVulnerableDriverByHash(
                item.HashSha256,
                rules);

        if (match is null)
            return false;

        findings.Add(new ScanFinding
        {
            RuleId = "DGS-KERNEL-HASH-001",
            Severity = FindingSeverity.Critical,
            Score = 100,
            Title = $"Exact vulnerable-driver hash matched: {match.Name}",
            Summary =
                "A loaded kernel driver exactly matched a SHA-256 entry in the vulnerable-driver dataset.",
            EvidenceSource = item.Source,
            Path = item.Path,
            HashSha256 = item.HashSha256,
            Timestamp = item.Timestamp,
            DetectedCheatName = match.Name,
            CheatFamily = match.Family,
            DetectionMethod =
                "Exact SHA-256 vulnerable-driver signature",
            Reasons = new[]
            {
                "Loaded kernel driver",
                "Exact SHA-256 match",
                string.IsNullOrWhiteSpace(match.SourceNote)
                    ? "Verified driver signature entry"
                    : match.SourceNote
            }
        });

        return true;
    }

    private static bool TryAddExactHashFinding(EvidenceRecord item, RuleSet rules, List<ScanFinding> findings)
    {
        KnownCheatEntry? exact = RuleMatcher.FindKnownCheat(item.HashSha256, rules);
        if (exact is not null)
        {
            string displayName = string.IsNullOrWhiteSpace(exact.Name) ? "Named cheat signature" : exact.Name;
            findings.Add(new ScanFinding
            {
                RuleId = "DGS-HASH-001",
                Severity = FindingSeverity.Critical,
                Score = 100,
                Title = $"Detected cheat: {displayName}",
                Summary = "The SHA-256 hash exactly matched a named entry in the DoubleG detection database.",
                EvidenceSource = item.Source,
                Path = item.Path ?? item.Url,
                HashSha256 = item.HashSha256,
                Timestamp = item.Timestamp,
                DetectedCheatName = displayName,
                CheatFamily = string.IsNullOrWhiteSpace(exact.Family) ? null : exact.Family,
                DetectionMethod = "Exact SHA-256 signature",
                Reasons = new[]
                {
                    "Exact SHA-256 match",
                    string.IsNullOrWhiteSpace(exact.SourceNote) ? "Verified local signature entry" : exact.SourceNote
                }
            });
            return true;
        }

        if (!RuleMatcher.IsKnownHash(item.HashSha256, rules)) return false;
        findings.Add(F("DGS-HASH-LEGACY", FindingSeverity.Critical, 100,
            "Known cheat hash matched",
            "The SHA-256 hash matched a legacy unnamed detection entry.",
            item, "Exact SHA-256 match"));
        return true;
    }

    private static void AddNamedCheatFinding(
        EvidenceRecord item,
        KnownCheatNameEntry named,
        List<ScanFinding> findings)
    {
        string artifact = item.Path ?? item.Url ?? item.Name;
        bool executableOrArchive = RuleMatcher.IsExecutableOrArchive(artifact);
        bool binary = RuleMatcher.IsBinary(artifact);
        bool unsigned = binary && item.IsSignatureValid != true;
        bool userWritable = RuleMatcher.IsUserWritable(item.Path);
        int staticScore = MetaInt(item, "StaticRiskScore");
        int archiveStatic = MetaInt(item, "ArchiveStaticScore");
        int archiveExecutables = MetaInt(item, "ArchiveExecutableCount");
        bool recentDownload = item.Metadata.GetValueOrDefault("RecordType") == "RecentDownloadArtifact";
        bool browserDownload = item.Kind == EvidenceKind.Browser && item.Metadata.GetValueOrDefault("RecordType") == "Download";
        bool cs2Module = item.Kind == EvidenceKind.Module &&
                         string.Equals(item.Metadata.GetValueOrDefault("ProcessName"), "cs2.exe", StringComparison.OrdinalIgnoreCase);
        bool technicalSupport = staticScore >= 30 || archiveStatic >= 25 || archiveExecutables > 0 || unsigned;

        if (cs2Module)
        {
            findings.Add(Named("DGS-NAMED-MODULE", FindingSeverity.Critical, 94,
                $"Named cheat module detected: {named.Name}",
                "A module loaded by CS2 matched a known cheat-family name.", item, named,
                "Known cheat name in a CS2-loaded module", "Loaded by cs2.exe"));
            return;
        }

        if (item.Kind == EvidenceKind.Process && executableOrArchive && userWritable && item.IsSignatureValid != true)
        {
            findings.Add(Named("DGS-NAMED-PROCESS", FindingSeverity.Critical, 88,
                $"Named cheat process detected: {named.Name}",
                "A running user-writable unsigned executable matched a known cheat-family name.", item, named,
                "Known cheat name + running unsigned executable", "Running process", "User-writable path"));
            return;
        }

        if (item.Kind == EvidenceKind.FileArtifact && recentDownload && executableOrArchive && technicalSupport)
        {
            findings.Add(Named("DGS-NAMED-DOWNLOAD", FindingSeverity.Critical, 86,
                $"Likely cheat artifact detected: {named.Name}",
                "A recent downloaded executable/archive matched a known cheat-family name and also had supporting technical indicators.",
                item, named, "Known cheat name + downloaded artifact + technical indicators",
                unsigned ? "Unsigned executable" : "Executable/archive payload",
                staticScore > 0 ? $"Static score: {staticScore}/100" : $"Archive executable entries: {archiveExecutables}"));
            return;
        }

        if (item.Kind == EvidenceKind.DeletedFile && executableOrArchive)
        {
            findings.Add(Named("DGS-NAMED-DELETED", FindingSeverity.High, 72,
                $"Deleted named cheat artifact: {named.Name}",
                "Deleted-file metadata referenced an executable/archive matching a known cheat-family name.",
                item, named, "Known cheat name in deleted-file metadata", "Manual verification required"));
            return;
        }

        if (item.Kind == EvidenceKind.RawDeletedFile)
        {
            int rawStaticScore = MetaInt(item, "StaticRiskScore");
            findings.Add(Named(
                "DGS-NAMED-RAW-DELETED",
                rawStaticScore >= 70 ? FindingSeverity.Critical : FindingSeverity.High,
                rawStaticScore >= 70 ? 92 : 78,
                $"Raw deleted cheat fragment detected: {named.Name}",
                "A known cheat-family name was recovered in memory from an executable/archive signature located in unallocated NTFS clusters.",
                item,
                named,
                "Known cheat name + unallocated executable/archive signature",
                "Cluster was marked free at scan time",
                "Content was analyzed in memory and was not restored to disk",
                rawStaticScore > 0 ? $"Static score: {rawStaticScore}/100" : "Named raw signature"));
            return;
        }

        if (item.Kind == EvidenceKind.UsnJournal && executableOrArchive)
        {
            bool deletion = MetaBool(item, "IsDeleteEvent");
            findings.Add(Named(
                deletion ? "DGS-NAMED-USN-DELETE" : "DGS-NAMED-USN",
                deletion ? FindingSeverity.High : FindingSeverity.Warning,
                deletion ? 76 : 44,
                deletion
                    ? $"USN deleted cheat trace: {named.Name}"
                    : $"USN named cheat trace: {named.Name}",
                deletion
                    ? "The NTFS change journal recorded a deletion or old-name event matching a known cheat-family name."
                    : "The NTFS change journal contained a file-change event matching a known cheat-family name.",
                item,
                named,
                deletion
                    ? "Known cheat name in NTFS deletion journal"
                    : "Known cheat name in NTFS change journal",
                "Journal metadata only",
                "Manual verification required"));
            return;
        }

        if (item.Kind == EvidenceKind.NtfsMetadata && executableOrArchive)
        {
            findings.Add(Named(
                "DGS-NAMED-MFT",
                FindingSeverity.Warning,
                38,
                $"Named cheat file metadata: {named.Name}",
                "An NTFS MFT metadata record matched a known cheat-family name. MFT metadata alone does not prove execution or deletion.",
                item,
                named,
                "Known cheat name in MFT metadata",
                "Manual verification required"));
            return;
        }

        if (item.Kind == EvidenceKind.Execution && executableOrArchive)
        {
            findings.Add(Named("DGS-NAMED-EXECUTION", FindingSeverity.High, 70,
                $"Named cheat execution trace: {named.Name}",
                "Windows execution artifacts referenced a known cheat-family name.",
                item, named, "Known cheat name in execution trace", "Manual verification required"));
            return;
        }

        if (item.Kind == EvidenceKind.FileArtifact && executableOrArchive)
        {
            findings.Add(Named("DGS-NAMED-FILE", technicalSupport ? FindingSeverity.High : FindingSeverity.Warning,
                technicalSupport ? 66 : 38,
                $"Possible named cheat artifact: {named.Name}",
                technicalSupport
                    ? "A local executable/archive matched a known cheat-family name and had supporting technical indicators."
                    : "A local filename matched a known cheat-family name, but the evidence is not sufficient for a conclusive detection.",
                item, named,
                technicalSupport ? "Known cheat name + technical indicators" : "Known cheat name match only",
                "Manual verification required"));
            return;
        }

        if (browserDownload)
        {
            findings.Add(Named("DGS-NAMED-WEB", FindingSeverity.High, 56,
                $"Named cheat download record: {named.Name}",
                "A browser download record matched a known cheat-family name. Browser history alone is not proof.",
                item, named, "Known cheat name in browser download", "Manual verification required"));
            return;
        }

        findings.Add(Named("DGS-NAMED-LOW", FindingSeverity.Warning, 28,
            $"Known cheat-family name found: {named.Name}",
            "A local evidence record matched a known cheat-family name. Additional evidence is required.",
            item, named, "Name/alias match", "Low-confidence naming evidence"));
    }

    private static void AddGenericFindings(
        EvidenceRecord item,
        string combined,
        RuleSet rules,
        List<ScanFinding> findings)
    {
        bool high = RuleMatcher.ContainsHigh(combined, rules);
        bool medium = RuleMatcher.ContainsMedium(combined, rules);
        bool userWritable = RuleMatcher.IsUserWritable(item.Path);
        bool trusted = RuleMatcher.IsTrustedPublisher(item.Publisher, rules);

        if (item.Kind == EvidenceKind.KernelSecurity)
        {
            string blocklist =
                item.Metadata.GetValueOrDefault(
                    "VulnerableDriverBlocklistConfigured") ??
                "";

            string memoryIntegrity =
                item.Metadata.GetValueOrDefault(
                    "MemoryIntegrityRunning") ??
                "";

            string dma =
                item.Metadata.GetValueOrDefault(
                    "KernelDmaProtectionAvailable") ??
                "";

            if (blocklist.Equals(
                    "Disabled",
                    StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(F(
                    "DGS-KERNEL-POSTURE-002",
                    FindingSeverity.Warning,
                    8,
                    "Microsoft vulnerable-driver blocklist is explicitly disabled",
                    "Windows is explicitly configured not to use the vulnerable-driver blocklist. This is a security posture warning, not cheat evidence.",
                    item,
                    "Kernel hardening disabled"));
            }

            if (memoryIntegrity.Equals(
                    "False",
                    StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(F(
                    "DGS-KERNEL-POSTURE-003",
                    FindingSeverity.Information,
                    0,
                    "Memory Integrity is not running",
                    "Memory Integrity / HVCI was not reported as running. This is a hardening status only.",
                    item,
                    "Security posture information"));
            }

            if (dma.Equals(
                    "False",
                    StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(F(
                    "DGS-KERNEL-POSTURE-004",
                    FindingSeverity.Information,
                    0,
                    "Kernel DMA Protection capability was not reported",
                    "The Device Guard status did not report DMA protection capability. This does not prove DMA cheating.",
                    item,
                    "Hardware security capability information"));
            }
        }

        if (item.Kind == EvidenceKind.KernelDriver)
        {
            bool loaded =
                MetaBool(
                    item,
                    "Loaded");

            bool systemPath =
                MetaBool(
                    item,
                    "IsSystemDriverPath");

            bool userWritableDriver =
                MetaBool(
                    item,
                    "IsUserWritablePath");

            bool filenameHeuristic =
                MetaBool(
                    item,
                    "FilenameHeuristicMatch");

            if (loaded &&
                userWritableDriver)
            {
                findings.Add(F(
                    "DGS-KERNEL-DRIVER-005",
                    FindingSeverity.Critical,
                    90,
                    "Kernel driver loaded from a user-writable path",
                    "A loaded kernel driver resolved to a user-writable directory. This is a strong kernel-integrity indicator requiring immediate review.",
                    item,
                    "Loaded kernel module",
                    "User-writable driver path",
                    item.IsSignatureValid == true
                        ? "Signature valid"
                        : "Signature not validated"));
            }
            else if (loaded &&
                     item.IsSignatureValid == false &&
                     !systemPath)
            {
                findings.Add(F(
                    "DGS-KERNEL-DRIVER-006",
                    FindingSeverity.High,
                    70,
                    "Non-system loaded driver failed signature validation",
                    "A loaded kernel driver outside the Windows directory did not pass the available Authenticode validation.",
                    item,
                    "Loaded kernel module",
                    "Non-system path",
                    "Signature validation failed or was unavailable",
                    "Catalog-only signing may require manual verification"));
            }
            else if (loaded &&
                     item.IsSignatureValid == false &&
                     systemPath)
            {
                findings.Add(F(
                    "DGS-KERNEL-DRIVER-007",
                    FindingSeverity.Warning,
                    18,
                    "System driver signature requires manual verification",
                    "A Windows-path driver did not pass the scanner's file-level signature check. Catalog signing and servicing state can cause false positives.",
                    item,
                    "Manual driver signature review",
                    "Do not treat this finding alone as cheat evidence"));
            }

            if (filenameHeuristic)
            {
                findings.Add(F(
                    "DGS-KERNEL-DRIVER-008",
                    FindingSeverity.High,
                    56,
                    "Loaded driver filename matches an abused-driver heuristic",
                    "The loaded driver filename matched a review list associated with vulnerable or frequently abused driver families. Filename matching alone is not conclusive.",
                    item,
                    item.Metadata.GetValueOrDefault(
                        "FilenameHeuristicName") ??
                    "Driver filename heuristic",
                    "Verify exact version and SHA-256"));
            }

            if (loaded &&
                !systemPath &&
                !trusted &&
                !userWritableDriver &&
                item.IsSignatureValid != true)
            {
                findings.Add(F(
                    "DGS-KERNEL-DRIVER-009",
                    FindingSeverity.Warning,
                    30,
                    "Untrusted non-system kernel driver",
                    "A loaded driver outside the Windows directory was not associated with a trusted publisher.",
                    item,
                    "Non-system path",
                    "Publisher/signature requires manual review"));
            }
        }

        if (item.Kind == EvidenceKind.CodeIntegrity)
        {
            string recordType =
                item.Metadata.GetValueOrDefault(
                    "RecordType") ??
                "";

            bool driverServiceInstall =
                recordType.Equals(
                    "DriverServiceInstallEvent",
                    StringComparison.OrdinalIgnoreCase);

            bool userWritableEventPath =
                RuleMatcher.IsUserWritable(
                    item.Path);

            KnownVulnerableDriverEntry? nameMatch =
                RuleMatcher.FindKnownVulnerableDriverByName(
                    item.Name,
                    item.Path,
                    rules);

            if (driverServiceInstall &&
                userWritableEventPath)
            {
                findings.Add(F(
                    "DGS-KERNEL-EVENT-010",
                    FindingSeverity.High,
                    68,
                    "Driver service installed from a user-writable path",
                    "Windows recorded installation of a driver-like service whose image path is user-writable.",
                    item,
                    "Service Control Manager event 7045",
                    "User-writable .sys path"));
            }
            else if (driverServiceInstall)
            {
                findings.Add(F(
                    "DGS-KERNEL-EVENT-011",
                    FindingSeverity.Warning,
                    24,
                    "Recent driver-service installation event",
                    "Windows recorded installation of a driver-like service. Review the image path, publisher, and installation context.",
                    item,
                    "Service Control Manager event 7045"));
            }
            else
            {
                findings.Add(F(
                    "DGS-KERNEL-EVENT-012",
                    nameMatch is not null
                        ? FindingSeverity.High
                        : FindingSeverity.Warning,
                    nameMatch is not null
                        ? 66
                        : 38,
                    nameMatch is not null
                        ? "Code Integrity event references a high-risk driver filename"
                        : "Windows Code Integrity driver event",
                    "Windows Code Integrity recorded a driver-related image verification event. A blocked or failed load attempt is evidence of activity, not proof that the driver successfully loaded.",
                    item,
                    nameMatch?.Name ??
                    "Code Integrity Operational log",
                    "Manual event review required"));
            }
        }

        if (item.Kind == EvidenceKind.Module &&
            string.Equals(item.Metadata.GetValueOrDefault("ProcessName"), "cs2.exe", StringComparison.OrdinalIgnoreCase))
        {
            if (item.IsSignatureValid == false && userWritable)
                findings.Add(F("DGS-MODULE-002", FindingSeverity.Critical, 85,
                    "Unsigned user-writable module loaded by CS2",
                    "A module loaded inside CS2 came from a user-writable location and lacked a valid signature.",
                    item, "Loaded by cs2.exe", "User-writable path", "Invalid or absent signature"));
            else if (high && !trusted)
                findings.Add(F("DGS-MODULE-003", FindingSeverity.High, 68,
                    "Potentially suspicious CS2 module",
                    "A CS2 module matched high-risk terms and was not associated with a trusted publisher.",
                    item, "Loaded by cs2.exe", "High-risk term"));
        }

        if (item.Kind == EvidenceKind.Process && high && userWritable && item.IsSignatureValid != true)
            findings.Add(F("DGS-PROC-004", FindingSeverity.High, 55,
                "Suspicious unsigned process",
                "A running executable matched high-risk terms and lacked a valid signature.",
                item, "Running process", "High-risk term", "Unsigned user-writable executable"));

        if (item.Kind == EvidenceKind.Browser)
        {
            if (RuleMatcher.IsKnownDomain(item.Url, rules))
                findings.Add(F("DGS-WEB-005", FindingSeverity.Critical, 90,
                    "Known cheat distribution domain",
                    "A local browser record matched a domain in the detection dataset.", item, "Known-domain match"));
            else if (high && (RuleMatcher.IsExecutableOrArchive(item.Path) || item.Metadata.GetValueOrDefault("RecordType") == "Download"))
                findings.Add(F("DGS-WEB-006", FindingSeverity.Warning, 28,
                    "Potential cheat-related download record",
                    "A browser download matched high-risk terms. Browser history alone is supporting evidence.",
                    item, "High-risk term in download metadata"));

            bool missingDownloadedArtifact =
                item.Metadata.GetValueOrDefault("RecordType") == "Download" &&
                MetaBool(item, "MissingLocalFile") &&
                MetaBool(item, "RecentDownload") &&
                RuleMatcher.IsExecutableOrArchive(item.Path);

            if (missingDownloadedArtifact && !high)
                findings.Add(F("DGS-WEB-MISSING-024", FindingSeverity.Warning, 34,
                    "Downloaded executable/archive is no longer present",
                    "The browser recorded a recent executable or archive download, but the referenced local file is now missing. This is a deleted-download trace and is not by itself proof of cheating.",
                    item,
                    "Recent browser download",
                    "Referenced file no longer exists",
                    "Manual verification required"));
        }

        if (item.Kind == EvidenceKind.Execution && high)
        {
            bool missing = !string.IsNullOrWhiteSpace(item.Path) && !File.Exists(item.Path);
            findings.Add(F("DGS-EXEC-007", FindingSeverity.Warning, missing ? 35 : 25,
                "Potentially relevant execution trace",
                "Windows retained an execution artifact matching a high-risk rule.",
                item, $"Artifact source: {item.Source}", missing ? "Referenced file is missing" : "Artifact remains"));
        }

        if (item.Kind == EvidenceKind.DeletedFile && high && RuleMatcher.IsExecutableOrArchive(item.Path))
            findings.Add(F("DGS-DEL-008", FindingSeverity.High, 52,
                "Deleted executable/archive trace",
                "Recycle Bin metadata referenced a deleted executable/archive matching high-risk terms.",
                item, "Deleted-file metadata", "Executable/archive extension"));

        if (item.Kind == EvidenceKind.UsnJournal &&
            MetaBool(item, "IsDeleteEvent") &&
            high &&
            RuleMatcher.IsExecutableOrArchive(item.Name))
        {
            findings.Add(F(
                "DGS-USN-021",
                FindingSeverity.High,
                58,
                "NTFS deletion journal matched a high-risk executable/archive",
                "The USN change journal recorded a deletion or old-name event matching high-risk detection terms.",
                item,
                "USN deletion metadata",
                item.Metadata.GetValueOrDefault("ReasonText") ?? "File deletion or rename event"));
        }

        if (item.Kind == EvidenceKind.RawDeletedFile)
        {
            int rawStaticScore = MetaInt(item, "StaticRiskScore");

            if (rawStaticScore >= 70)
            {
                findings.Add(F(
                    "DGS-RAW-022",
                    FindingSeverity.High,
                    72,
                    "Strong cheat-like deleted binary fragment",
                    "A PE fragment found in unallocated clusters contained strong CS2 and process/memory manipulation indicators.",
                    item,
                    $"Static score: {rawStaticScore}/100",
                    item.Metadata.GetValueOrDefault("StaticIndicators") ?? "Static indicators",
                    "Content was not restored to disk"));
            }
            else if (rawStaticScore >= 45 || high)
            {
                findings.Add(F(
                    "DGS-RAW-023",
                    FindingSeverity.Warning,
                    42,
                    "Suspicious deleted executable/archive fragment",
                    "A signature located in free NTFS clusters contained suspicious static strings or high-risk terms.",
                    item,
                    $"Signature: {item.Metadata.GetValueOrDefault("SignatureType")}",
                    $"Disk offset: {item.Metadata.GetValueOrDefault("DiskOffsetHex")}",
                    "Manual verification required"));
            }
        }

        bool isDriver = item.Kind == EvidenceKind.FileArtifact && item.Metadata.GetValueOrDefault("RecordType") == "Driver";
        if (isDriver && item.IsSignatureValid == false && userWritable)
            findings.Add(F("DGS-DRV-009", FindingSeverity.Critical, 80,
                "Unsigned driver from a user-writable location",
                "A registered driver resolved to a user-writable path and lacked a valid signature.",
                item, "Registered driver", "User-writable path", "Invalid or absent signature"));
        else if (item.Kind == EvidenceKind.FileArtifact && high && userWritable && item.IsSignatureValid != true)
            findings.Add(F("DGS-FILE-010", FindingSeverity.Warning, 27,
                "Potentially suspicious local file",
                "A recent local file matched high-risk metadata and lacked a valid trusted signature.",
                item, "High-risk metadata", "Not conclusive"));

        if (item.Kind == EvidenceKind.FileArtifact)
        {
            int staticScore = MetaInt(item, "StaticRiskScore");
            int archiveStatic = MetaInt(item, "ArchiveStaticScore");
            int archiveExecutables = MetaInt(item, "ArchiveExecutableCount");
            bool recentDownload = item.Metadata.GetValueOrDefault("RecordType") == "RecentDownloadArtifact";
            bool archiveUnreadable = MetaBool(item, "ArchiveUnreadable");
            string extension = item.Metadata.GetValueOrDefault("Extension") ?? Path.GetExtension(item.Path ?? "");
            bool binary = extension.Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
                          extension.Equals(".dll", StringComparison.OrdinalIgnoreCase) ||
                          extension.Equals(".sys", StringComparison.OrdinalIgnoreCase) ||
                          extension.Equals(".com", StringComparison.OrdinalIgnoreCase) ||
                          extension.Equals(".scr", StringComparison.OrdinalIgnoreCase) ||
                          extension.Equals(".msi", StringComparison.OrdinalIgnoreCase);

            if (staticScore >= 70)
                findings.Add(F("DGS-STATIC-014", FindingSeverity.High, 66,
                    "Strong CS2 cheat-like static indicators",
                    "The binary contained a strong combination of CS2 references and process/memory manipulation indicators.",
                    item, $"Static score: {staticScore}/100", item.Metadata.GetValueOrDefault("StaticIndicators") ?? "Static indicators"));
            else if (staticScore >= 45)
                findings.Add(F("DGS-STATIC-015", FindingSeverity.Warning, 38,
                    "Suspicious static binary indicators",
                    "The binary contained several static indicators associated with loaders, injectors, or CS2 modification tools.",
                    item, $"Static score: {staticScore}/100", item.Metadata.GetValueOrDefault("StaticIndicators") ?? "Static indicators"));

            if (archiveExecutables > 0 && archiveStatic >= 55)
                findings.Add(F("DGS-ARCHIVE-016", FindingSeverity.High, 60,
                    "Archive contains suspicious executable payload",
                    "A recent archive contained executable/script payloads with strong static indicators.",
                    item, $"Executable/script entries: {archiveExecutables}", $"Embedded static score: {archiveStatic}/100"));
            else if (recentDownload && archiveExecutables > 0)
                findings.Add(F("DGS-ARCHIVE-017", FindingSeverity.Warning, 28,
                    "Downloaded archive contains executable payload",
                    "A recent archive contains executable/script payloads. This is common for installers and is not proof of cheating.",
                    item, $"Executable/script entries: {archiveExecutables}"));
            else if (recentDownload && archiveUnreadable)
                findings.Add(F("DGS-ARCHIVE-018", FindingSeverity.Warning, 22,
                    "Downloaded archive could not be fully inspected",
                    "The archive is encrypted, unsupported, or damaged. Manual review may be required.",
                    item, "Archive content unavailable"));

            if (recentDownload && binary && item.IsSignatureValid != true && staticScore < 45 && !high)
                findings.Add(F("DGS-DOWNLOAD-019", FindingSeverity.Warning, 16,
                    "Unsigned recent executable (not classified as cheat)",
                    "A recent executable lacks a valid signature. This is common for small utilities and is not proof of cheating.",
                    item, "Recent download", "Invalid or absent signature"));
        }

        if (item.Kind == EvidenceKind.Network && high)
            findings.Add(F("DGS-NET-011", FindingSeverity.Warning, 22,
                "Suspiciously named process has a live connection",
                "A process matching a high-risk term had an active TCP connection.", item, "Live network connection"));

        if (medium && (item.Kind == EvidenceKind.Process || item.Kind == EvidenceKind.FileArtifact) &&
            userWritable && item.IsSignatureValid == false)
            findings.Add(F("DGS-HEUR-012", FindingSeverity.Warning, 12,
                "Low-confidence unsigned tool indicator",
                "An unsigned user-writable executable matched a generic loader/injector term.",
                item, "Generic medium-risk term", "Manual review only"));
    }

    private static void AddCorrelation(
        IReadOnlyList<EvidenceRecord> evidence,
        List<ScanFinding> findings,
        RuleSet rules)
    {
        var namedGroups = evidence
            .Select(x => new { Evidence = x, Match = RuleMatcher.FindKnownCheatName(
                string.Join(" ", x.Name, x.Path, x.Url, x.Detail), rules) })
            .Where(x => x.Match is not null)
            .GroupBy(x => x.Match!.Name, StringComparer.OrdinalIgnoreCase);

        foreach (var group in namedGroups)
        {
            EvidenceKind[] kinds = group.Select(x => x.Evidence.Kind).Distinct().ToArray();
            bool browser = kinds.Contains(EvidenceKind.Browser);
            bool local = kinds.Contains(EvidenceKind.FileArtifact) || kinds.Contains(EvidenceKind.DeletedFile) || kinds.Contains(EvidenceKind.NtfsMetadata) || kinds.Contains(EvidenceKind.UsnJournal) || kinds.Contains(EvidenceKind.RawDeletedFile);
            bool execution = kinds.Contains(EvidenceKind.Execution) || kinds.Contains(EvidenceKind.Process) || kinds.Contains(EvidenceKind.Module) || kinds.Contains(EvidenceKind.UsnJournal);
            if (!browser || !local) continue;

            EvidenceRecord primary = group.Select(x => x.Evidence).OrderByDescending(x => x.Timestamp).First();
            KnownCheatNameEntry match = group.First().Match!;
            int score = execution ? 94 : 88;
            findings.Add(Named("DGS-NAMED-CORR", FindingSeverity.Critical, score,
                $"Correlated named cheat evidence: {match.Name}",
                execution
                    ? "The same known cheat-family name appeared in browser, local-file, and execution/process evidence."
                    : "The same known cheat-family name appeared independently in browser download and local-file evidence.",
                primary, match, "Independent named-evidence correlation", string.Join(", ", kinds)));
        }

        var highRiskGroups = evidence
            .Where(x => RuleMatcher.ContainsHigh(string.Join(" ", x.Name, x.Path, x.Url, x.Detail), rules))
            .Where(x => !string.IsNullOrWhiteSpace(x.Name))
            .GroupBy(x => Normalize(x.Name), StringComparer.OrdinalIgnoreCase);

        foreach (var group in highRiskGroups)
        {
            EvidenceKind[] kinds = group.Select(x => x.Kind).Distinct().ToArray();
            if (kinds.Contains(EvidenceKind.Browser) && kinds.Contains(EvidenceKind.Execution) &&
                (kinds.Contains(EvidenceKind.DeletedFile) || kinds.Contains(EvidenceKind.FileArtifact) || kinds.Contains(EvidenceKind.UsnJournal) || kinds.Contains(EvidenceKind.RawDeletedFile)))
            {
                EvidenceRecord primary = group.OrderByDescending(x => x.Timestamp).First();
                findings.Add(F("DGS-CORR-013", FindingSeverity.Critical, 82,
                    "Correlated download, execution, and file trace",
                    "The same high-risk artifact appeared in independent browser, execution, and file/deletion sources.",
                    primary, "Independent evidence correlation", string.Join(", ", kinds)));
            }
        }

        var loadedKernelDrivers = evidence
            .Where(item =>
                item.Kind == EvidenceKind.KernelDriver &&
                MetaBool(item, "Loaded") &&
                !string.IsNullOrWhiteSpace(item.Name))
            .ToArray();

        var driverArtifacts = evidence
            .Where(item =>
                item.Kind is EvidenceKind.Browser or
                    EvidenceKind.FileArtifact or
                    EvidenceKind.DeletedFile or
                    EvidenceKind.UsnJournal or
                    EvidenceKind.Execution)
            .Where(item =>
                Path.GetExtension(
                    item.Path ?? item.Name)
                    .Equals(
                        ".sys",
                        StringComparison.OrdinalIgnoreCase))
            .Where(item =>
                !string.IsNullOrWhiteSpace(item.Name))
            .ToArray();

        foreach (EvidenceRecord loadedDriver in loadedKernelDrivers)
        {
            string normalizedDriver =
                Normalize(
                    loadedDriver.Name);

            if (string.IsNullOrWhiteSpace(
                    normalizedDriver))
                continue;

            EvidenceRecord[] related =
                driverArtifacts
                    .Where(item =>
                        Normalize(
                            item.Name) ==
                        normalizedDriver)
                    .ToArray();

            if (related.Length == 0)
                continue;

            bool strong =
                MetaBool(
                    loadedDriver,
                    "IsUserWritablePath") ||
                MetaBool(
                    loadedDriver,
                    "FilenameHeuristicMatch") ||
                related.Any(item =>
                    RuleMatcher.ContainsHigh(
                        string.Join(
                            " ",
                            item.Name,
                            item.Path,
                            item.Url,
                            item.Detail),
                        rules));

            EvidenceRecord primary =
                related
                    .OrderByDescending(item =>
                        item.Timestamp)
                    .First();

            findings.Add(F(
                "DGS-KERNEL-CORR-013",
                strong
                    ? FindingSeverity.Critical
                    : FindingSeverity.High,
                strong
                    ? 88
                    : 62,
                strong
                    ? "Loaded kernel driver correlated with suspicious file activity"
                    : "Loaded kernel driver correlated with recent file activity",
                "The same .sys filename appeared as a currently loaded kernel driver and in an independent browser, file, deletion, USN, or execution artifact.",
                loadedDriver,
                $"Related source: {primary.Source}",
                $"Related artifact: {primary.Path ?? primary.Url ?? primary.Name}",
                strong
                    ? "Additional high-risk driver evidence"
                    : "Manual verification required"));
        }

        var browserDownloads = evidence
            .Where(item =>
                item.Kind == EvidenceKind.Browser &&
                item.Metadata.GetValueOrDefault("RecordType") == "Download" &&
                RuleMatcher.IsExecutableOrArchive(item.Path))
            .Where(item =>
                !string.IsNullOrWhiteSpace(item.Name))
            .ToArray();

        var deletedTraces = evidence
            .Where(item =>
                item.Kind == EvidenceKind.DeletedFile ||
                (item.Kind == EvidenceKind.UsnJournal &&
                 MetaBool(item, "IsDeleteEvent")))
            .Where(item =>
                RuleMatcher.IsExecutableOrArchive(
                    item.Name ?? item.Path))
            .Where(item =>
                !string.IsNullOrWhiteSpace(item.Name))
            .ToArray();

        foreach (EvidenceRecord browserDownload in browserDownloads)
        {
            string normalized =
                Normalize(browserDownload.Name);

            if (string.IsNullOrWhiteSpace(normalized))
                continue;

            EvidenceRecord? deleted = deletedTraces
                .Where(item =>
                    Normalize(item.Name) == normalized)
                .OrderByDescending(item =>
                    item.Timestamp)
                .FirstOrDefault();

            if (deleted is null)
                continue;

            string combined =
                string.Join(
                    " ",
                    browserDownload.Name,
                    browserDownload.Path,
                    browserDownload.Url,
                    deleted.Name,
                    deleted.Path);

            if (RuleMatcher.FindKnownCheatName(
                    combined,
                    rules) is not null)
                continue;

            bool knownDomain =
                RuleMatcher.IsKnownDomain(
                    browserDownload.Url,
                    rules);

            bool high =
                RuleMatcher.ContainsHigh(
                    combined,
                    rules);

            findings.Add(F(
                "DGS-CORR-DELETED-DOWNLOAD-025",
                knownDomain || high
                    ? FindingSeverity.High
                    : FindingSeverity.Warning,
                knownDomain || high
                    ? 64
                    : 42,
                knownDomain || high
                    ? "Suspicious download was later deleted"
                    : "Downloaded executable/archive was later deleted",
                knownDomain || high
                    ? "The same executable/archive appeared in a browser download record and an independent deletion trace, with additional high-risk or known-domain evidence."
                    : "The same executable/archive appeared in both browser download history and an independent Recycle Bin or USN deletion trace. This confirms download-and-delete activity but does not by itself prove cheating.",
                deleted,
                "Browser download + independent deletion trace",
                $"Browser source: {browserDownload.Url}",
                $"Deleted trace source: {deleted.Source}",
                "Manual verification required"));
        }

        var downloads = evidence
            .Where(x => (x.Kind == EvidenceKind.Browser && x.Metadata.GetValueOrDefault("RecordType") == "Download") ||
                        (x.Kind == EvidenceKind.FileArtifact && x.Metadata.GetValueOrDefault("RecordType") == "RecentDownloadArtifact"))
            .Where(x => !string.IsNullOrWhiteSpace(x.Name))
            .GroupBy(x => Normalize(x.Name), StringComparer.OrdinalIgnoreCase)
            .Where(x => !string.IsNullOrWhiteSpace(x.Key));

        foreach (var group in downloads)
        {
            EvidenceRecord? browser = group.FirstOrDefault(x => x.Kind == EvidenceKind.Browser);
            EvidenceRecord? file = group.FirstOrDefault(x => x.Kind == EvidenceKind.FileArtifact);
            if (browser is null || file is null) continue;

            int staticScore = MetaInt(file, "StaticRiskScore");
            int archiveStatic = MetaInt(file, "ArchiveStaticScore");
            int archiveExecutables = MetaInt(file, "ArchiveExecutableCount");
            bool strong = staticScore >= 45 || archiveStatic >= 40;
            bool payload = archiveExecutables > 0 || RuleMatcher.IsExecutableOrArchive(file.Path);
            if (!payload && !strong) continue;

            findings.Add(F("DGS-CORR-020", strong ? FindingSeverity.High : FindingSeverity.Warning,
                strong ? 58 : 30,
                "Correlated browser download and local file",
                strong
                    ? "The same download exists locally and has supporting static indicators."
                    : "The same recent executable/archive appears in browser history and on disk; this alone is not proof of cheating.",
                file, "Browser + local-file correlation",
                strong ? "Supporting static indicators" : "Generic executable/archive payload"));
        }
    }

    private static ScanFinding Named(
        string id,
        FindingSeverity severity,
        int score,
        string title,
        string summary,
        EvidenceRecord evidence,
        KnownCheatNameEntry named,
        string method,
        params string[] reasons) => new()
    {
        RuleId = id,
        Severity = severity,
        Score = score,
        Title = title,
        Summary = summary,
        EvidenceSource = evidence.Source,
        Path = evidence.Path ?? evidence.Url,
        HashSha256 = evidence.HashSha256,
        Timestamp = evidence.Timestamp,
        DetectedCheatName = named.Name,
        CheatFamily = named.Family,
        DetectionMethod = method,
        Reasons = reasons
    };

    private static int MetaInt(EvidenceRecord item, string key) =>
        item.Metadata.TryGetValue(key, out string? value) && int.TryParse(value, out int parsed) ? parsed : 0;

    private static bool MetaBool(EvidenceRecord item, string key) =>
        item.Metadata.TryGetValue(key, out string? value) && bool.TryParse(value, out bool parsed) && parsed;

    private static string Normalize(string name) =>
        new string(Path.GetFileNameWithoutExtension(name).ToLowerInvariant().Where(char.IsLetterOrDigit).ToArray());

    private static ScanFinding F(
        string id,
        FindingSeverity severity,
        int score,
        string title,
        string summary,
        EvidenceRecord evidence,
        params string[] reasons) => new()
    {
        RuleId = id,
        Severity = severity,
        Score = score,
        Title = title,
        Summary = summary,
        EvidenceSource = evidence.Source,
        Path = evidence.Path ?? evidence.Url,
        HashSha256 = evidence.HashSha256,
        Timestamp = evidence.Timestamp,
        Reasons = reasons
    };
}
