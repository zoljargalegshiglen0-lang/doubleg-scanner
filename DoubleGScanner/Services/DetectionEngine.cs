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
                item.Metadata.GetValueOrDefault("ShortcutFileName"),
                item.Metadata.GetValueOrDefault("ShortcutPath"),
                item.Metadata.GetValueOrDefault("TargetPath"),
                item.Metadata.GetValueOrDefault("Arguments"),
                item.Metadata.GetValueOrDefault("WorkingDirectory"),
                item.Metadata.GetValueOrDefault("InternetUrl"),
                item.Metadata.GetValueOrDefault("ArchiveIndicators"),
                item.Metadata.GetValueOrDefault("StaticIndicators"),
                item.Metadata.GetValueOrDefault("AccessRights"),
                item.Metadata.GetValueOrDefault("GrantedAccessHex"),
                item.Metadata.GetValueOrDefault("WindowTitle"),
                item.Metadata.GetValueOrDefault("WindowClass"),
                item.Metadata.GetValueOrDefault("TaskPath"),
                item.Metadata.GetValueOrDefault("TaskCommand"),
                item.Metadata.GetValueOrDefault("ServiceCommand"),
                item.Metadata.GetValueOrDefault("ServiceDll"),
                item.Metadata.GetValueOrDefault("HardwareIds"),
                item.Metadata.GetValueOrDefault("CompatibleIds"),
                item.Metadata.GetValueOrDefault("DmaAlias"),
                item.Metadata.GetValueOrDefault("FpgaAlias"),
                item.Metadata.GetValueOrDefault("MappedPath"),
                item.Metadata.GetValueOrDefault("Protection"),
                item.Metadata.GetValueOrDefault("MemoryType"));

            KnownCheatNameEntry? namedCheat = FindQualifiedKnownCheatName(item, combined, rules);
            if (namedCheat is not null)
                AddNamedCheatFinding(item, namedCheat, findings);

            AddGenericFindings(item, combined, rules, findings, namedCheat is not null);
        }

        AddCorrelation(evidence, findings, rules);

        return ConsolidateFindings(findings)
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

        // Browser history, ordinary deleted installers, generic unsigned files and weak
        // static strings must not inflate the case to maximum risk. Confirmed detections
        // contribute their full score; review-only findings contribute a small capped value.
        ScanFinding[] confirmed = findings.Where(IsConfirmedDetectionFinding).ToArray();
        int confirmedRisk = confirmed.Sum(x => x.Score);
        int reviewRisk = Math.Min(20, findings
            .Where(x => !IsConfirmedDetectionFinding(x) && x.Score >= 50)
            .Sum(x => Math.Min(5, x.Score)));
        int risk = Math.Min(200, confirmedRisk + reviewRisk);

        // A confirmed cheat/threat remains a detection even when another optional
        // or forensic coverage module is unavailable. Coverage limitations are still
        // shown separately in the report's trust map.
        if (confirmed.Length > 0)
            return (ScanVerdict.Detected, risk);

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

        if (findings.Any(x => x.Score >= 50 && (x.Severity is FindingSeverity.High or FindingSeverity.Critical)))
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
            Title = $"THREAT DETECTED - {threat}",
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
        string browserRecordType = item.Metadata.GetValueOrDefault("RecordType") ?? "";

        bool browserDownload = item.Kind == EvidenceKind.Browser &&
                               browserRecordType.Equals("Download", StringComparison.OrdinalIgnoreCase);
        bool browserVisit = item.Kind == EvidenceKind.Browser &&
                            browserRecordType.Equals("Visit", StringComparison.OrdinalIgnoreCase);
        bool browserSearch = item.Kind == EvidenceKind.Browser &&
                             IsSearchEngineUrl(item.Url) &&
                             HasExplicitCheatSearchContext(item.Url, named);
        bool recoveredBrowser = item.Kind == EvidenceKind.Browser &&
                                browserRecordType.Equals("RecoveredBrowserFragment", StringComparison.OrdinalIgnoreCase);
        bool communitySource = named.Family.Contains("Community", StringComparison.OrdinalIgnoreCase);
        bool cs2Module = item.Kind == EvidenceKind.Module &&
                         string.Equals(item.Metadata.GetValueOrDefault("ProcessName"), "cs2.exe", StringComparison.OrdinalIgnoreCase);
        bool directNamedArtifact = ArtifactDirectlyNamesCheat(item, named);
        bool strongStatic = HasStrongStaticCheatEvidence(item);
        bool embeddedNamedEvidence = binary && NamedAppearsInTechnicalMetadata(item, named) &&
                                     !IsDeveloperPackageCollision(item);
        bool technicalSupport = strongStatic || embeddedNamedEvidence || archiveStatic >= 70 ||
                                (directNamedArtifact && archiveExecutables > 0) ||
                                (directNamedArtifact && unsigned && userWritable);

        if (cs2Module && directNamedArtifact)
        {
            findings.Add(Named("DGS-NAMED-MODULE", FindingSeverity.Critical, 98,
                $"CHEAT DETECTED - {named.Name}",
                $"The known CS2 cheat {named.Name} was found as a module loaded by cs2.exe.", item, named,
                "Known cheat module loaded by cs2.exe", "CONFIRMED CHEAT", "Loaded by cs2.exe"));
            return;
        }

        if (item.Kind == EvidenceKind.Process && directNamedArtifact && executableOrArchive &&
            userWritable && item.IsSignatureValid != true)
        {
            findings.Add(Named("DGS-NAMED-PROCESS", FindingSeverity.Critical, 96,
                $"CHEAT DETECTED - {named.Name}",
                $"The known CS2 cheat {named.Name} was found running from a user-writable location.", item, named,
                "Known cheat process currently running", "CONFIRMED CHEAT", "Running process", "User-writable path"));
            return;
        }

        if (item.Kind == EvidenceKind.FileArtifact && recentDownload && executableOrArchive &&
            directNamedArtifact && technicalSupport)
        {
            findings.Add(Named("DGS-NAMED-DOWNLOAD", FindingSeverity.Critical, 92,
                $"CHEAT DETECTED - {named.Name}",
                $"A downloaded executable/archive for the known CS2 cheat {named.Name} was found with supporting technical evidence.",
                item, named, "Named cheat download + technical evidence", "CONFIRMED CHEAT",
                strongStatic ? "Distinctive cheat feature/loader indicators" : "Named executable/archive payload"));
            return;
        }

        if (item.Kind == EvidenceKind.RawDeletedFile)
        {
            // Unallocated clusters do not preserve reliable file identity, execution state,
            // original path, or complete binary contents. A product-name string in free
            // space must never become a confirmed cheat detection by itself.
            if (!HasRawExecutableStructure(item) || !strongStatic || IsAmbiguousKnownCheatName(named))
                return;

            int rawStaticScore = MetaInt(item, "StaticRiskScore");
            findings.Add(Named("DGS-NAMED-RAW-DELETED-REVIEW", FindingSeverity.Warning,
                rawStaticScore >= 85 ? 36 : 28,
                $"HISTORICAL CHEAT-LIKE FRAGMENT - {named.Name}",
                $"A deleted PE-like fragment in unallocated NTFS space contained the name {named.Name} together with distinctive cheat-like indicators. This is historical review evidence only and does not prove installation or execution.",
                item, named, "Unallocated-space fragment requiring review", "NOT CONFIRMED",
                "Original file identity is unavailable",
                "No execution proof",
                "Content was analyzed in memory; the file was not restored"));
            return;
        }

        if (item.Kind == EvidenceKind.Execution && directNamedArtifact && executableOrArchive)
        {
            findings.Add(Named("DGS-NAMED-EXECUTION", FindingSeverity.Critical, 88,
                $"CHEAT EXECUTION DETECTED - {named.Name}",
                $"Windows execution records show that the known CS2 cheat {named.Name} was executed.",
                item, named, "Named cheat in Windows execution artifact", "CONFIRMED CHEAT EXECUTION"));
            return;
        }

        if (item.Kind == EvidenceKind.FileArtifact && executableOrArchive &&
            (directNamedArtifact || strongStatic || embeddedNamedEvidence))
        {
            if (technicalSupport)
            {
                findings.Add(Named("DGS-NAMED-FILE", FindingSeverity.High, 82,
                    $"CHEAT DETECTED - {named.Name}",
                    $"A local executable/archive was identified as the known CS2 cheat {named.Name} and contains supporting technical indicators.",
                    item, named, "Named cheat artifact + technical evidence", "CONFIRMED CHEAT",
                    strongStatic ? "Distinctive cheat feature/loader indicators" :
                    embeddedNamedEvidence ? "Embedded known cheat-family marker" : "Named unsigned artifact"));
            }
            else
            {
                findings.Add(Named("DGS-NAMED-FILE-REVIEW", FindingSeverity.Warning, 32,
                    $"POSSIBLE CHEAT FILE - {named.Name}",
                    $"The file name references the known CS2 cheat {named.Name}, but stronger proof was not found.",
                    item, named, "Name match only", "NOT CONFIRMED", "Manual verification required"));
            }
            return;
        }

        if (item.Kind == EvidenceKind.DeletedFile && directNamedArtifact && executableOrArchive)
        {
            findings.Add(Named("DGS-NAMED-DELETED", FindingSeverity.Warning, 48,
                $"DELETED CHEAT TRACE - {named.Name}",
                $"Deleted-file metadata referenced an executable/archive named after the known CS2 cheat {named.Name}. This does not prove execution.",
                item, named, "Named cheat in deleted-file metadata", "SUPPORTING TRACE"));
            return;
        }

        if (item.Kind == EvidenceKind.UsnJournal && directNamedArtifact && executableOrArchive)
        {
            bool deletion = MetaBool(item, "IsDeleteEvent");
            findings.Add(Named(deletion ? "DGS-NAMED-USN-DELETE" : "DGS-NAMED-USN",
                FindingSeverity.Warning, deletion ? 46 : 24,
                deletion ? $"DELETED CHEAT TRACE - {named.Name}" : $"CHEAT FILESYSTEM TRACE - {named.Name}",
                deletion
                    ? $"The NTFS journal recorded deletion/rename activity for a file named after the known CS2 cheat {named.Name}."
                    : $"The NTFS journal contains a filesystem record named after the known CS2 cheat {named.Name}.",
                item, named, "Named cheat in NTFS journal", "SUPPORTING TRACE", "Manual verification required"));
            return;
        }

        if (item.Kind == EvidenceKind.NtfsMetadata && directNamedArtifact && executableOrArchive)
        {
            findings.Add(Named("DGS-NAMED-MFT", FindingSeverity.Warning, 22,
                $"CHEAT FILE METADATA - {named.Name}",
                $"NTFS metadata contains a file named after the known CS2 cheat {named.Name}; metadata alone does not prove use.",
                item, named, "Named cheat in MFT metadata", "SUPPORTING TRACE"));
            return;
        }

        if (item.Kind == EvidenceKind.Browser && communitySource)
        {
            findings.Add(Named("DGS-NAMED-COMMUNITY-BROWSER", FindingSeverity.Warning, 14,
                $"CHEAT COMMUNITY WEBSITE TRACE - {named.Name}",
                "A browser record referenced a community cheat-release source. This is browser history only and is not proof that a cheat was installed or used.",
                item, named, "Community release source in browser data", "BROWSER ONLY - NOT PROOF OF USE"));
            return;
        }

        if (browserDownload)
        {
            findings.Add(Named("DGS-NAMED-BROWSER-DOWNLOAD", FindingSeverity.Warning, 42,
                $"CHEAT DOWNLOAD HISTORY - {named.Name}",
                $"Browser download history referenced the known CS2 cheat {named.Name}. A download record alone does not prove execution.",
                item, named, "Known cheat in browser download history", "BROWSER ONLY - NOT CONFIRMED"));
            return;
        }

        if (browserSearch)
        {
            findings.Add(Named("DGS-NAMED-BROWSER-SEARCH", FindingSeverity.Warning, 30,
                $"CHEAT SEARCH HISTORY - {named.Name}",
                $"Browser history shows an explicit search for the known CS2 cheat {named.Name}. This is relevant review evidence, but it does not prove download, installation, or execution.",
                item, named, "Explicit cheat-related search query", "BROWSER SEARCH ONLY - NOT PROOF OF USE"));
            return;
        }

        if (browserVisit)
        {
            findings.Add(Named("DGS-NAMED-BROWSER-VISIT", FindingSeverity.Warning, 24,
                $"CHEAT WEBSITE VISITED - {named.Name}",
                $"Browser history shows a visit to a website/page associated with the known CS2 cheat {named.Name}. This does not prove the cheat was downloaded or run.",
                item, named, "Known cheat website in browser history", "BROWSER ONLY - NOT PROOF OF USE"));
            return;
        }

        if (recoveredBrowser)
        {
            findings.Add(Named("DGS-NAMED-BROWSER-RECOVERED", FindingSeverity.Warning, 18,
                $"RECOVERED CHEAT WEBSITE TRACE - {named.Name}",
                $"A residual browser fragment referenced the known CS2 cheat {named.Name}. The record may be stale or deleted and has no reliable execution meaning.",
                item, named, "Residual browser storage", "BROWSER ONLY - NOT PROOF OF USE"));
            return;
        }

        // A bare name/alias match is retained in the evidence JSON, but it is not
        // promoted to a report finding. This prevents package names such as
        // @sapphire/* and ordinary product/file names from being labelled as cheats.
    }

    private static void AddGenericFindings(
        EvidenceRecord item,
        string combined,
        RuleSet rules,
        List<ScanFinding> findings,
        bool hasNamedCheatMatch)
    {
        bool high = RuleMatcher.ContainsHigh(combined, rules);
        bool medium = RuleMatcher.ContainsMedium(combined, rules);
        bool userWritable = RuleMatcher.IsUserWritable(item.Path);
        bool trusted = RuleMatcher.IsTrustedPublisher(item.Publisher, rules);
        bool benignStaticTarget = IsKnownBenignStaticTarget(item, rules);
        bool strongStaticCheatEvidence = HasStrongStaticCheatEvidence(item);

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

        if (item.Kind == EvidenceKind.ProcessHandle)
        {
            bool dangerous = MetaBool(item, "DangerousWriteOrInjectionAccess");
            bool vmRead = MetaBool(item, "HasVmRead");
            bool unsignedOrUnknown = item.IsSignatureValid != true;
            bool knownWindowsSystemProcess = IsKnownWindowsSystemProcess(item);

            if (dangerous && userWritable && unsignedOrUnknown && !trusted && !knownWindowsSystemProcess)
            {
                findings.Add(F(
                    "DGS-HANDLE-026",
                    FindingSeverity.Critical,
                    94,
                    "Untrusted process has injection-capable access to CS2",
                    "A process from a user-writable location holds a live CS2 handle containing memory-write, memory-operation, or remote-thread style rights.",
                    item,
                    item.Metadata.GetValueOrDefault("AccessRights") ?? "Dangerous process rights",
                    "User-writable executable",
                    "Publisher/signature not trusted"));
            }
            else if (dangerous && !trusted && !knownWindowsSystemProcess)
            {
                findings.Add(F(
                    "DGS-HANDLE-027",
                    FindingSeverity.High,
                    72,
                    "Process has injection-capable access to CS2",
                    "A non-trusted process currently holds a CS2 handle with rights that can support memory modification or thread injection. Legitimate overlays and security tools can also request some of these rights.",
                    item,
                    item.Metadata.GetValueOrDefault("AccessRights") ?? "Dangerous process rights",
                    "Live handle relationship",
                    "Manual verification required"));
            }
            else if (vmRead && unsignedOrUnknown && !trusted && !knownWindowsSystemProcess)
            {
                findings.Add(F(
                    "DGS-HANDLE-028",
                    FindingSeverity.Warning,
                    30,
                    "Unsigned process can read CS2 memory",
                    "A non-trusted process holds a live CS2 handle with VM_READ access. Read access alone is supporting evidence and may be legitimate.",
                    item,
                    item.Metadata.GetValueOrDefault("AccessRights") ?? "PROCESS_VM_READ",
                    "Manual verification required"));
            }
        }

        if (item.Kind == EvidenceKind.Overlay)
        {
            bool strongOverlay = MetaBool(item, "StrongOverlayPattern");
            if (strongOverlay && userWritable && item.IsSignatureValid != true && !trusted)
            {
                findings.Add(F(
                    "DGS-OVERLAY-029",
                    FindingSeverity.High,
                    70,
                    "Untrusted overlay-style window overlaps CS2",
                    "A layered/click-through/topmost style window substantially overlaps CS2 and belongs to an unsigned or untrusted executable in a user-writable location.",
                    item,
                    item.Metadata.GetValueOrDefault("WindowTitle") ?? "Overlay window",
                    item.Metadata.GetValueOrDefault("WindowClass") ?? "Unknown window class",
                    "Overlay pattern is not conclusive by itself"));
            }
            else if (strongOverlay && !trusted)
            {
                findings.Add(F(
                    "DGS-OVERLAY-030",
                    FindingSeverity.Warning,
                    34,
                    "Overlay-style window requires review",
                    "A window with overlay-like properties substantially overlaps CS2. Steam, Discord, capture tools, GPU utilities, and accessibility software can produce similar windows.",
                    item,
                    item.Metadata.GetValueOrDefault("WindowTitle") ?? "Overlay window",
                    "Manual verification required"));
            }
        }

        if (item.Kind == EvidenceKind.Persistence)
        {
            bool userWritableTarget = MetaBool(item, "UserWritableTarget") || userWritable;
            bool autoOrEnabled = MetaBool(item, "AutomaticStart") || MetaBool(item, "Enabled");
            string recordType = item.Metadata.GetValueOrDefault("RecordType") ?? "Persistence";
            bool unsignedOrUnknown = item.IsSignatureValid != true;

            if (autoOrEnabled && userWritableTarget && unsignedOrUnknown && (high || RuleMatcher.FindKnownCheatName(combined, rules) is not null))
            {
                findings.Add(F(
                    "DGS-PERSIST-031",
                    FindingSeverity.Critical,
                    82,
                    "Suspicious automatic persistence target",
                    "An enabled scheduled task or automatic service launches an unsigned/untrusted executable from a user-writable path and also matches high-risk or named cheat metadata.",
                    item,
                    recordType,
                    "Automatic or enabled persistence",
                    "User-writable target"));
            }
            else if (autoOrEnabled && userWritableTarget && unsignedOrUnknown)
            {
                findings.Add(F(
                    "DGS-PERSIST-032",
                    FindingSeverity.Warning,
                    36,
                    "Unsigned user-writable persistence target",
                    "An enabled scheduled task or automatic Windows service launches an unsigned or unverified executable from a user-writable directory.",
                    item,
                    recordType,
                    "Persistence alone is not cheat proof"));
            }
        }

        if (item.Kind == EvidenceKind.MemoryRegion)
        {
            bool privateExecutable = MetaBool(item, "ExecutablePrivateMemory");
            int threadStartCount = MetaInt(item, "ThreadStartCount");
            long regionSize = MetaLong(item, "RegionSize");
            bool mappedWithoutPath =
                string.Equals(item.Metadata.GetValueOrDefault("RecordType"), "MappedExecutableRegion", StringComparison.OrdinalIgnoreCase) &&
                string.IsNullOrWhiteSpace(item.Metadata.GetValueOrDefault("MappedPath"));

            if (privateExecutable && threadStartCount > 0)
            {
                findings.Add(F(
                    "DGS-MEMORY-033",
                    FindingSeverity.Critical,
                    96,
                    "CS2 thread starts inside private executable memory",
                    "At least one CS2 thread start address falls inside an executable MEM_PRIVATE region that is not part of a normal loaded image module. The scanner did not read region contents.",
                    item,
                    $"Thread starts in region: {threadStartCount}",
                    item.Metadata.GetValueOrDefault("Protection") ?? "Executable protection",
                    "Manual-map/injection-style memory anomaly"));
            }
            else if (privateExecutable && regionSize >= 65536)
            {
                findings.Add(F(
                    "DGS-MEMORY-034",
                    FindingSeverity.High,
                    62,
                    "Large private executable region inside CS2",
                    "CS2 contains a committed executable MEM_PRIVATE region outside normal image modules. JIT, security, capture, and compatibility components can sometimes create legitimate regions.",
                    item,
                    $"Region size: {regionSize:N0} bytes",
                    item.Metadata.GetValueOrDefault("Protection") ?? "Executable protection",
                    "Manual verification required"));
            }
            else if (mappedWithoutPath)
            {
                findings.Add(F(
                    "DGS-MEMORY-035",
                    FindingSeverity.Warning,
                    40,
                    "Executable mapped region has no resolved image path",
                    "An executable mapped region inside CS2 could not be resolved to a normal loaded image path.",
                    item,
                    "Memory-map anomaly",
                    "Manual verification required"));
            }
        }

        if (item.Kind == EvidenceKind.DmaDevice)
        {
            if (MetaBool(item, "DmaAliasMatch"))
            {
                findings.Add(F(
                    "DGS-DMA-036",
                    FindingSeverity.Warning,
                    38,
                    "DMA-tooling/device alias found in PnP metadata",
                    "PCI/USB device metadata contains a distinctive alias associated with DMA tooling or commercial DMA hardware. Hardware IDs and names can be spoofed, and this finding is not proof without independent software or activity evidence.",
                    item,
                    item.Metadata.GetValueOrDefault("DmaAlias") ?? "DMA alias",
                    "Hardware metadata only",
                    "Correlation required"));
            }
            else if (MetaBool(item, "FpgaReviewMatch"))
            {
                findings.Add(F(
                    "DGS-DMA-037",
                    FindingSeverity.Information,
                    0,
                    "FPGA-capable device present",
                    "PnP metadata contains an FPGA-related alias. FPGA devices have many legitimate uses and are listed for review only.",
                    item,
                    item.Metadata.GetValueOrDefault("FpgaAlias") ?? "FPGA alias",
                    "Not cheat evidence"));
            }
        }

        if (item.Kind == EvidenceKind.Browser)
        {
            if (!hasNamedCheatMatch && RuleMatcher.IsKnownDomain(item.Url, rules))
                findings.Add(F("DGS-WEB-005", FindingSeverity.Warning, 18,
                    "CHEAT WEBSITE HISTORY TRACE",
                    "A browser record matched a known cheat-related domain. Browser history alone is not proof of installation or use.",
                    item, "BROWSER ONLY - NOT PROOF OF USE"));
            else if (!hasNamedCheatMatch && high && (RuleMatcher.IsExecutableOrArchive(item.Path) || item.Metadata.GetValueOrDefault("RecordType") == "Download"))
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

        if (!hasNamedCheatMatch && !benignStaticTarget && strongStaticCheatEvidence &&
            item.Kind == EvidenceKind.Execution)
        {
            bool missing = !string.IsNullOrWhiteSpace(item.Path) && !File.Exists(item.Path);
            findings.Add(F("DGS-EXEC-007", FindingSeverity.High, missing ? 64 : 72,
                "UNKNOWN CHEAT / INJECTOR EXECUTION TRACE",
                "Windows retained an execution record for a binary containing distinctive cheat or injector indicators.",
                item, "Distinctive cheat/loader indicators", missing ? "Referenced file is missing" : "Artifact remains"));
        }

        if (item.Kind == EvidenceKind.RawDeletedFile)
        {
            int rawStaticScore = MetaInt(item, "StaticRiskScore");

            // Free-space fragments are volatile historical residue. Keep only fragments
            // that still look like executable content AND contain multiple distinctive
            // cheat/injection indicators. They remain review-only and never trigger DETECTED.
            if (rawStaticScore >= 80 && HasRawExecutableStructure(item) && strongStaticCheatEvidence)
            {
                findings.Add(F(
                    "DGS-RAW-022-REVIEW",
                    FindingSeverity.Warning,
                    34,
                    "Deleted executable fragment requires review",
                    "A PE-like fragment in unallocated NTFS space contained multiple distinctive cheat/injection indicators. The original file, path, hash, and execution state are unavailable, so this is not a confirmed cheat detection.",
                    item,
                    $"Static score: {rawStaticScore}/100",
                    item.Metadata.GetValueOrDefault("StaticIndicators") ?? "Static indicators",
                    "HISTORICAL TRACE - NOT PROOF OF USE"));
            }
        }

        bool isDriver = item.Kind == EvidenceKind.FileArtifact && item.Metadata.GetValueOrDefault("RecordType") == "Driver";
        if (isDriver && item.IsSignatureValid == false && userWritable)
            findings.Add(F("DGS-DRV-009", FindingSeverity.Critical, 80,
                "Unsigned driver from a user-writable location",
                "A registered driver resolved to a user-writable path and lacked a valid signature.",
                item, "Registered driver", "User-writable path", "Invalid or absent signature"));
        else if (!hasNamedCheatMatch && !benignStaticTarget && strongStaticCheatEvidence &&
                 item.Kind == EvidenceKind.FileArtifact && high && userWritable && item.IsSignatureValid != true)
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

            if (!hasNamedCheatMatch && !benignStaticTarget && staticScore >= 70 && strongStaticCheatEvidence)
                findings.Add(F("DGS-STATIC-014", FindingSeverity.High, 74,
                    "UNKNOWN CHEAT / INJECTOR BINARY",
                    "The binary contains distinctive cheat features or driver-mapper indicators together with CS2/injection evidence. No product name was identified.",
                    item, $"Static score: {staticScore}/100", item.Metadata.GetValueOrDefault("StaticIndicators") ?? "Distinctive static indicators"));

            if (!hasNamedCheatMatch && !benignStaticTarget && archiveExecutables > 0 && archiveStatic >= 70 && strongStaticCheatEvidence)
                findings.Add(F("DGS-ARCHIVE-016", FindingSeverity.High, 68,
                    "ARCHIVE CONTAINS UNKNOWN CHEAT / INJECTOR PAYLOAD",
                    "The archive contains executable/script payloads with distinctive cheat or loader indicators.",
                    item, $"Executable/script entries: {archiveExecutables}", $"Embedded static score: {archiveStatic}/100"));

            // Generic unsigned executables, normal installers, unreadable archives and
            // binaries containing only OpenProcess/client.dll strings remain in JSON
            // evidence but are intentionally omitted from cheat findings.
        }

        if (item.Kind == EvidenceKind.Network && high)
            findings.Add(F("DGS-NET-011", FindingSeverity.Warning, 22,
                "Suspiciously named process has a live connection",
                "A process matching a high-risk term had an active TCP connection.", item, "Live network connection"));

        // Generic medium-risk words are evidence metadata only. They are not
        // promoted to findings because words such as loader, client.dll, service,
        // bhop or OpenProcess occur in many legitimate products and SDK packages.
        _ = medium;
        _ = trusted;
    }

    private static void AddCorrelation(
        IReadOnlyList<EvidenceRecord> evidence,
        List<ScanFinding> findings,
        RuleSet rules)
    {
        var dangerousHandles = evidence
            .Where(item => item.Kind == EvidenceKind.ProcessHandle && MetaBool(item, "DangerousWriteOrInjectionAccess"))
            .ToArray();

        var strongOverlays = evidence
            .Where(item => item.Kind == EvidenceKind.Overlay && MetaBool(item, "StrongOverlayPattern"))
            .ToArray();

        foreach (EvidenceRecord handle in dangerousHandles)
        {
            EvidenceRecord? overlay = strongOverlays.FirstOrDefault(item => item.ProcessId == handle.ProcessId);
            if (overlay is null) continue;

            bool userWritable = RuleMatcher.IsUserWritable(handle.Path) || RuleMatcher.IsUserWritable(overlay.Path);
            bool untrusted = !RuleMatcher.IsTrustedPublisher(handle.Publisher ?? overlay.Publisher, rules);
            findings.Add(F(
                "DGS-CORR-HANDLE-OVERLAY-038",
                userWritable && untrusted ? FindingSeverity.Critical : FindingSeverity.High,
                userWritable && untrusted ? 97 : 78,
                "Same process overlays CS2 and holds injection-capable CS2 access",
                "One process independently matched both a live CS2 handle with memory-modification/thread rights and a strong overlay-style window relationship.",
                handle,
                $"Process ID: {handle.ProcessId}",
                handle.Metadata.GetValueOrDefault("AccessRights") ?? "Dangerous process rights",
                overlay.Metadata.GetValueOrDefault("WindowTitle") ?? "Overlay window"));
        }

        var privateThreadRegions = evidence
            .Where(item => item.Kind == EvidenceKind.MemoryRegion && MetaBool(item, "ExecutablePrivateMemory") && MetaInt(item, "ThreadStartCount") > 0)
            .ToArray();

        if (privateThreadRegions.Length > 0 && dangerousHandles.Length > 0)
        {
            EvidenceRecord region = privateThreadRegions.OrderByDescending(item => MetaInt(item, "ThreadStartCount")).First();
            EvidenceRecord handle = dangerousHandles.First();
            findings.Add(F(
                "DGS-CORR-MEMORY-HANDLE-039",
                FindingSeverity.Critical,
                99,
                "CS2 private executable-thread anomaly correlated with external process access",
                "CS2 contains a thread starting in private executable memory while another process holds injection-capable access to CS2. This is a high-confidence integrity correlation, though final attribution still requires analyst review.",
                region,
                $"External process: {handle.Name} (PID {handle.ProcessId})",
                handle.Metadata.GetValueOrDefault("AccessRights") ?? "Dangerous process rights",
                $"Thread starts: {region.Metadata.GetValueOrDefault("ThreadStartCount")}"));
        }

        var dmaDevices = evidence
            .Where(item => item.Kind == EvidenceKind.DmaDevice && MetaBool(item, "DmaAliasMatch"))
            .ToArray();

        if (dmaDevices.Length > 0)
        {
            EvidenceRecord? dmaSoftwareTrace = evidence
                .Where(item => item.Kind != EvidenceKind.DmaDevice)
                .FirstOrDefault(item =>
                {
                    string text = string.Join(" ", item.Name, item.Path, item.Url, item.Detail,
                        item.Metadata.GetValueOrDefault("Arguments"),
                        item.Metadata.GetValueOrDefault("ServiceCommand"),
                        item.Metadata.GetValueOrDefault("TaskCommand"),
                        item.Metadata.GetValueOrDefault("StaticIndicators"));
                    KnownCheatNameEntry? named = RuleMatcher.FindKnownCheatName(text, rules);
                    bool namedDma = named is not null &&
                        (named.Name.Contains("DMA", StringComparison.OrdinalIgnoreCase) ||
                         named.Family.Contains("DMA", StringComparison.OrdinalIgnoreCase));
                    return namedDma ||
                           text.Contains("pcileech", StringComparison.OrdinalIgnoreCase) ||
                           text.Contains("leechcore", StringComparison.OrdinalIgnoreCase) ||
                           text.Contains("ftd3xx", StringComparison.OrdinalIgnoreCase) ||
                           text.Contains("usb3380", StringComparison.OrdinalIgnoreCase);
                });

            if (dmaSoftwareTrace is not null)
            {
                EvidenceRecord device = dmaDevices[0];
                findings.Add(F(
                    "DGS-CORR-DMA-040",
                    FindingSeverity.Critical,
                    92,
                    "DMA hardware alias correlated with local DMA software/activity trace",
                    "A distinctive DMA-related PnP device alias was independently correlated with a local execution, file, browser, service, task, or static-analysis trace associated with DMA tooling. Hardware spoofing and legitimate lab use remain possible.",
                    device,
                    $"DMA alias: {device.Metadata.GetValueOrDefault("DmaAlias")}",
                    $"Software/activity source: {dmaSoftwareTrace.Source}",
                    $"Related artifact: {dmaSoftwareTrace.Path ?? dmaSoftwareTrace.Url ?? dmaSoftwareTrace.Name}"));
            }
        }

        var namedGroups = evidence
            .Select(x => new
            {
                Evidence = x,
                Match = FindQualifiedKnownCheatName(
                    x,
                    string.Join(" ", x.Name, x.Path, x.Url, x.Detail,
                        x.Metadata.GetValueOrDefault("StaticIndicators"),
                        x.Metadata.GetValueOrDefault("ArchiveIndicators")),
                    rules)
            })
            .Where(x => x.Match is not null)
            .GroupBy(x => x.Match!.Name, StringComparer.OrdinalIgnoreCase);

        foreach (var group in namedGroups)
        {
            EvidenceKind[] kinds = group.Select(x => x.Evidence.Kind).Distinct().ToArray();
            bool browser = kinds.Contains(EvidenceKind.Browser);
            bool local = kinds.Contains(EvidenceKind.FileArtifact) || kinds.Contains(EvidenceKind.DeletedFile) ||
                         kinds.Contains(EvidenceKind.NtfsMetadata) || kinds.Contains(EvidenceKind.UsnJournal);
            bool execution = kinds.Contains(EvidenceKind.Execution) || kinds.Contains(EvidenceKind.Process) ||
                             kinds.Contains(EvidenceKind.Module);
            bool strongLocal = group.Any(x =>
                                   x.Evidence.Kind == EvidenceKind.FileArtifact &&
                                   (HasStrongStaticCheatEvidence(x.Evidence) ||
                                    ArtifactDirectlyNamesCheat(x.Evidence, x.Match!))) ||
                               group.Any(x => x.Evidence.Kind is EvidenceKind.Execution or EvidenceKind.Process or EvidenceKind.Module);
            if (!browser || !local || !strongLocal) continue;

            EvidenceRecord primary = group.Select(x => x.Evidence).OrderByDescending(x => x.Timestamp).First();
            KnownCheatNameEntry match = group.First().Match!;
            int score = execution ? 94 : 88;
            findings.Add(Named("DGS-NAMED-CORR", FindingSeverity.Critical, score,
                $"CHEAT DETECTED - {match.Name}",
                execution
                    ? "The same known cheat-family name appeared in browser, local-file, and execution/process evidence."
                    : "The same known cheat-family name appeared independently in browser download and local-file evidence.",
                primary, match, "Independent named-evidence correlation", "CONFIRMED CHEAT", string.Join(", ", kinds)));
        }

        var highRiskGroups = evidence
            .Where(x => ContainsDistinctiveCheatTerm(string.Join(" ", x.Name, x.Path, x.Url, x.Detail,
                x.Metadata.GetValueOrDefault("StaticIndicators"))))
            .Where(x => !string.IsNullOrWhiteSpace(x.Name))
            .GroupBy(x => Normalize(x.Name), StringComparer.OrdinalIgnoreCase);

        foreach (var group in highRiskGroups)
        {
            EvidenceKind[] kinds = group.Select(x => x.Kind).Distinct().ToArray();
            if (kinds.Contains(EvidenceKind.Browser) && kinds.Contains(EvidenceKind.Execution) &&
                (kinds.Contains(EvidenceKind.DeletedFile) || kinds.Contains(EvidenceKind.FileArtifact) || kinds.Contains(EvidenceKind.UsnJournal)))
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

            if (!knownDomain && !ContainsDistinctiveCheatTerm(combined))
                continue;

            findings.Add(F(
                "DGS-CORR-DELETED-DOWNLOAD-025",
                FindingSeverity.Warning,
                46,
                "CHEAT-RELATED DOWNLOAD WAS LATER DELETED",
                "A browser download associated with cheat-related content was independently matched to a deletion trace. This is supporting evidence and does not by itself prove execution.",
                deleted,
                "Browser download + independent deletion trace",
                $"Browser source: {browserDownload.Url}",
                $"Deleted trace source: {deleted.Source}",
                "SUPPORTING TRACE - NOT CONFIRMED"));
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
            bool strong = (staticScore >= 70 || archiveStatic >= 70) && HasStrongStaticCheatEvidence(file);
            bool payload = archiveExecutables > 0 || RuleMatcher.IsExecutableOrArchive(file.Path);
            if (!payload || !strong || IsKnownBenignStaticTarget(file, rules)) continue;

            findings.Add(F("DGS-CORR-020", FindingSeverity.High, 64,
                "UNKNOWN CHEAT DOWNLOAD CORRELATED WITH LOCAL FILE",
                "The same download exists locally and contains distinctive cheat/loader indicators, but a product name was not identified.",
                file, "Browser + local-file correlation", "Distinctive static indicators"));
        }
    }

    private static KnownCheatNameEntry? FindQualifiedKnownCheatName(
        EvidenceRecord item,
        string combined,
        RuleSet rules)
    {
        KnownCheatNameEntry? match = RuleMatcher.FindKnownCheatName(combined, rules);
        if (match is null)
            return null;

        if (item.Kind == EvidenceKind.Browser)
        {
            bool directKnownDomain = RuleMatcher.IsKnownDomain(item.Url, rules);
            bool directName = ArtifactDirectlyNamesCheat(item, match);

            // Explicit Google/Bing/DuckDuckGo searches for a known cheat are retained
            // as review-only browser evidence. ChatGPT conversations and generic media
            // result pages remain suppressed unless they point to a known distribution domain.
            if (IsConversationOrMediaUrl(item.Url) && !directKnownDomain)
                return null;
            if (IsSearchEngineUrl(item.Url) && !directKnownDomain)
                return directName && HasExplicitCheatSearchContext(item.Url, match) ? match : null;

            return directKnownDomain || directName ? match : null;
        }

        bool directArtifact = ArtifactDirectlyNamesCheat(item, match);
        bool technicalMetadata = NamedAppearsInTechnicalMetadata(item, match);
        bool strongStatic = HasStrongStaticCheatEvidence(item);

        // Raw unallocated-space samples commonly contain unrelated words, cache text,
        // scanner signature lists, and partial overwritten data. Require a PE-like
        // structure plus strong technical indicators, and suppress ambiguous brand words.
        if (item.Kind == EvidenceKind.RawDeletedFile)
        {
            return HasRawExecutableStructure(item) &&
                   strongStatic &&
                   !IsAmbiguousKnownCheatName(match)
                ? match
                : null;
        }

        if (IsDeveloperPackageCollision(item) && !directArtifact && !strongStatic)
            return null;

        bool nonBenignBinaryMarker = technicalMetadata &&
                                      RuleMatcher.IsBinary(item.Path ?? item.Name) &&
                                      !IsKnownBenignStaticTarget(item, rules);
        return directArtifact || (technicalMetadata && strongStatic) || nonBenignBinaryMarker ? match : null;
    }

    private static bool ArtifactDirectlyNamesCheat(EvidenceRecord item, KnownCheatNameEntry named)
    {
        string[] candidates =
        {
            item.Name ?? "",
            Path.GetFileNameWithoutExtension(item.Path ?? ""),
            Path.GetFileNameWithoutExtension(item.Metadata.GetValueOrDefault("TargetPath") ?? ""),
            item.Url ?? ""
        };

        string[] aliases = new[] { named.Name }
            .Concat(named.Aliases)
            .Concat(named.ExactAliases)
            .Concat(named.PrefixAliases)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        foreach (string candidate in candidates)
        {
            string normalizedCandidate = NormalizeLoose(candidate);
            if (string.IsNullOrWhiteSpace(normalizedCandidate))
                continue;

            foreach (string alias in aliases)
            {
                string normalizedAlias = NormalizeLoose(alias);
                if (normalizedAlias.Length >= 4 && normalizedCandidate.Contains(normalizedAlias, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }

        return false;
    }

    private static bool NamedAppearsInTechnicalMetadata(EvidenceRecord item, KnownCheatNameEntry named)
    {
        string technical = string.Join(" ",
            item.Metadata.GetValueOrDefault("StaticIndicators"),
            item.Metadata.GetValueOrDefault("ArchiveIndicators"),
            item.Detail);
        string normalized = NormalizeLoose(technical);
        if (string.IsNullOrWhiteSpace(normalized))
            return false;

        return new[] { named.Name }
            .Concat(named.Aliases)
            .Concat(named.ExactAliases)
            .Concat(named.PrefixAliases)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(NormalizeLoose)
            .Any(alias => alias.Length >= 5 && normalized.Contains(alias, StringComparison.OrdinalIgnoreCase));
    }

    private static bool HasStrongStaticCheatEvidence(EvidenceRecord item)
    {
        string indicators = string.Join(" ",
            item.Metadata.GetValueOrDefault("StaticIndicators"),
            item.Metadata.GetValueOrDefault("ArchiveIndicators"),
            item.Detail);
        string text = indicators.ToLowerInvariant();

        string[] directFeatures =
        {
            "aimbot", "triggerbot", "wallhack", "ragebot", "silent aim", "silentaim",
            "skin changer", "skinchanger", "world_to_screen", "worldtoscreen",
            "bone matrix", "bonematrix", "external cheat", "internal cheat",
            "cheat menu", "kdmapper", "iqvw64e.sys", "pcileech", "leechcore"
        };
        string[] injectionApis =
        {
            "writeprocessmemory", "createremotethread", "virtualallocex", "queueuserapc",
            "ntmapviewofsection", "setwindowshookex", "manual map", "manualmap"
        };
        string[] cs2Terms = { "cs2.exe", "counter-strike 2", "counter strike 2", "client.dll" };

        int featureCount = directFeatures.Count(term => text.Contains(term, StringComparison.OrdinalIgnoreCase));
        bool injection = injectionApis.Any(term => text.Contains(term, StringComparison.OrdinalIgnoreCase));
        bool cs2 = cs2Terms.Any(term => text.Contains(term, StringComparison.OrdinalIgnoreCase));
        bool driverMapper = text.Contains("kdmapper", StringComparison.OrdinalIgnoreCase) ||
                            text.Contains("iqvw64e.sys", StringComparison.OrdinalIgnoreCase) ||
                            text.Contains("pcileech", StringComparison.OrdinalIgnoreCase) ||
                            text.Contains("leechcore", StringComparison.OrdinalIgnoreCase);

        return driverMapper || featureCount >= 2 || (featureCount >= 1 && (injection || cs2));
    }

    private static bool ContainsDistinctiveCheatTerm(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return false;
        string text = value.ToLowerInvariant();
        string[] terms =
        {
            "aimbot", "triggerbot", "wallhack", "ragebot", "silentaim", "silent aim",
            "skinchanger", "skin changer", "external cheat", "internal cheat", "cheat menu",
            "kdmapper", "iqvw64e.sys", "pcileech", "leechcore"
        };
        return terms.Any(term => text.Contains(term, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsKnownBenignStaticTarget(EvidenceRecord item, RuleSet rules)
    {
        string path = (item.Path ?? "").Replace('/', '\\').ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(path))
            return false;

        bool trustedSigned = item.IsSignatureValid == true &&
                             (RuleMatcher.IsTrustedPublisher(item.Publisher, rules) || !RuleMatcher.IsUserWritable(item.Path));
        bool knownPlatformPath =
            path.Contains("\\windows\\", StringComparison.OrdinalIgnoreCase) ||
            path.Contains("\\winsxs\\", StringComparison.OrdinalIgnoreCase) ||
            path.Contains("\\programdata\\microsoft\\", StringComparison.OrdinalIgnoreCase) ||
            path.Contains("\\program files\\windowsapps\\microsoft.", StringComparison.OrdinalIgnoreCase) ||
            path.Contains("\\microsoft\\onedrive\\", StringComparison.OrdinalIgnoreCase) ||
            path.Contains("\\githubdesktop\\", StringComparison.OrdinalIgnoreCase) ||
            path.Contains("\\visualstudio\\packages\\", StringComparison.OrdinalIgnoreCase) ||
            path.Contains("\\package cache\\", StringComparison.OrdinalIgnoreCase) ||
            path.Contains("\\windows kits\\", StringComparison.OrdinalIgnoreCase) ||
            path.Contains("\\dotnet\\", StringComparison.OrdinalIgnoreCase) ||
            path.Contains("\\doubleg scanner\\", StringComparison.OrdinalIgnoreCase) ||
            path.EndsWith("\\doublegscanner.exe", StringComparison.OrdinalIgnoreCase);

        return trustedSigned || knownPlatformPath;
    }

    private static bool IsDeveloperPackageCollision(EvidenceRecord item)
    {
        string text = string.Join(" ", item.Path, item.Name, item.Detail,
            item.Metadata.GetValueOrDefault("ArchiveIndicators"),
            item.Metadata.GetValueOrDefault("StaticIndicators")).ToLowerInvariant();
        return text.Contains("node_modules", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("@sapphire/", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("@sapphire\\", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("visualstudio\\packages", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("microsoft.netcore.targetingpack", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("microsoft.windowsdesktop.targetingpack", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("githubdesktop", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("package cache", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsSearchEngineUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url))
            return false;
        string lower = url.ToLowerInvariant();
        return lower.Contains("google.", StringComparison.OrdinalIgnoreCase) ||
               lower.Contains("bing.com/search", StringComparison.OrdinalIgnoreCase) ||
               lower.Contains("duckduckgo.com", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsConversationOrMediaUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url))
            return false;
        string lower = url.ToLowerInvariant();
        return lower.Contains("chatgpt.com/", StringComparison.OrdinalIgnoreCase) ||
               lower.Contains("youtube.com/results", StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasExplicitCheatSearchContext(string? url, KnownCheatNameEntry named)
    {
        if (string.IsNullOrWhiteSpace(url))
            return false;

        string decoded;
        try
        {
            decoded = Uri.UnescapeDataString(url.Replace('+', ' '));
        }
        catch
        {
            decoded = url.Replace('+', ' ');
        }

        string lower = decoded.ToLowerInvariant();
        string[] contextTerms =
        {
            "cs2", "csgo", "counter-strike", "counter strike", "cheat", "hack",
            "aimbot", "triggerbot", "wallhack", "esp", "loader", "injector",
            "external", "internal", "undetected", "free/lite", "download"
        };

        bool hasContext = contextTerms.Any(term => lower.Contains(term, StringComparison.OrdinalIgnoreCase));
        if (hasContext)
            return true;

        // Distinctive product names can still be shown when the search query is
        // exactly the known brand. Common words remain hidden without CS2/cheat context.
        string[] ambiguousNames =
        {
            "midnight", "osiris", "sapphire", "legend", "eclipse", "aurora",
            "fantasy", "precision", "predator", "plague", "airflow", "interium"
        };
        string normalizedName = NormalizeLoose(named.Name);
        bool ambiguous = ambiguousNames.Any(x => NormalizeLoose(x) == normalizedName);
        return !ambiguous && normalizedName.Length >= 6 && NormalizeLoose(decoded).Contains(normalizedName);
    }

    private static bool HasRawExecutableStructure(EvidenceRecord item)
    {
        string signature = string.Join(" ",
            item.Metadata.GetValueOrDefault("SignatureType"),
            item.Metadata.GetValueOrDefault("FileSignature"),
            item.Metadata.GetValueOrDefault("Magic"),
            item.Metadata.GetValueOrDefault("PeHeader"),
            item.Metadata.GetValueOrDefault("StaticIndicators"),
            item.Detail).ToLowerInvariant();

        return MetaBool(item, "HasMzHeader") ||
               MetaBool(item, "HasPeHeader") ||
               MetaBool(item, "ValidPeStructure") ||
               signature.Contains("mz header", StringComparison.OrdinalIgnoreCase) ||
               signature.Contains("pe header", StringComparison.OrdinalIgnoreCase) ||
               signature.Contains("portable executable", StringComparison.OrdinalIgnoreCase) ||
               signature.Contains("pe32", StringComparison.OrdinalIgnoreCase) ||
               signature.Contains("pe64", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsAmbiguousKnownCheatName(KnownCheatNameEntry named)
    {
        string[] ambiguousNames =
        {
            "midnight", "osiris", "sapphire", "legend", "eclipse", "aurora",
            "fantasy", "precision", "predator", "plague", "airflow", "interium",
            "phantom", "nexus", "monolith", "stern", "oxide"
        };

        string normalizedName = NormalizeLoose(named.Name);
        return normalizedName.Length < 6 ||
               ambiguousNames.Any(value => NormalizeLoose(value) == normalizedName);
    }

    private static bool IsKnownWindowsSystemProcess(EvidenceRecord item)
    {
        string path = (item.Path ?? "").Replace('/', '\\').ToLowerInvariant();
        string name = Path.GetFileName(path.Length > 0 ? path : item.Name ?? "").ToLowerInvariant();

        bool systemPath = path.StartsWith(@"c:\windows\system32\", StringComparison.OrdinalIgnoreCase) ||
                          path.StartsWith(@"c:\windows\syswow64\", StringComparison.OrdinalIgnoreCase) ||
                          path.StartsWith(@"c:\windows\winsxs\", StringComparison.OrdinalIgnoreCase);

        string[] standardNames =
        {
            "svchost.exe", "services.exe", "lsass.exe", "wininit.exe", "csrss.exe",
            "dwm.exe", "smss.exe", "taskhostw.exe", "wmiprvse.exe", "spoolsv.exe"
        };

        return systemPath && standardNames.Contains(name, StringComparer.OrdinalIgnoreCase);
    }

    private static bool IsConfirmedDetectionFinding(ScanFinding finding)
    {
        if (finding.RuleId.Equals("DGS-DEFENDER-001", StringComparison.OrdinalIgnoreCase) ||
            finding.RuleId.Equals("DGS-HASH-001", StringComparison.OrdinalIgnoreCase) ||
            finding.RuleId.Equals("DGS-HASH-LEGACY", StringComparison.OrdinalIgnoreCase) ||
            finding.RuleId.Equals("DGS-KERNEL-HASH-001", StringComparison.OrdinalIgnoreCase))
            return true;

        if (finding.RuleId.StartsWith("DGS-NAMED-CORR", StringComparison.OrdinalIgnoreCase) ||
            finding.RuleId.StartsWith("DGS-NAMED-MODULE", StringComparison.OrdinalIgnoreCase) ||
            finding.RuleId.StartsWith("DGS-NAMED-PROCESS", StringComparison.OrdinalIgnoreCase) ||
            finding.RuleId.StartsWith("DGS-NAMED-DOWNLOAD", StringComparison.OrdinalIgnoreCase) ||
            finding.RuleId.StartsWith("DGS-NAMED-EXECUTION", StringComparison.OrdinalIgnoreCase) ||
            (finding.RuleId.Equals("DGS-NAMED-FILE", StringComparison.OrdinalIgnoreCase) && finding.Score >= 75))
            return true;

        return finding.RuleId is "DGS-MEMORY-033" or "DGS-CORR-HANDLE-OVERLAY-038" or
               "DGS-CORR-MEMORY-HANDLE-039" or "DGS-CORR-DMA-040";
    }

    private static string NormalizeLoose(string? value) =>
        string.IsNullOrWhiteSpace(value)
            ? ""
            : new string(value.ToLowerInvariant().Where(char.IsLetterOrDigit).ToArray());

    private static IReadOnlyList<ScanFinding> ConsolidateFindings(
        IReadOnlyList<ScanFinding> findings)
    {
        var output = new List<ScanFinding>();

        // One named cheat/artifact family is reported once, even when the
        // browser, USN, MFT, archive and local-file collectors all saw it.
        foreach (IGrouping<string, ScanFinding> group in findings
                     .Where(item =>
                         !string.IsNullOrWhiteSpace(
                             item.DetectedCheatName))
                     .GroupBy(
                         item => NormalizeDetectionName(
                             item.DetectedCheatName!),
                         StringComparer.OrdinalIgnoreCase))
        {
            ScanFinding strongest = group
                .OrderByDescending(item =>
                    SeverityRank(item.Severity))
                .ThenByDescending(item =>
                    item.Score)
                .ThenByDescending(item =>
                    item.Timestamp)
                .First();

            output.Add(
                MergeFindingGroup(
                    strongest,
                    group.ToArray(),
                    $"Named evidence records: {group.Count():N0}"));
        }

        // Kernel findings often repeat once per loaded Windows driver.
        // Keep one summary per kernel rule instead of dozens of identical cards.
        foreach (IGrouping<string, ScanFinding> group in findings
                     .Where(item =>
                         string.IsNullOrWhiteSpace(
                             item.DetectedCheatName) &&
                         item.RuleId.StartsWith(
                             "DGS-KERNEL-",
                             StringComparison.OrdinalIgnoreCase))
                     .GroupBy(
                         item => item.RuleId,
                         StringComparer.OrdinalIgnoreCase))
        {
            ScanFinding strongest = group
                .OrderByDescending(item =>
                    SeverityRank(item.Severity))
                .ThenByDescending(item =>
                    item.Score)
                .ThenByDescending(item =>
                    item.Timestamp)
                .First();

            output.Add(
                MergeFindingGroup(
                    strongest,
                    group.ToArray(),
                    $"Kernel records combined: {group.Count():N0}"));
        }

        // Preserve unrelated findings, while removing exact duplicates.
        output.AddRange(
            findings
                .Where(item =>
                    string.IsNullOrWhiteSpace(
                        item.DetectedCheatName) &&
                    !item.RuleId.StartsWith(
                        "DGS-KERNEL-",
                        StringComparison.OrdinalIgnoreCase))
                .GroupBy(
                    item =>
                        $"{item.RuleId}|{Normalize(item.Path ?? item.Title)}",
                    StringComparer.OrdinalIgnoreCase)
                .Select(group =>
                    group
                        .OrderByDescending(item =>
                            SeverityRank(item.Severity))
                        .ThenByDescending(item =>
                            item.Score)
                        .ThenByDescending(item =>
                            item.Timestamp)
                        .First()));

        return output;
    }

    private static ScanFinding MergeFindingGroup(
        ScanFinding strongest,
        IReadOnlyList<ScanFinding> group,
        string countReason)
    {
        string[] paths = group
            .Select(item => item.Path)
            .Where(path =>
                !string.IsNullOrWhiteSpace(path))
            .Cast<string>()
            .Distinct(
                StringComparer.OrdinalIgnoreCase)
            .Take(8)
            .ToArray();

        string[] sources = group
            .Select(item => item.EvidenceSource)
            .Where(source =>
                !string.IsNullOrWhiteSpace(source))
            .Distinct(
                StringComparer.OrdinalIgnoreCase)
            .Take(8)
            .ToArray();

        string[] methods = group
            .Select(item => item.DetectionMethod)
            .Where(method =>
                !string.IsNullOrWhiteSpace(method))
            .Cast<string>()
            .Distinct(
                StringComparer.OrdinalIgnoreCase)
            .Take(6)
            .ToArray();

        string[] combinedReasons = group
            .SelectMany(item =>
                item.Reasons)
            .Where(reason =>
                !string.IsNullOrWhiteSpace(reason))
            .Distinct(
                StringComparer.OrdinalIgnoreCase)
            .Take(12)
            .Concat(
                new[]
                {
                    countReason,
                    sources.Length == 0
                        ? ""
                        : $"Sources: {string.Join(", ", sources)}",
                    paths.Length == 0
                        ? ""
                        : $"Artifacts: {string.Join("; ", paths)}"
                })
            .Where(reason =>
                !string.IsNullOrWhiteSpace(reason))
            .ToArray();

        return new ScanFinding
        {
            RuleId = strongest.RuleId,
            Severity = group
                .OrderByDescending(item =>
                    SeverityRank(item.Severity))
                .Select(item =>
                    item.Severity)
                .First(),
            Score = group.Max(item =>
                item.Score),
            Title = strongest.Title,
            Summary = group.Count == 1
                ? strongest.Summary
                : $"{strongest.Summary} {group.Count:N0} related evidence records were combined into this single finding.",
            EvidenceSource = sources.Length == 0
                ? strongest.EvidenceSource
                : string.Join(
                    ", ",
                    sources),
            Path = strongest.Path ??
                   paths.FirstOrDefault(),
            HashSha256 = strongest.HashSha256 ??
                         group
                             .Select(item =>
                                 item.HashSha256)
                             .FirstOrDefault(hash =>
                                 !string.IsNullOrWhiteSpace(hash)),
            Timestamp = group
                .Where(item =>
                    item.Timestamp is not null)
                .OrderByDescending(item =>
                    item.Timestamp)
                .Select(item =>
                    item.Timestamp)
                .FirstOrDefault(),
            DetectedCheatName =
                strongest.DetectedCheatName,
            CheatFamily =
                strongest.CheatFamily ??
                group
                    .Select(item =>
                        item.CheatFamily)
                    .FirstOrDefault(value =>
                        !string.IsNullOrWhiteSpace(value)),
            DetectionMethod = methods.Length switch
            {
                0 => strongest.DetectionMethod,
                1 => methods[0],
                _ => string.Join(
                    "; ",
                    methods)
            },
            Reasons = combinedReasons
        };
    }

    private static int SeverityRank(
        FindingSeverity severity) =>
        severity switch
        {
            FindingSeverity.Critical => 4,
            FindingSeverity.High => 3,
            FindingSeverity.Warning => 2,
            _ => 1
        };

    private static string NormalizeDetectionName(
        string value)
    {
        string normalized =
            new string(
                value
                    .ToLowerInvariant()
                    .Where(char.IsLetterOrDigit)
                    .ToArray());

        return string.IsNullOrWhiteSpace(normalized)
            ? value.Trim().ToLowerInvariant()
            : normalized;
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

    private static long MetaLong(EvidenceRecord item, string key) =>
        item.Metadata.TryGetValue(key, out string? value) && long.TryParse(value, out long parsed) ? parsed : 0L;

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
