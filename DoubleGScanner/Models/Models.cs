namespace DoubleGScanner.Models;

public enum ScanMode { Quick, Full, Forensic }
public enum ScanVerdict { NotDetected, Review, Detected, Incomplete, Cancelled }
public enum FindingSeverity { Information, Warning, High, Critical }
public enum EvidenceKind { System, Process, Module, Browser, Execution, DeletedFile, Network, FileArtifact, Antivirus }
public enum CoverageStatus { Completed, Partial, Unavailable, Skipped, Failed }

public sealed class KnownCheatEntry
{
    public string Name { get; set; } = "";
    public string Family { get; set; } = "";
    public string HashSha256 { get; set; } = "";
    public string SourceNote { get; set; } = "";
}

public sealed class KnownCheatNameEntry
{
    public string Name { get; set; } = "";
    public string Family { get; set; } = "CS2 cheat";
    public List<string> Aliases { get; set; } = new();
}

public sealed class RuleSet
{
    public string Version { get; set; } = "1.8.0";
    public List<KnownCheatEntry> KnownCheats { get; set; } = new();
    public List<KnownCheatNameEntry> KnownCheatNames { get; set; } = new();
    // Legacy exact hashes remain supported, but they cannot show a product/family name.
    public List<string> KnownHashes { get; set; } = new();
    public List<string> KnownDomains { get; set; } = new();
    public List<string> HighRiskKeywords { get; set; } = new();
    public List<string> MediumRiskKeywords { get; set; } = new();
    public List<string> TrustedPublishers { get; set; } = new();
}

public sealed class EvidenceRecord
{
    public EvidenceKind Kind { get; init; }
    public required string Source { get; init; }
    public required string Name { get; init; }
    public string? Path { get; init; }
    public string? Url { get; init; }
    public string? HashSha256 { get; init; }
    public string? Publisher { get; init; }
    public bool? IsSignatureValid { get; init; }
    public int? ProcessId { get; init; }
    public DateTimeOffset? Timestamp { get; init; }
    public string? Detail { get; init; }
    public Dictionary<string,string> Metadata { get; init; } = new(StringComparer.OrdinalIgnoreCase);
}

public sealed class ScanFinding
{
    public required string RuleId { get; init; }
    public required FindingSeverity Severity { get; init; }
    public required int Score { get; init; }
    public required string Title { get; init; }
    public required string Summary { get; init; }
    public required string EvidenceSource { get; init; }
    public string? Path { get; init; }
    public string? HashSha256 { get; init; }
    public DateTimeOffset? Timestamp { get; init; }
    public string? DetectedCheatName { get; init; }
    public string? CheatFamily { get; init; }
    public string? DetectionMethod { get; init; }
    public IReadOnlyList<string> Reasons { get; init; } = Array.Empty<string>();
}

public sealed class ScanCoverage
{
    public required string Module { get; init; }
    public required CoverageStatus Status { get; init; }
    public required string Summary { get; init; }
    public int ItemsChecked { get; init; }
    public TimeSpan Duration { get; init; }
}

public sealed class ScanResult
{
    public required string ScanId { get; init; }
    public required string ScannerVersion { get; init; }
    public required ScanMode Mode { get; init; }
    public required DateTimeOffset StartedAt { get; init; }
    public required DateTimeOffset CompletedAt { get; init; }
    public required ScanVerdict Verdict { get; init; }
    public required int RiskScore { get; init; }
    public required IReadOnlyList<EvidenceRecord> Evidence { get; init; }
    public required IReadOnlyList<ScanFinding> Findings { get; init; }
    public required IReadOnlyList<ScanCoverage> Coverage { get; init; }
    public required string RuleDatabaseVersion { get; init; }
    public required string ScannerBinaryHash { get; init; }
    public required string MachineName { get; init; }
    public required string WindowsUser { get; init; }
    public required bool IsElevated { get; init; }
    public required string PrivacyStatement { get; init; }
    public string? EvidenceJsonHash { get; set; }
    public int CriticalCount => Findings.Count(x => x.Severity == FindingSeverity.Critical);
    public int HighCount => Findings.Count(x => x.Severity == FindingSeverity.High);
    public int WarningCount => Findings.Count(x => x.Severity == FindingSeverity.Warning);
}

public sealed class ScanProgressUpdate
{
    public required int Percent { get; init; }
    public required string Module { get; init; }
    public required string Message { get; init; }
    public int ItemsChecked { get; init; }
    public int Findings { get; init; }
}

public sealed class ScanContext
{
    public required ScanMode Mode { get; init; }
    public required RuleSet Rules { get; init; }
    public required string TempDirectory { get; init; }
    public required DateTimeOffset StartedAt { get; init; }
}

public sealed class CollectorOutput
{
    public required string Module { get; init; }
    public required CoverageStatus Status { get; init; }
    public required string Summary { get; init; }
    public required IReadOnlyList<EvidenceRecord> Evidence { get; init; }
    public required int ItemsChecked { get; init; }
    public required TimeSpan Duration { get; init; }
}

public interface IScanCollector
{
    string Name { get; }
    bool Supports(ScanMode mode);
    Task<CollectorOutput> CollectAsync(ScanContext context, IProgress<ScanProgressUpdate>? progress, CancellationToken token);
}

public sealed class ReportBundle
{
    public required string PdfPath { get; init; }
    public required string JsonPath { get; init; }
    public required string PdfHashPath { get; init; }
}
