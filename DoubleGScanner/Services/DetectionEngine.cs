using DoubleGScanner.Models;

namespace DoubleGScanner.Services;

public static class DetectionEngine
{
    public static IReadOnlyList<ScanFinding> Analyze(IReadOnlyList<EvidenceRecord> evidence,RuleSet rules)
    {
        var findings=new List<ScanFinding>();
        foreach(EvidenceRecord item in evidence)
        {
            KnownCheatEntry? knownCheat = RuleMatcher.FindKnownCheat(item.HashSha256, rules);
            if(knownCheat is not null)
            {
                string displayName = string.IsNullOrWhiteSpace(knownCheat.Name) ? "Named cheat signature" : knownCheat.Name;
                findings.Add(new ScanFinding
                {
                    RuleId = "DGS-HASH-001",
                    Severity = FindingSeverity.Critical,
                    Score = 100,
                    Title = $"Detected cheat: {displayName}",
                    Summary = "The artifact SHA-256 exactly matched a named entry in the local DoubleG detection database.",
                    EvidenceSource = item.Source,
                    Path = item.Path ?? item.Url,
                    HashSha256 = item.HashSha256,
                    Timestamp = item.Timestamp,
                    DetectedCheatName = displayName,
                    CheatFamily = string.IsNullOrWhiteSpace(knownCheat.Family) ? null : knownCheat.Family,
                    DetectionMethod = "Exact SHA-256 signature",
                    Reasons = new[]
                    {
                        "Exact SHA-256 match",
                        string.IsNullOrWhiteSpace(knownCheat.SourceNote)
                            ? "Matched a locally maintained named detection entry"
                            : knownCheat.SourceNote
                    }
                });
                continue;
            }
            if(RuleMatcher.IsKnownHash(item.HashSha256,rules))
            {
                findings.Add(F("DGS-HASH-001-LEGACY",FindingSeverity.Critical,100,"Known cheat hash matched",
                    "The SHA-256 hash exactly matched a legacy unnamed entry in the local detection-rule dataset.",item,"Exact legacy hash match"));
                continue;
            }
            string combined=string.Join(" ",item.Name,item.Path,item.Url,item.Detail);
            bool high=RuleMatcher.ContainsHigh(combined,rules),medium=RuleMatcher.ContainsMedium(combined,rules);
            bool user=RuleMatcher.IsUserWritable(item.Path),trusted=RuleMatcher.IsTrustedPublisher(item.Publisher,rules);

            if(item.Kind==EvidenceKind.Module&&item.Metadata.TryGetValue("ProcessName",out string? pn)&&pn.Equals("cs2.exe",StringComparison.OrdinalIgnoreCase))
            {
                if(item.IsSignatureValid==false&&user)findings.Add(F("DGS-MODULE-002",FindingSeverity.Critical,85,
                    "Unsigned user-writable module loaded by CS2","A module loaded inside CS2 came from a user-writable location and lacked a valid signature.",
                    item,"Loaded by cs2.exe","User-writable path","Signature invalid or absent"));
                else if(high&&!trusted)findings.Add(F("DGS-MODULE-003",FindingSeverity.High,70,
                    "Potentially suspicious CS2 module","A CS2 module matched high-risk naming rules and was not associated with a trusted publisher.",
                    item,"Loaded by cs2.exe","High-risk keyword"));
            }
            if(item.Kind==EvidenceKind.Process&&high&&user&&item.IsSignatureValid!=true)
                findings.Add(F("DGS-PROC-004",FindingSeverity.High,58,"Suspicious unsigned process",
                    "A running executable matched high-risk terms, ran from a user-writable location, and lacked a valid signature.",
                    item,"Running process","High-risk term","Unsigned user-writable executable"));

            if(item.Kind==EvidenceKind.Browser)
            {
                if(RuleMatcher.IsKnownDomain(item.Url,rules))findings.Add(F("DGS-WEB-005",FindingSeverity.Critical,90,
                    "Known cheat distribution domain","A local browser record matched a domain in the detection-rule dataset.",item,"Known-domain match"));
                else if(high&&(RuleMatcher.IsExecutableOrArchive(item.Path)||item.Metadata.GetValueOrDefault("RecordType")=="Download"))
                    findings.Add(F("DGS-WEB-006",FindingSeverity.Warning,35,"Potential cheat-related download record",
                        "A browser download matched high-risk terms. Browser history alone is supporting evidence, not proof.",item,"High-risk term in download metadata"));
            }
            if(item.Kind==EvidenceKind.Execution&&high)
            {
                bool missing=!string.IsNullOrWhiteSpace(item.Path)&&!File.Exists(item.Path);
                findings.Add(F("DGS-EXEC-007",FindingSeverity.Warning,missing?38:28,"Potentially relevant execution trace",
                    "Windows retained an execution-related artifact matching a high-risk rule.",item,$"Artifact source: {item.Source}",missing?"Referenced file is missing":"Artifact remains"));
            }
            if(item.Kind==EvidenceKind.DeletedFile&&high&&RuleMatcher.IsExecutableOrArchive(item.Path))
                findings.Add(F("DGS-DEL-008",FindingSeverity.High,55,"Deleted executable/archive trace",
                    "Recycle Bin metadata referenced a deleted executable or archive matching high-risk rules.",item,"Deleted-file metadata","Executable/archive extension"));
            bool isDriver=item.Kind==EvidenceKind.FileArtifact&&item.Metadata.GetValueOrDefault("RecordType")=="Driver";
            if(isDriver&&item.IsSignatureValid==false&&user)
                findings.Add(F("DGS-DRV-009",FindingSeverity.Critical,80,"Unsigned driver from a user-writable location",
                    "A registered kernel/file-system driver resolved to a user-writable path and lacked a valid signature.",item,"Registered driver","User-writable path","Invalid or absent signature"));
            else if(item.Kind==EvidenceKind.FileArtifact&&high&&user&&item.IsSignatureValid!=true)
                findings.Add(F("DGS-FILE-010",FindingSeverity.Warning,32,"Potentially suspicious local file",
                    "A recent file in a user-writable high-risk location matched metadata rules and lacked a valid trusted signature.",item,"Recent file artifact"));
            if(item.Kind==EvidenceKind.Network&&high)
                findings.Add(F("DGS-NET-011",FindingSeverity.Warning,25,"Suspiciously named process has a live connection",
                    "A process matching a high-risk naming rule had an active TCP connection during the scan.",item,"Live network connection"));
            if(medium&&(item.Kind==EvidenceKind.Process||item.Kind==EvidenceKind.FileArtifact)&&user&&item.IsSignatureValid==false)
                findings.Add(F("DGS-HEUR-012",FindingSeverity.Warning,18,"Low-confidence unsigned tool indicator",
                    "A user-writable unsigned executable matched a medium-risk term. Manual review is required.",item,"Medium-risk term"));
        }
        AddCorrelation(evidence,findings,rules);
        return findings.GroupBy(x=>$"{x.RuleId}|{x.Path}|{x.Timestamp:O}",StringComparer.OrdinalIgnoreCase)
            .Select(g=>g.OrderByDescending(x=>x.Score).First()).OrderByDescending(x=>x.Score).ThenByDescending(x=>x.Timestamp).ToArray();
    }

    public static (ScanVerdict Verdict,int Risk) Verdict(IReadOnlyList<ScanFinding> f,IReadOnlyList<ScanCoverage> c,ScanMode mode)
    {
        int failed=c.Count(x=>x.Status is CoverageStatus.Failed or CoverageStatus.Unavailable);
        int partial=c.Count(x=>x.Status==CoverageStatus.Partial);
        if(failed>=(mode==ScanMode.Quick?2:3)||failed+partial>=5)return(ScanVerdict.Incomplete,Math.Min(200,f.Sum(x=>x.Score)));
        int risk=Math.Min(200,f.Sum(x=>x.Score));
        if(f.Any(x=>x.Severity==FindingSeverity.Critical&&x.Score>=80))return(ScanVerdict.Detected,risk);
        if(f.Any(x=>(int)x.Severity>=(int)FindingSeverity.High)||risk>=55)return(ScanVerdict.Review,risk);
        return(ScanVerdict.NotDetected,risk);
    }

    private static void AddCorrelation(IReadOnlyList<EvidenceRecord> evidence,List<ScanFinding> findings,RuleSet rules)
    {
        var relevant=evidence.Where(x=>RuleMatcher.ContainsHigh(string.Join(" ",x.Name,x.Path,x.Url,x.Detail),rules))
            .Where(x=>!string.IsNullOrWhiteSpace(x.Name)).GroupBy(x=>Normalize(x.Name),StringComparer.OrdinalIgnoreCase);
        foreach(var g in relevant)
        {
            EvidenceKind[] kinds=g.Select(x=>x.Kind).Distinct().ToArray();
            if(kinds.Contains(EvidenceKind.Browser)&&kinds.Contains(EvidenceKind.Execution)&&
               (kinds.Contains(EvidenceKind.DeletedFile)||kinds.Contains(EvidenceKind.FileArtifact)))
            {
                EvidenceRecord primary=g.OrderByDescending(x=>x.Timestamp).First();
                findings.Add(F("DGS-CORR-013",FindingSeverity.Critical,82,"Correlated download, execution, and file trace",
                    "The same high-risk name appeared in independent browser, execution, and file/deletion sources.",
                    primary,"Independent evidence correlation",string.Join(", ",kinds)));
            }
        }
    }
    private static string Normalize(string name)=>new string(Path.GetFileNameWithoutExtension(name).ToLowerInvariant().Where(char.IsLetterOrDigit).ToArray());
    private static ScanFinding F(string id,FindingSeverity s,int score,string title,string summary,EvidenceRecord e,params string[] reasons)=>new()
    {RuleId=id,Severity=s,Score=score,Title=title,Summary=summary,EvidenceSource=e.Source,Path=e.Path??e.Url,HashSha256=e.HashSha256,Timestamp=e.Timestamp,Reasons=reasons};
}
