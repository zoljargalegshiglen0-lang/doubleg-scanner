using System.Reflection;
using DoubleGScanner.Collectors;
using DoubleGScanner.Models;

namespace DoubleGScanner.Services;

public sealed class ScanCoordinator
{
    private readonly IReadOnlyList<IScanCollector> collectors=new IScanCollector[]
    {
        new SystemProfileCollector(),new ProcessCollector(),new ModuleCollector(),new BrowserCollector(),
        new ExecutionHistoryCollector(),new RecycleBinCollector(),new NtfsMftCollector(),new UsnJournalCollector(),new UnallocatedSpaceCollector(),new DriverPersistenceCollector(),new NetworkCollector(),new FileArtifactCollector(),new DefenderCollector()
    };

    public async Task<ScanResult> RunAsync(ScanMode mode,IProgress<ScanProgressUpdate>? progress,CancellationToken token)
    {
        DateTimeOffset started=DateTimeOffset.Now;string temp=Path.Combine(Path.GetTempPath(),"DoubleGScanner",Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        try
        {
            RuleSet rules=await RuleLoader.LoadAsync(token);var ctx=new ScanContext{Mode=mode,Rules=rules,TempDirectory=temp,StartedAt=started};
            var evidence=new List<EvidenceRecord>();var coverage=new List<ScanCoverage>();int index=0,supported=collectors.Count(x=>x.Supports(mode));
            foreach(IScanCollector collector in collectors)
            {
                if(!collector.Supports(mode)){coverage.Add(new(){Module=collector.Name,Status=CoverageStatus.Skipped,Summary=$"Skipped in {mode} mode.",ItemsChecked=0,Duration=TimeSpan.Zero});continue;}
                token.ThrowIfCancellationRequested();index++;
                progress?.Report(new(){Percent=Math.Min(92,2+(int)((index-1)/(double)Math.Max(1,supported)*88)),Module=collector.Name,Message=$"Starting {collector.Name}...",ItemsChecked=evidence.Count});
                try
                {
                    CollectorOutput output=await collector.CollectAsync(ctx,progress,token);evidence.AddRange(output.Evidence);
                    coverage.Add(new(){Module=output.Module,Status=output.Status,Summary=output.Summary,ItemsChecked=output.ItemsChecked,Duration=output.Duration});
                }
                catch(OperationCanceledException){throw;}
                catch(Exception ex){coverage.Add(new(){Module=collector.Name,Status=CoverageStatus.Failed,Summary="Module failed safely: "+ex.GetType().Name,ItemsChecked=0,Duration=TimeSpan.Zero});}
            }
            progress?.Report(new(){Percent=94,Module="Detection engine",Message="Correlating independent evidence sources...",ItemsChecked=evidence.Count});
            IReadOnlyList<ScanFinding> findings=DetectionEngine.Analyze(evidence,rules);(ScanVerdict verdict,int risk)=DetectionEngine.Verdict(findings,coverage,mode);
            string? exe=Environment.ProcessPath;string hash=exe is null?"Unavailable":HashService.TrySha256(exe)??"Unavailable";
            progress?.Report(new(){Percent=98,Module="Report",Message="Generating local PDF and JSON evidence package...",ItemsChecked=evidence.Count,Findings=findings.Count});
            return new(){ScanId=$"DGS-{started:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}"[..31].ToUpperInvariant(),
                ScannerVersion=Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "unknown",Mode=mode,StartedAt=started,CompletedAt=DateTimeOffset.Now,
                Verdict=verdict,RiskScore=risk,Evidence=evidence,Findings=findings,Coverage=coverage,RuleDatabaseVersion=rules.Version,
                ScannerBinaryHash=hash,MachineName=Environment.MachineName,WindowsUser=Environment.UserName,IsElevated=SystemProfileCollector.IsAdministrator(),
                PrivacyStatement="Local-only, read-only scan. No passwords, cookies, session tokens, private messages, photos, or document contents are collected. No files are uploaded, deleted, quarantined, or modified."};
        }
        finally{try{if(Directory.Exists(temp))Directory.Delete(temp,true);}catch{}}
    }
}
