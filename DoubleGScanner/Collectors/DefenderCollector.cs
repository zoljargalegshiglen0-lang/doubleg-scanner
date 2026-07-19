using System.Diagnostics;
using System.Text.RegularExpressions;
using DoubleGScanner.Models;

namespace DoubleGScanner.Collectors;

public sealed class DefenderCollector : IScanCollector
{
    public string Name => "Microsoft Defender no-remediation scan";
    public bool Supports(ScanMode mode) => mode != ScanMode.Quick;

    public async Task<CollectorOutput> CollectAsync(
        ScanContext context,
        IProgress<ScanProgressUpdate>? progress,
        CancellationToken token)
    {
        DateTime started = DateTime.UtcNow;
        var evidence = new List<EvidenceRecord>();

        if (!SystemProfileCollector.IsAdministrator())
        {
            return new CollectorOutput
            {
                Module = Name,
                Status = CoverageStatus.Unavailable,
                Summary = "Microsoft Defender custom scanning requires an elevated scanner session. Run DoubleG Scanner as administrator.",
                Evidence = evidence,
                ItemsChecked = 0,
                Duration = DateTime.UtcNow - started
            };
        }

        string? defender = FindMpCmdRun();
        if (defender is null)
        {
            return new CollectorOutput
            {
                Module = Name,
                Status = CoverageStatus.Unavailable,
                Summary = "Microsoft Defender MpCmdRun.exe was not found or Defender is unavailable.",
                Evidence = evidence,
                ItemsChecked = 0,
                Duration = DateTime.UtcNow - started
            };
        }

        string user = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var targets = new List<(string Path, string Label)>
        {
            (Path.Combine(user, "Downloads"), "Downloads"),
            (Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "Desktop")
        };
        if (context.Mode == ScanMode.Forensic)
            targets.Add((Path.GetTempPath(), "Temporary files"));

        int completed = 0;
        bool partial = false;
        foreach ((string path, string label) in targets
                     .Where(x => !string.IsNullOrWhiteSpace(x.Path) && Directory.Exists(x.Path))
                     .DistinctBy(x => Path.GetFullPath(x.Path), StringComparer.OrdinalIgnoreCase))
        {
            token.ThrowIfCancellationRequested();
            progress?.Report(new ScanProgressUpdate
            {
                Percent = context.Mode == ScanMode.Full ? 85 : 88,
                Module = Name,
                Message = $"Microsoft Defender is scanning {label} without remediation...",
                ItemsChecked = completed
            });

            DefenderRun run = await RunAsync(defender, path, context.Mode, token);
            completed++;
            if (run.TimedOut || run.ScanError) partial = true;

            foreach (DefenderDetection detection in run.Detections)
            {
                string artifact = string.IsNullOrWhiteSpace(detection.Path) ? path : detection.Path;
                evidence.Add(new EvidenceRecord
                {
                    Kind = EvidenceKind.Antivirus,
                    Source = Name,
                    Name = detection.ThreatName,
                    Path = artifact,
                    Timestamp = DateTimeOffset.Now,
                    Detail = "Microsoft Defender detected this threat during a custom scan with remediation disabled.",
                    Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["RecordType"] = "DefenderDetection",
                        ["ThreatName"] = detection.ThreatName,
                        ["DetectionEngine"] = "Microsoft Defender Antivirus",
                        ["DetectionMethod"] = "Custom folder scan with -DisableRemediation",
                        ["Target"] = path,
                        ["ExitCode"] = run.ExitCode.ToString(),
                        ["NoRemediation"] = "True"
                    }
                });
            }
        }

        CoverageStatus status = completed == 0
            ? CoverageStatus.Unavailable
            : partial ? CoverageStatus.Partial : CoverageStatus.Completed;
        string summary = completed == 0
            ? "No supported scan target was available."
            : $"Completed {completed} Microsoft Defender no-remediation target scan(s); detected {evidence.Count} threat record(s).";

        return new CollectorOutput
        {
            Module = Name,
            Status = status,
            Summary = summary,
            Evidence = evidence,
            ItemsChecked = completed,
            Duration = DateTime.UtcNow - started
        };
    }

    private static async Task<DefenderRun> RunAsync(string executable, string target, ScanMode mode, CancellationToken token)
    {
        var start = new ProcessStartInfo
        {
            FileName = executable,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = Path.GetDirectoryName(executable) ?? Environment.CurrentDirectory
        };
        start.ArgumentList.Add("-Scan");
        start.ArgumentList.Add("-ScanType");
        start.ArgumentList.Add("3");
        start.ArgumentList.Add("-File");
        start.ArgumentList.Add(target);
        start.ArgumentList.Add("-DisableRemediation");
        start.ArgumentList.Add("-CpuThrottling");
        start.ArgumentList.Add(mode == ScanMode.Forensic ? "45" : "30");

        using var process = new Process { StartInfo = start };
        try
        {
            if (!process.Start())
                return new DefenderRun(-1, "", true, false, Array.Empty<DefenderDetection>());

            Task<string> stdoutTask = process.StandardOutput.ReadToEndAsync();
            Task<string> stderrTask = process.StandardError.ReadToEndAsync();
            TimeSpan timeout = mode == ScanMode.Forensic ? TimeSpan.FromMinutes(10) : TimeSpan.FromMinutes(6);
            using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeoutSource.CancelAfter(timeout);

            try
            {
                await process.WaitForExitAsync(timeoutSource.Token);
            }
            catch (OperationCanceledException) when (!token.IsCancellationRequested)
            {
                try { process.Kill(true); } catch { }
                string partialOutput = await stdoutTask;
                return new DefenderRun(-1, partialOutput, false, true, ParseDetections(partialOutput, target));
            }

            string stdout = await stdoutTask;
            string stderr = await stderrTask;
            string combined = string.Join(Environment.NewLine, stdout, stderr);
            IReadOnlyList<DefenderDetection> detections = ParseDetections(combined, target);
            bool scanError = process.ExitCode == 2 && detections.Count == 0;
            return new DefenderRun(process.ExitCode, combined, scanError, false, detections);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            return new DefenderRun(-1, ex.GetType().Name, true, false, Array.Empty<DefenderDetection>());
        }
    }

    private static IReadOnlyList<DefenderDetection> ParseDetections(string output, string fallbackPath)
    {
        if (string.IsNullOrWhiteSpace(output)) return Array.Empty<DefenderDetection>();

        var names = new List<string>();
        foreach (Match match in Regex.Matches(output,
                     @"(?im)^\s*(?:Threat(?:\s+Name)?|Detected\s+threat)\s*[:=]\s*(?<name>[^\r\n]+)"))
        {
            string name = match.Groups["name"].Value.Trim();
            if (!string.IsNullOrWhiteSpace(name)) names.Add(name);
        }

        foreach (Match match in Regex.Matches(output,
                     @"(?i)\b(?:HackTool|Trojan|VirTool|PUA|Behavior|Backdoor|Worm|Virus|Ransom|Exploit|Tool):[A-Za-z0-9_./!+\-]+"))
        {
            if (!string.IsNullOrWhiteSpace(match.Value)) names.Add(match.Value.Trim());
        }

        string[] paths = Regex.Matches(output, @"(?im)\bfile:(?<path>[^\r\n]+)")
            .Cast<Match>()
            .Select(x => x.Groups["path"].Value.Trim().Trim('"'))
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        string[] distinctNames = names
            .Select(CleanThreatName)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (distinctNames.Length == 0) return Array.Empty<DefenderDetection>();

        var detections = new List<DefenderDetection>();
        for (int index = 0; index < distinctNames.Length; index++)
        {
            string path = paths.Length == 0 ? fallbackPath : paths[Math.Min(index, paths.Length - 1)];
            detections.Add(new DefenderDetection(distinctNames[index], path));
        }
        return detections;
    }

    private static string CleanThreatName(string value)
    {
        string result = value.Trim();
        int resourceIndex = result.IndexOf("Resources", StringComparison.OrdinalIgnoreCase);
        if (resourceIndex > 0) result = result[..resourceIndex].Trim();
        return result.TrimEnd('.', ';', ',');
    }

    private static string? FindMpCmdRun()
    {
        string platform = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Microsoft", "Windows Defender", "Platform");
        try
        {
            if (Directory.Exists(platform))
            {
                string? latest = new DirectoryInfo(platform).EnumerateDirectories()
                    .OrderByDescending(x => x.Name, StringComparer.OrdinalIgnoreCase)
                    .Select(x => Path.Combine(x.FullName, "MpCmdRun.exe"))
                    .FirstOrDefault(File.Exists);
                if (latest is not null) return latest;
            }
        }
        catch { }

        string fallback = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "Windows Defender", "MpCmdRun.exe");
        return File.Exists(fallback) ? fallback : null;
    }

    private sealed record DefenderDetection(string ThreatName, string Path);
    private sealed record DefenderRun(
        int ExitCode,
        string Output,
        bool ScanError,
        bool TimedOut,
        IReadOnlyList<DefenderDetection> Detections);
}
