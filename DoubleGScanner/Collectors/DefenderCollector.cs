using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using DoubleGScanner.Models;

namespace DoubleGScanner.Collectors;

public sealed class DefenderCollector : IScanCollector
{
    public string Name => "Microsoft Defender no-remediation scan";
    public bool Supports(ScanMode mode) => true;

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

        string user = Environment.GetFolderPath(
            Environment.SpecialFolder.UserProfile);

        var targets = new List<DefenderTarget>
        {
            new(
                Path.Combine(user, "Downloads"),
                "Downloads",
                TimeSpan.FromSeconds(90)),
            new(
                Environment.GetFolderPath(
                    Environment.SpecialFolder.DesktopDirectory),
                "Desktop",
                TimeSpan.FromSeconds(60))
        };

        if (context.Mode != ScanMode.Quick)
        {
            targets.Add(new DefenderTarget(
                Path.GetTempPath(),
                "Temporary files",
                TimeSpan.FromSeconds(60)));
        }

        DefenderTarget[] availableTargets = targets
            .Where(item =>
                !string.IsNullOrWhiteSpace(item.Path) &&
                Directory.Exists(item.Path))
            .DistinctBy(
                item => Path.GetFullPath(item.Path),
                StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (availableTargets.Length == 0)
        {
            return new CollectorOutput
            {
                Module = Name,
                Status = CoverageStatus.Unavailable,
                Summary = "No supported Microsoft Defender scan target was available.",
                Evidence = evidence,
                ItemsChecked = 0,
                Duration = DateTime.UtcNow - started
            };
        }

        int completed = 0;
        int timedOut = 0;
        int failed = 0;

        for (int index = 0; index < availableTargets.Length; index++)
        {
            token.ThrowIfCancellationRequested();
            DefenderTarget target = availableTargets[index];

            DefenderRun run = await RunAsync(
                defender,
                target,
                context.Mode,
                index,
                availableTargets.Length,
                completed,
                progress,
                token);

            completed++;

            if (run.TimedOut)
                timedOut++;

            if (run.ScanError)
                failed++;

            foreach (DefenderDetection detection in run.Detections)
            {
                string artifact = string.IsNullOrWhiteSpace(detection.Path)
                    ? target.Path
                    : detection.Path;

                evidence.Add(new EvidenceRecord
                {
                    Kind = EvidenceKind.Antivirus,
                    Source = Name,
                    Name = detection.ThreatName,
                    Path = artifact,
                    Timestamp = DateTimeOffset.Now,
                    Detail = "Microsoft Defender detected this threat during a custom scan with remediation disabled.",
                    Metadata = new Dictionary<string, string>(
                        StringComparer.OrdinalIgnoreCase)
                    {
                        ["RecordType"] = "DefenderDetection",
                        ["ThreatName"] = detection.ThreatName,
                        ["DetectionEngine"] = "Microsoft Defender Antivirus",
                        ["DetectionMethod"] =
                            "Custom folder scan with -DisableRemediation",
                        ["Target"] = target.Path,
                        ["TargetLabel"] = target.Label,
                        ["ExitCode"] = run.ExitCode.ToString(),
                        ["NoRemediation"] = "True",
                        ["TimedOut"] = run.TimedOut.ToString()
                    }
                });
            }

            int completedPercent = context.Mode != ScanMode.Quick
                ? 88 + (int)Math.Round(
                    completed / (double)availableTargets.Length * 3)
                : 85 + (int)Math.Round(
                    completed / (double)availableTargets.Length * 5);

            progress?.Report(new ScanProgressUpdate
            {
                Percent = Math.Min(92, completedPercent),
                Module = Name,
                Message = run.TimedOut
                    ? $"{target.Label} reached the safety timeout; continuing to the next module."
                    : run.ScanError
                        ? $"{target.Label} scan returned an error; continuing safely."
                        : $"Microsoft Defender completed {target.Label}.",
                ItemsChecked = completed,
                Findings = evidence.Count
            });
        }

        CoverageStatus status =
            timedOut > 0 || failed > 0
                ? CoverageStatus.Partial
                : CoverageStatus.Completed;

        string summary =
            $"Completed {completed}/{availableTargets.Length} Microsoft Defender target attempt(s); " +
            $"{timedOut} timed out, {failed} returned an error, and " +
            $"{evidence.Count} threat record(s) were captured. " +
            "Timed-out targets were stopped and did not block the remaining scan.";

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

    private static async Task<DefenderRun> RunAsync(
        string executable,
        DefenderTarget target,
        ScanMode mode,
        int targetIndex,
        int targetCount,
        int previouslyCompleted,
        IProgress<ScanProgressUpdate>? progress,
        CancellationToken token)
    {
        var start = new ProcessStartInfo
        {
            FileName = executable,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory =
                Path.GetDirectoryName(executable) ??
                Environment.CurrentDirectory
        };

        start.ArgumentList.Add("-Scan");
        start.ArgumentList.Add("-ScanType");
        start.ArgumentList.Add("3");
        start.ArgumentList.Add("-File");
        start.ArgumentList.Add(target.Path);
        start.ArgumentList.Add("-DisableRemediation");
        start.ArgumentList.Add("-CpuThrottling");
        start.ArgumentList.Add(mode == ScanMode.Quick ? "30" : "45");

        using var process = new Process
        {
            StartInfo = start,
            EnableRaisingEvents = true
        };

        var output = new StringBuilder();
        object outputLock = new();

        process.OutputDataReceived += (_, args) =>
        {
            if (args.Data is null)
                return;

            lock (outputLock)
                output.AppendLine(args.Data);
        };

        process.ErrorDataReceived += (_, args) =>
        {
            if (args.Data is null)
                return;

            lock (outputLock)
                output.AppendLine(args.Data);
        };

        DateTimeOffset scanStarted = DateTimeOffset.Now;
        bool timedOut = false;

        try
        {
            if (!process.Start())
            {
                return new DefenderRun(
                    -1,
                    "MpCmdRun.exe did not start.",
                    true,
                    false,
                    Array.Empty<DefenderDetection>());
            }

            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            while (true)
            {
                token.ThrowIfCancellationRequested();

                bool exited;
                try
                {
                    exited = process.HasExited;
                }
                catch
                {
                    exited = true;
                }

                if (exited)
                    break;

                TimeSpan elapsed =
                    DateTimeOffset.Now - scanStarted;

                if (elapsed >= target.Timeout)
                {
                    timedOut = true;
                    StopProcessTree(process);
                    break;
                }

                int percent = CalculateHeartbeatPercent(
                    mode,
                    targetIndex,
                    targetCount,
                    elapsed,
                    target.Timeout);

                progress?.Report(new ScanProgressUpdate
                {
                    Percent = percent,
                    Module = "Microsoft Defender no-remediation scan",
                    Message =
                        $"Scanning {target.Label} • target {targetIndex + 1}/{targetCount} • " +
                        $"{elapsed:mm\\:ss} elapsed • safety limit {target.Timeout:mm\\:ss}",
                    ItemsChecked = previouslyCompleted
                });

                await Task.Delay(
                    TimeSpan.FromSeconds(2),
                    token);
            }

            if (!timedOut)
            {
                try
                {
                    await process.WaitForExitAsync(token);
                }
                catch (InvalidOperationException)
                {
                    // The process had already exited between checks.
                }
            }
            else
            {
                // Bounded wait only. Never wait indefinitely for redirected output.
                try
                {
                    process.WaitForExit(3000);
                }
                catch
                {
                    // A timed-out target is reported as partial and scanning continues.
                }
            }

            string combined;
            lock (outputLock)
                combined = output.ToString();

            IReadOnlyList<DefenderDetection> detections =
                ParseDetections(combined, target.Path);

            int exitCode = -1;
            bool hasExited;
            try
            {
                hasExited = process.HasExited;
                if (hasExited)
                    exitCode = process.ExitCode;
            }
            catch
            {
                hasExited = false;
            }

            bool scanError =
                !timedOut &&
                (!hasExited ||
                 (exitCode != 0 &&
                  exitCode != 1 &&
                  detections.Count == 0));

            return new DefenderRun(
                exitCode,
                combined,
                scanError,
                timedOut,
                detections);
        }
        catch (OperationCanceledException)
        {
            StopProcessTree(process);
            throw;
        }
        catch (Exception ex)
        {
            StopProcessTree(process);

            return new DefenderRun(
                -1,
                ex.GetType().Name + ": " + ex.Message,
                true,
                false,
                Array.Empty<DefenderDetection>());
        }
    }

    private static int CalculateHeartbeatPercent(
        ScanMode mode,
        int targetIndex,
        int targetCount,
        TimeSpan elapsed,
        TimeSpan timeout)
    {
        int startPercent =
            mode != ScanMode.Quick ? 88 : 85;

        int span =
            mode != ScanMode.Quick ? 3 : 6;

        double elapsedFraction = timeout.TotalSeconds <= 0
            ? 0
            : Math.Clamp(
                elapsed.TotalSeconds / timeout.TotalSeconds,
                0,
                0.9);

        double overallFraction =
            (targetIndex + elapsedFraction) /
            Math.Max(1, targetCount);

        return Math.Min(
            92,
            startPercent +
            (int)Math.Floor(overallFraction * span));
    }

    private static void StopProcessTree(Process process)
    {
        try
        {
            if (!process.HasExited)
                process.Kill(entireProcessTree: true);
        }
        catch
        {
            try
            {
                if (process.Id > 0)
                {
                    using Process? taskKill = Process.Start(
                        new ProcessStartInfo
                        {
                            FileName = "taskkill.exe",
                            Arguments =
                                $"/PID {process.Id} /T /F",
                            UseShellExecute = false,
                            CreateNoWindow = true
                        });

                    taskKill?.WaitForExit(2000);
                }
            }
            catch
            {
                // Best effort only. The scanner itself must never hang here.
            }
        }
    }

    private static IReadOnlyList<DefenderDetection> ParseDetections(
        string output,
        string fallbackPath)
    {
        if (string.IsNullOrWhiteSpace(output))
            return Array.Empty<DefenderDetection>();

        var names = new List<string>();

        foreach (Match match in Regex.Matches(
                     output,
                     @"(?im)^\s*(?:Threat(?:\s+Name)?|Detected\s+threat)\s*[:=]\s*(?<name>[^\r\n]+)"))
        {
            string name =
                match.Groups["name"].Value.Trim();

            if (!string.IsNullOrWhiteSpace(name))
                names.Add(name);
        }

        foreach (Match match in Regex.Matches(
                     output,
                     @"(?i)\b(?:HackTool|Trojan|VirTool|PUA|Behavior|Backdoor|Worm|Virus|Ransom|Exploit|Tool):[A-Za-z0-9_./!+\-]+"))
        {
            if (!string.IsNullOrWhiteSpace(match.Value))
                names.Add(match.Value.Trim());
        }

        string[] paths = Regex.Matches(
                output,
                @"(?im)\bfile:(?<path>[^\r\n]+)")
            .Cast<Match>()
            .Select(match =>
                match.Groups["path"]
                    .Value
                    .Trim()
                    .Trim('"'))
            .Where(path =>
                !string.IsNullOrWhiteSpace(path))
            .Distinct(
                StringComparer.OrdinalIgnoreCase)
            .ToArray();

        string[] distinctNames = names
            .Select(CleanThreatName)
            .Where(name =>
                !string.IsNullOrWhiteSpace(name))
            .Distinct(
                StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (distinctNames.Length == 0)
            return Array.Empty<DefenderDetection>();

        var detections =
            new List<DefenderDetection>();

        for (int index = 0;
             index < distinctNames.Length;
             index++)
        {
            string path = paths.Length == 0
                ? fallbackPath
                : paths[Math.Min(
                    index,
                    paths.Length - 1)];

            detections.Add(
                new DefenderDetection(
                    distinctNames[index],
                    path));
        }

        return detections;
    }

    private static string CleanThreatName(string value)
    {
        string result = value.Trim();

        int resourceIndex = result.IndexOf(
            "Resources",
            StringComparison.OrdinalIgnoreCase);

        if (resourceIndex > 0)
            result = result[..resourceIndex].Trim();

        return result.TrimEnd('.', ';', ',');
    }

    private static string? FindMpCmdRun()
    {
        string platform = Path.Combine(
            Environment.GetFolderPath(
                Environment.SpecialFolder.CommonApplicationData),
            "Microsoft",
            "Windows Defender",
            "Platform");

        try
        {
            if (Directory.Exists(platform))
            {
                string? latest =
                    new DirectoryInfo(platform)
                        .EnumerateDirectories()
                        .OrderByDescending(
                            directory => directory.Name,
                            StringComparer.OrdinalIgnoreCase)
                        .Select(directory =>
                            Path.Combine(
                                directory.FullName,
                                "MpCmdRun.exe"))
                        .FirstOrDefault(File.Exists);

                if (latest is not null)
                    return latest;
            }
        }
        catch
        {
            // Fall back to the standard Defender location.
        }

        string fallback = Path.Combine(
            Environment.GetFolderPath(
                Environment.SpecialFolder.ProgramFiles),
            "Windows Defender",
            "MpCmdRun.exe");

        return File.Exists(fallback)
            ? fallback
            : null;
    }

    private sealed record DefenderTarget(
        string Path,
        string Label,
        TimeSpan Timeout);

    private sealed record DefenderDetection(
        string ThreatName,
        string Path);

    private sealed record DefenderRun(
        int ExitCode,
        string Output,
        bool ScanError,
        bool TimedOut,
        IReadOnlyList<DefenderDetection> Detections);
}
