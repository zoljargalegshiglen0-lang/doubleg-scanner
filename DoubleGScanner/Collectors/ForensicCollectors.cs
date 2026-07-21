using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Text;
using DoubleGScanner.Models;
using DoubleGScanner.Services;
using Microsoft.Win32;

namespace DoubleGScanner.Collectors;

public sealed class ExecutionHistoryCollector : IScanCollector
{
    public string Name=>"Execution history";
    public bool Supports(ScanMode mode)=>true;
    public Task<CollectorOutput> CollectAsync(ScanContext c,IProgress<ScanProgressUpdate>? p,CancellationToken t)
    {
        DateTime start=DateTime.UtcNow;var list=new List<EvidenceRecord>();int checkedCount=0;bool partial=false;
        p?.Report(new(){Percent=49,Module=Name,Message="Reading Prefetch, UserAssist, BAM, and Recent Items..."});
        try{checkedCount+=Prefetch(list,c.Mode);}catch{partial=true;}
        try{checkedCount+=UserAssist(list);}catch{partial=true;}
        try{checkedCount+=Bam(list);}catch{partial=true;}
        try{checkedCount+=Recent(list);}catch{partial=true;}
        return Task.FromResult(new CollectorOutput{Module=Name,Status=partial?CoverageStatus.Partial:CoverageStatus.Completed,
            Summary=$"Collected {list.Count:N0} execution traces from {checkedCount:N0} records. A trace alone is not proof.",
            Evidence=list,ItemsChecked=checkedCount,Duration=DateTime.UtcNow-start});
    }
    private static int Prefetch(List<EvidenceRecord> list,ScanMode mode)
    {
        string folder=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),"Prefetch");
        if(!Directory.Exists(folder))return 0;int limit=mode==ScanMode.Quick?700:2000;
        FileInfo[] files=new DirectoryInfo(folder).EnumerateFiles("*.pf").OrderByDescending(x=>x.LastWriteTimeUtc).Take(limit).ToArray();
        foreach(FileInfo f in files)
        {
            string stem=f.Name;int dash=stem.LastIndexOf('-');if(dash>0)stem=stem[..dash];
            list.Add(new(){Kind=EvidenceKind.Execution,Source="Windows Prefetch",Name=stem,Path=f.FullName,Timestamp=f.LastWriteTime,
                Detail="Prefetch artifact timestamp; referenced executable may no longer exist.",
                Metadata=new(StringComparer.OrdinalIgnoreCase){["Artifact"]=f.Name,["FileSize"]=f.Length.ToString()}});
        }
        return files.Length;
    }
    private static int UserAssist(List<EvidenceRecord> list)
    {
        using RegistryKey? root=Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist");
        if(root is null)return 0;int count=0;
        foreach(string guid in root.GetSubKeyNames())
        {
            using RegistryKey? key=root.OpenSubKey(guid+@"\Count");if(key is null)continue;
            foreach(string encoded in key.GetValueNames())
            {
                if(key.GetValue(encoded)is not byte[] data)continue;count++;string decoded=Rot13(encoded);
                int runs=data.Length>=8?Math.Max(0,BitConverter.ToInt32(data,4)):0;DateTimeOffset? time=null;
                if(data.Length>=68){long ft=BitConverter.ToInt64(data,60);try{if(ft>0)time=DateTimeOffset.FromFileTime(ft);}catch{}}
                list.Add(new(){Kind=EvidenceKind.Execution,Source="UserAssist",
                    Name=Path.GetFileName(decoded)is{Length:>0}n?n:decoded,Path=decoded,Timestamp=time,
                    Detail="Explorer UserAssist execution trace.",Metadata=new(StringComparer.OrdinalIgnoreCase){["RunCount"]=runs.ToString(),["RegistryGroup"]=guid}});
            }
        }
        return count;
    }
    private static int Bam(List<EvidenceRecord> list)
    {
        int count=0;foreach(string path in new[]{@"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",@"SYSTEM\CurrentControlSet\Services\bam\UserSettings"})
        {
            using RegistryKey? root=Registry.LocalMachine.OpenSubKey(path);if(root is null)continue;
            foreach(string sid in root.GetSubKeyNames())
            {
                using RegistryKey? key=root.OpenSubKey(sid);if(key is null)continue;
                foreach(string name in key.GetValueNames())
                {
                    if(string.IsNullOrWhiteSpace(name)||name.StartsWith("Version",StringComparison.OrdinalIgnoreCase)||name.StartsWith("Sequence",StringComparison.OrdinalIgnoreCase))continue;
                    count++;DateTimeOffset? time=null;if(key.GetValue(name)is byte[] data&&data.Length>=8)
                    {long ft=BitConverter.ToInt64(data,0);try{if(ft>0)time=DateTimeOffset.FromFileTime(ft);}catch{}}
                    list.Add(new(){Kind=EvidenceKind.Execution,Source="BAM",Name=Path.GetFileName(name)is{Length:>0}n?n:name,
                        Path=name,Timestamp=time,Detail="Background Activity Moderator execution trace.",
                        Metadata=new(StringComparer.OrdinalIgnoreCase){["UserSid"]=sid}});
                }
            }
        }
        return count;
    }
    private static int Recent(List<EvidenceRecord> list)
    {
        string folder =
            Environment.GetFolderPath(
                Environment.SpecialFolder.Recent);

        if (!Directory.Exists(folder))
            return 0;

        FileInfo[] files =
            new DirectoryInfo(folder)
                .EnumerateFiles("*")
                .OrderByDescending(item =>
                    item.LastWriteTimeUtc)
                .Take(1_500)
                .ToArray();

        foreach (FileInfo file in files)
        {
            string extension =
                file.Extension.ToLowerInvariant();

            string displayName =
                Path.GetFileNameWithoutExtension(
                    file.Name);

            string? targetPath = null;
            string? arguments = null;
            string? workingDirectory = null;
            string? internetUrl = null;

            if (extension == ".lnk")
            {
                TryReadShellShortcut(
                    file.FullName,
                    out targetPath,
                    out arguments,
                    out workingDirectory);
            }
            else if (extension == ".url")
            {
                internetUrl =
                    TryReadInternetShortcut(
                        file.FullName);
            }

            string detail = extension switch
            {
                ".lnk" when
                    !string.IsNullOrWhiteSpace(targetPath) =>
                    "Recent Items shortcut metadata was read without opening the target.",
                ".url" when
                    !string.IsNullOrWhiteSpace(internetUrl) =>
                    "Recent Internet Shortcut URL was read without opening it.",
                _ =>
                    "Recent Items shell artifact; the referenced item was not opened."
            };

            list.Add(new EvidenceRecord
            {
                Kind = EvidenceKind.Execution,
                Source = "Recent Items",
                Name = string.IsNullOrWhiteSpace(displayName)
                    ? file.Name
                    : displayName,
                Path = !string.IsNullOrWhiteSpace(targetPath)
                    ? targetPath
                    : file.FullName,
                Url = internetUrl,
                Timestamp = file.LastWriteTime,
                Detail = detail,
                Metadata =
                    new Dictionary<string, string>(
                        StringComparer.OrdinalIgnoreCase)
                    {
                        ["RecordType"] =
                            extension == ".lnk"
                                ? "ShellShortcut"
                                : extension == ".url"
                                    ? "InternetShortcut"
                                    : "RecentItem",
                        ["ShortcutPath"] =
                            file.FullName,
                        ["ShortcutFileName"] =
                            file.Name,
                        ["TargetPath"] =
                            targetPath ?? "",
                        ["Arguments"] =
                            arguments ?? "",
                        ["WorkingDirectory"] =
                            workingDirectory ?? "",
                        ["InternetUrl"] =
                            internetUrl ?? "",
                        ["TargetExists"] =
                            (!string.IsNullOrWhiteSpace(targetPath) &&
                             File.Exists(targetPath))
                                .ToString()
                    }
            });
        }

        return files.Length;
    }

    private static void TryReadShellShortcut(
        string shortcutPath,
        out string? targetPath,
        out string? arguments,
        out string? workingDirectory)
    {
        targetPath = null;
        arguments = null;
        workingDirectory = null;

        object? shell = null;
        object? shortcut = null;

        try
        {
            Type? shellType =
                Type.GetTypeFromProgID(
                    "WScript.Shell");

            if (shellType is null)
                return;

            shell =
                Activator.CreateInstance(
                    shellType);

            if (shell is null)
                return;

            dynamic dynamicShell = shell;
            shortcut =
                dynamicShell.CreateShortcut(
                    shortcutPath);

            dynamic dynamicShortcut =
                shortcut;

            targetPath =
                Convert.ToString(
                    dynamicShortcut.TargetPath);

            arguments =
                Convert.ToString(
                    dynamicShortcut.Arguments);

            workingDirectory =
                Convert.ToString(
                    dynamicShortcut.WorkingDirectory);
        }
        catch
        {
            // The shortcut filename remains useful even when COM metadata
            // cannot be resolved.
        }
        finally
        {
            if (shortcut is not null &&
                Marshal.IsComObject(shortcut))
            {
                try
                {
                    Marshal.FinalReleaseComObject(
                        shortcut);
                }
                catch
                {
                }
            }

            if (shell is not null &&
                Marshal.IsComObject(shell))
            {
                try
                {
                    Marshal.FinalReleaseComObject(
                        shell);
                }
                catch
                {
                }
            }
        }
    }

    private static string? TryReadInternetShortcut(
        string shortcutPath)
    {
        try
        {
            foreach (string line in
                     File.ReadLines(shortcutPath)
                         .Take(80))
            {
                if (!line.StartsWith(
                        "URL=",
                        StringComparison.OrdinalIgnoreCase))
                    continue;

                string value =
                    line[4..].Trim();

                return string.IsNullOrWhiteSpace(value)
                    ? null
                    : value;
            }
        }
        catch
        {
        }

        return null;
    }
    private static string Rot13(string s)
    {
        var b=new StringBuilder(s.Length);foreach(char ch in s)
        {if(ch is>='a'and<='z')b.Append((char)('a'+(ch-'a'+13)%26));else if(ch is>='A'and<='Z')b.Append((char)('A'+(ch-'A'+13)%26));else b.Append(ch);}return b.ToString();
    }
}

public sealed class RecycleBinCollector : IScanCollector
{
    public string Name => "Deleted-file traces";
    public bool Supports(ScanMode mode) => true;

    public Task<CollectorOutput> CollectAsync(
        ScanContext context,
        IProgress<ScanProgressUpdate>? progress,
        CancellationToken token)
    {
        DateTime started = DateTime.UtcNow;
        var evidence = new List<EvidenceRecord>();
        int checkedCount = 0;
        bool partial = false;

        int maxRecords = context.Mode == ScanMode.Quick
            ? 10_000
            : 30_000;

        int recentDays = context.Mode == ScanMode.Quick
            ? 120
            : 365;

        DateTimeOffset cutoff =
            DateTimeOffset.Now.AddDays(-recentDays);

        progress?.Report(new ScanProgressUpdate
        {
            Percent = context.Mode == ScanMode.Quick ? 53 : 61,
            Module = Name,
            Message = context.Mode == ScanMode.Quick
                ? "Checking recent Recycle Bin executable/archive metadata..."
                : "Reading Recycle Bin metadata without restoring files..."
        });

        foreach (DriveInfo drive in DriveInfo
                     .GetDrives()
                     .Where(item =>
                         item.IsReady &&
                         item.DriveType == DriveType.Fixed))
        {
            string recycleBin =
                Path.Combine(
                    drive.RootDirectory.FullName,
                    "$Recycle.Bin");

            if (!Directory.Exists(recycleBin))
                continue;

            try
            {
                foreach (string metadataFile in
                         Files(recycleBin, "$I*"))
                {
                    token.ThrowIfCancellationRequested();

                    if (checkedCount >= maxRecords)
                    {
                        partial = true;
                        break;
                    }

                    checkedCount++;

                    if (!Parse(
                            metadataFile,
                            out Deleted? deleted) ||
                        deleted is null)
                        continue;

                    bool executableOrArchive =
                        RuleMatcher.IsExecutableOrArchive(
                            deleted.Path);

                    bool named =
                        RuleMatcher.FindKnownCheatName(
                            deleted.Path,
                            context.Rules) is not null;

                    bool high =
                        RuleMatcher.ContainsHigh(
                            deleted.Path,
                            context.Rules);

                    bool recent =
                        deleted.Time is not null &&
                        deleted.Time.Value >= cutoff;

                    // Quick Scan now has the previous Full Scan scope.
                    // Retain all available Recycle Bin metadata within its 120-day / 10k cap.
                    bool relevant = true;

                    if (!relevant)
                        continue;

                    evidence.Add(new EvidenceRecord
                    {
                        Kind = EvidenceKind.DeletedFile,
                        Source = Name,
                        Name =
                            Path.GetFileName(deleted.Path),
                        Path = deleted.Path,
                        Timestamp = deleted.Time,
                        Detail =
                            "Recycle Bin metadata; content was not restored or opened.",
                        Metadata =
                            new Dictionary<string, string>(
                                StringComparer.OrdinalIgnoreCase)
                            {
                                ["OriginalSize"] =
                                    deleted.Size.ToString(),
                                ["MetadataFile"] =
                                    metadataFile,
                                ["CurrentStatus"] =
                                    "Deleted trace",
                                ["RecordType"] =
                                    "RecycleBinDeletedTrace",
                                ["RecentTrace"] =
                                    recent.ToString(),
                                ["ExecutableOrArchive"] =
                                    executableOrArchive.ToString()
                            }
                    });
                }
            }
            catch
            {
                partial = true;
            }

            if (checkedCount >= maxRecords)
                break;
        }

        return Task.FromResult(
            new CollectorOutput
            {
                Module = Name,
                Status = partial
                    ? CoverageStatus.Partial
                    : CoverageStatus.Completed,
                Summary =
                    $"Checked {checkedCount:N0} Recycle Bin metadata records and retained {evidence.Count:N0} relevant deleted-file traces.",
                Evidence = evidence,
                ItemsChecked = checkedCount,
                Duration = DateTime.UtcNow - started
            });
    }

    private static bool Parse(
        string path,
        out Deleted? deleted)
    {
        deleted = null;

        try
        {
            byte[] data = File.ReadAllBytes(path);
            if (data.Length < 24)
                return false;

            long version = BitConverter.ToInt64(
                data,
                0);
            long size = BitConverter.ToInt64(
                data,
                8);
            long fileTime = BitConverter.ToInt64(
                data,
                16);

            DateTimeOffset? deletedTime = null;
            try
            {
                if (fileTime > 0)
                    deletedTime =
                        DateTimeOffset.FromFileTime(
                            fileTime);
            }
            catch
            {
            }

            string originalPath;
            if (version == 2 &&
                data.Length >= 28)
            {
                int characters =
                    BitConverter.ToInt32(
                        data,
                        24);

                int bytes = Math.Min(
                    Math.Max(
                        characters * 2,
                        0),
                    data.Length - 28);

                originalPath =
                    Encoding.Unicode
                        .GetString(
                            data,
                            28,
                            bytes)
                        .TrimEnd('\0');
            }
            else
            {
                originalPath =
                    Encoding.Unicode
                        .GetString(
                            data,
                            24,
                            data.Length - 24)
                        .TrimEnd('\0');
            }

            if (string.IsNullOrWhiteSpace(
                    originalPath))
                return false;

            deleted = new Deleted(
                originalPath,
                size,
                deletedTime);

            return true;
        }
        catch
        {
            return false;
        }
    }

    private static IEnumerable<string> Files(
        string root,
        string pattern)
    {
        var directories =
            new Stack<string>();

        directories.Push(root);

        while (directories.Count > 0)
        {
            string current =
                directories.Pop();

            string[] files;
            try
            {
                files =
                    Directory.GetFiles(
                        current,
                        pattern);
            }
            catch
            {
                files =
                    Array.Empty<string>();
            }

            foreach (string file in files)
                yield return file;

            string[] childDirectories;
            try
            {
                childDirectories =
                    Directory.GetDirectories(
                        current);
            }
            catch
            {
                childDirectories =
                    Array.Empty<string>();
            }

            foreach (string directory in
                     childDirectories)
                directories.Push(directory);
        }
    }

    private sealed record Deleted(
        string Path,
        long Size,
        DateTimeOffset? Time);
}

public sealed class FileArtifactCollector : IScanCollector
{
    public string Name => "Downloaded and local file scan";
    public bool Supports(ScanMode mode) => true;

    private static readonly HashSet<string> Extensions =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".sys", ".com", ".scr", ".msi",
            ".bat", ".cmd", ".ps1", ".vbs", ".js",
            ".zip", ".rar", ".7z", ".jar", ".iso", ".img",
            ".lnk", ".url"
        };

    private static readonly HashSet<string> BinaryExtensions =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".sys", ".com", ".scr", ".msi"
        };

    private static readonly HashSet<string> ArchiveExtensions =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ".zip", ".rar", ".7z", ".jar", ".iso", ".img"
        };

    private static readonly HashSet<string> ArchivePayloadExtensions =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".sys", ".com", ".scr", ".msi",
            ".bat", ".cmd", ".ps1", ".vbs", ".js",
            ".zip", ".rar", ".7z", ".jar", ".iso", ".img"
        };

    private static readonly EnumerationOptions EnumerationSettings =
        new()
        {
            IgnoreInaccessible = true,
            RecurseSubdirectories = false,
            ReturnSpecialDirectories = false,
            AttributesToSkip =
                FileAttributes.ReparsePoint |
                FileAttributes.Offline
        };

    public async Task<CollectorOutput> CollectAsync(
        ScanContext context,
        IProgress<ScanProgressUpdate>? progress,
        CancellationToken token)
    {
        DateTime started = DateTime.UtcNow;
        DateTime lastProgress = DateTime.MinValue;

        var evidence = new List<EvidenceRecord>();
        var seenFiles =
            new HashSet<string>(
                StringComparer.OrdinalIgnoreCase);

        int metadataCandidates = 0;
        int deepInspected = 0;
        int volumeRootsVisited = 0;
        int timedOutFiles = 0;
        bool partial = false;
        bool stoppedByGlobalLimit = false;

        int metadataLimit = context.Mode switch
        {
            ScanMode.Quick => 120_000,
            ScanMode.Full => 400_000,
            _ => 900_000
        };

        int deepInspectionLimit = context.Mode switch
        {
            ScanMode.Quick => 2_500,
            ScanMode.Full => 10_000,
            _ => 25_000
        };

        TimeSpan totalTimeLimit = context.Mode switch
        {
            ScanMode.Quick => TimeSpan.FromSeconds(75),
            ScanMode.Full => TimeSpan.FromMinutes(3),
            _ => TimeSpan.FromMinutes(5)
        };

        TimeSpan priorityRootLimit = context.Mode switch
        {
            ScanMode.Quick => TimeSpan.FromSeconds(20),
            ScanMode.Full => TimeSpan.FromSeconds(40),
            _ => TimeSpan.FromSeconds(60)
        };

        TimeSpan perFileTimeout = context.Mode switch
        {
            ScanMode.Quick => TimeSpan.FromSeconds(4),
            ScanMode.Full => TimeSpan.FromSeconds(8),
            _ => TimeSpan.FromSeconds(12)
        };

        long maximumDeepFileSize = context.Mode switch
        {
            ScanMode.Quick => 128L * 1024 * 1024,
            ScanMode.Full => 384L * 1024 * 1024,
            _ => 512L * 1024 * 1024
        };

        long maximumArchiveInspectionSize = context.Mode switch
        {
            ScanMode.Quick => 256L * 1024 * 1024,
            ScanMode.Full => 768L * 1024 * 1024,
            _ => 1536L * 1024 * 1024
        };

        int recentDays = context.Mode switch
        {
            ScanMode.Quick => 180,
            ScanMode.Full => 1_095,
            _ => int.MaxValue
        };

        DateTime cutoff = context.Mode == ScanMode.Forensic
            ? DateTime.MinValue
            : DateTime.UtcNow.AddDays(-recentDays);

        string user =
            Environment.GetFolderPath(
                Environment.SpecialFolder.UserProfile);

        string downloads =
            Path.Combine(
                user,
                "Downloads");

        string desktop =
            Environment.GetFolderPath(
                Environment.SpecialFolder.DesktopDirectory);

        string temp =
            Path.GetTempPath();

        string localTemp =
            Path.Combine(
                Environment.GetFolderPath(
                    Environment.SpecialFolder.LocalApplicationData),
                "Temp");

        string windows =
            Environment.GetFolderPath(
                Environment.SpecialFolder.Windows);

        string programFiles =
            Environment.GetFolderPath(
                Environment.SpecialFolder.ProgramFiles);

        string programFilesX86 =
            Environment.GetFolderPath(
                Environment.SpecialFolder.ProgramFilesX86);

        DriveInfo[] drives =
            DriveInfo.GetDrives()
                .Where(item =>
                    item.IsReady &&
                    item.DriveType is
                        DriveType.Fixed or
                        DriveType.Removable)
                .ToArray();

        var roots =
            new List<ScanRoot>
            {
                new(downloads, "Downloads", false),
                new(desktop, "Desktop", false),
                new(temp, "Temporary files", false),
                new(localTemp, "Local temporary files", false)
            };

        roots.AddRange(
            drives.Select(drive =>
                new ScanRoot(
                    drive.RootDirectory.FullName,
                    $"{drive.DriveType} disk {drive.Name}",
                    true)));

        TimeSpan perVolumeRootLimit =
            drives.Length == 0
                ? totalTimeLimit
                : TimeSpan.FromTicks(
                    Math.Max(
                        TimeSpan.FromSeconds(25).Ticks,
                        (long)(
                            totalTimeLimit.Ticks *
                            0.72 /
                            drives.Length)));

        foreach (ScanRoot scanRoot in roots
                     .Where(item =>
                         !string.IsNullOrWhiteSpace(
                             item.Path))
                     .DistinctBy(
                         item =>
                             Path.GetFullPath(item.Path),
                         StringComparer.OrdinalIgnoreCase))
        {
            token.ThrowIfCancellationRequested();

            if (!Directory.Exists(scanRoot.Path))
                continue;

            if (DateTime.UtcNow - started >= totalTimeLimit ||
                metadataCandidates >= metadataLimit)
            {
                partial = true;
                stoppedByGlobalLimit = true;
                break;
            }

            if (scanRoot.IsVolumeRoot)
                volumeRootsVisited++;

            DateTime rootStarted = DateTime.UtcNow;

            TimeSpan rootTimeLimit =
                scanRoot.IsVolumeRoot
                    ? perVolumeRootLimit
                    : priorityRootLimit;

            progress?.Report(
                new ScanProgressUpdate
                {
                    Percent =
                        ComputeProgressPercent(
                            context.Mode,
                            DateTime.UtcNow - started,
                            totalTimeLimit,
                            metadataCandidates,
                            metadataLimit),
                    Module = Name,
                    Message =
                        $"Fast metadata sweep in {scanRoot.Location}",
                    ItemsChecked = metadataCandidates
                });

            try
            {
                foreach (string file in
                         EnumerateFiles(
                             scanRoot.Path,
                             context.Mode))
                {
                    token.ThrowIfCancellationRequested();

                    TimeSpan totalElapsed =
                        DateTime.UtcNow - started;

                    TimeSpan rootElapsed =
                        DateTime.UtcNow - rootStarted;

                    if (totalElapsed >= totalTimeLimit ||
                        metadataCandidates >= metadataLimit)
                    {
                        partial = true;
                        stoppedByGlobalLimit = true;
                        break;
                    }

                    if (rootElapsed >= rootTimeLimit)
                    {
                        partial = true;
                        break;
                    }

                    string extension =
                        Path.GetExtension(file);

                    if (!Extensions.Contains(extension))
                        continue;

                    string fullPath;

                    try
                    {
                        fullPath =
                            Path.GetFullPath(file);
                    }
                    catch
                    {
                        fullPath = file;
                    }

                    if (!seenFiles.Add(fullPath))
                        continue;

                    metadataCandidates++;

                    FileInfo info;

                    try
                    {
                        info =
                            new FileInfo(fullPath);
                    }
                    catch
                    {
                        continue;
                    }

                    if (!info.Exists)
                        continue;

                    KnownCheatNameEntry? namedPath =
                        RuleMatcher.FindKnownCheatName(
                            fullPath,
                            context.Rules);

                    bool highPath =
                        RuleMatcher.ContainsHigh(
                            fullPath,
                            context.Rules);

                    bool mediumPath =
                        RuleMatcher.ContainsMedium(
                            fullPath,
                            context.Rules);

                    bool isBinary =
                        BinaryExtensions.Contains(extension);

                    bool isArchive =
                        ArchiveExtensions.Contains(extension);

                    bool isDownload =
                        IsUnderPath(
                            fullPath,
                            downloads);

                    bool isUserWritable =
                        RuleMatcher.IsUserWritable(
                            fullPath);

                    bool isSystemLocation =
                        IsUnderPath(
                            fullPath,
                            windows) ||
                        IsUnderPath(
                            fullPath,
                            programFiles) ||
                        IsUnderPath(
                            fullPath,
                            programFilesX86);

                    bool recentForMode =
                        info.LastWriteTimeUtc >= cutoff;

                    bool recent30Days =
                        info.LastWriteTimeUtc >=
                        DateTime.UtcNow.AddDays(-30);

                    bool namedOrKeyword =
                        namedPath is not null ||
                        highPath ||
                        mediumPath;

                    bool shouldDeepInspect =
                        namedOrKeyword ||
                        isDownload ||
                        (
                            isUserWritable &&
                            (
                                recentForMode ||
                                context.Mode != ScanMode.Quick
                            )
                        ) ||
                        (
                            isArchive &&
                            isUserWritable
                        ) ||
                        (
                            context.Mode == ScanMode.Forensic &&
                            recent30Days &&
                            !isSystemLocation
                        );

                    // All disks are still searched by path/filename. Expensive
                    // file content analysis is reserved for candidates that can
                    // reasonably affect a verdict.
                    if (!shouldDeepInspect)
                    {
                        ReportProgressIfNeeded(
                            progress,
                            context.Mode,
                            started,
                            totalTimeLimit,
                            metadataCandidates,
                            metadataLimit,
                            deepInspected,
                            scanRoot.Location,
                            ref lastProgress);

                        continue;
                    }

                    bool deepBudgetAvailable =
                        deepInspected <
                        deepInspectionLimit;

                    InspectionResult inspection;

                    if (deepBudgetAvailable)
                    {
                        deepInspected++;

                        inspection =
                            await InspectCandidateAsync(
                                info,
                                extension,
                                isBinary,
                                isArchive,
                                namedOrKeyword,
                                context,
                                maximumDeepFileSize,
                                maximumArchiveInspectionSize,
                                perFileTimeout,
                                token);

                        if (inspection.TimedOut)
                            timedOutFiles++;
                    }
                    else
                    {
                        partial = true;

                        inspection =
                            InspectionResult.Skipped(
                                "Deep inspection limit reached; filename/path evidence was retained.");
                    }

                    string combined =
                        string.Join(
                            " ",
                            new[] { fullPath }
                                .Concat(
                                    inspection.Archive.Indicators)
                                .Concat(
                                    inspection.StaticResult.Indicators));

                    bool knownHash =
                        RuleMatcher.IsKnownHash(
                            inspection.Hash,
                            context.Rules);

                    bool namedCheat =
                        namedPath is not null ||
                        RuleMatcher.FindKnownCheatName(
                            combined,
                            context.Rules) is not null;

                    bool highKeyword =
                        RuleMatcher.ContainsHigh(
                            combined,
                            context.Rules);

                    bool mediumKeyword =
                        RuleMatcher.ContainsMedium(
                            combined,
                            context.Rules);

                    bool unsignedUserBinary =
                        isBinary &&
                        inspection.Signature?.IsValid != true &&
                        isUserWritable;

                    bool strongStatic =
                        inspection.StaticResult.Score >= 45;

                    bool archiveWithPayload =
                        inspection.Archive.ExecutableEntries > 0;

                    bool strongArchive =
                        inspection.Archive.StaticScore >= 40 ||
                        inspection.Archive.Indicators.Count > 0;

                    bool recentOpaqueArchive =
                        isArchive &&
                        inspection.Archive.Unreadable &&
                        isDownload &&
                        recent30Days;

                    bool recentDownloadedBinary =
                        isDownload &&
                        recent30Days &&
                        unsignedUserBinary;

                    bool recentDownloadedPayloadArchive =
                        isDownload &&
                        recent30Days &&
                        archiveWithPayload;

                    bool recentDownloadedCandidate =
                        isDownload &&
                        recent30Days &&
                        (isBinary || isArchive);

                    bool relevant =
                        knownHash ||
                        namedCheat ||
                        highKeyword ||
                        strongStatic ||
                        strongArchive ||
                        recentDownloadedCandidate ||
                        recentDownloadedBinary ||
                        recentDownloadedPayloadArchive ||
                        recentOpaqueArchive ||
                        (
                            mediumKeyword &&
                            (
                                unsignedUserBinary ||
                                archiveWithPayload
                            )
                        );

                    if (!relevant)
                    {
                        ReportProgressIfNeeded(
                            progress,
                            context.Mode,
                            started,
                            totalTimeLimit,
                            metadataCandidates,
                            metadataLimit,
                            deepInspected,
                            scanRoot.Location,
                            ref lastProgress);

                        continue;
                    }

                    string effectiveLocation =
                        isDownload
                            ? "Downloads"
                            : scanRoot.Location;

                    string detail =
                        BuildDetail(
                            inspection.Signature,
                            inspection.StaticResult,
                            inspection.Archive,
                            isArchive,
                            inspection.Note);

                    var metadata =
                        new Dictionary<string, string>(
                            StringComparer.OrdinalIgnoreCase)
                        {
                            ["RecordType"] =
                                isDownload
                                    ? "RecentDownloadArtifact"
                                    : "LocalFileArtifact",
                            ["Location"] =
                                effectiveLocation,
                            ["VolumeRoot"] =
                                Path.GetPathRoot(fullPath) ?? "",
                            ["AllDiskSweep"] =
                                "True",
                            ["MetadataSweep"] =
                                "True",
                            ["DeepInspected"] =
                                deepBudgetAvailable.ToString(),
                            ["InspectionTimedOut"] =
                                inspection.TimedOut.ToString(),
                            ["InspectionNote"] =
                                inspection.Note,
                            ["FileSize"] =
                                info.Length.ToString(),
                            ["Extension"] =
                                extension,
                            ["Created"] =
                                info.CreationTime.ToString("O"),
                            ["LastWrite"] =
                                info.LastWriteTime.ToString("O"),
                            ["Recent30Days"] =
                                recent30Days.ToString(),
                            ["IsSystemLocation"] =
                                isSystemLocation.ToString(),
                            ["IsUserWritable"] =
                                isUserWritable.ToString(),
                            ["StaticRiskScore"] =
                                inspection.StaticResult.Score.ToString(),
                            ["StaticIndicators"] =
                                string.Join(
                                    "; ",
                                    inspection.StaticResult.Indicators),
                            ["ArchiveEntryCount"] =
                                inspection.Archive.EntryCount.ToString(),
                            ["ArchiveExecutableCount"] =
                                inspection.Archive.ExecutableEntries.ToString(),
                            ["ArchiveStaticScore"] =
                                inspection.Archive.StaticScore.ToString(),
                            ["ArchiveUnreadable"] =
                                inspection.Archive.Unreadable.ToString(),
                            ["ArchiveCapped"] =
                                inspection.Archive.Capped.ToString(),
                            ["ArchiveIndicators"] =
                                string.Join(
                                    "; ",
                                    inspection.Archive.Indicators)
                        };

                    evidence.Add(
                        new EvidenceRecord
                        {
                            Kind =
                                EvidenceKind.FileArtifact,
                            Source =
                                Name,
                            Name =
                                info.Name,
                            Path =
                                info.FullName,
                            HashSha256 =
                                inspection.Hash,
                            Publisher =
                                inspection.Signature?.Publisher,
                            IsSignatureValid =
                                inspection.Signature?.IsValid,
                            Timestamp =
                                info.LastWriteTime,
                            Detail =
                                detail,
                            Metadata =
                                metadata
                        });

                    ReportProgressIfNeeded(
                        progress,
                        context.Mode,
                        started,
                        totalTimeLimit,
                        metadataCandidates,
                        metadataLimit,
                        deepInspected,
                        scanRoot.Location,
                        ref lastProgress);
                }
            }
            catch
            {
                partial = true;
            }

            if (stoppedByGlobalLimit)
                break;
        }

        string completionReason =
            stoppedByGlobalLimit
                ? "The mode time/item limit was reached."
                : timedOutFiles > 0
                    ? $"{timedOutFiles:N0} slow file(s) reached the per-file timeout."
                    : "The bounded sweep completed.";

        return new CollectorOutput
        {
            Module = Name,
            Status =
                partial
                    ? CoverageStatus.Partial
                    : CoverageStatus.Completed,
            Summary =
                $"Fast-scanned {metadataCandidates:N0} executable/archive/shortcut candidates across {volumeRootsVisited:N0} ready fixed or removable volume root(s); deep-inspected {deepInspected:N0} relevant candidates and retained {evidence.Count:N0} evidence item(s). {completionReason}",
            Evidence =
                evidence,
            ItemsChecked =
                metadataCandidates,
            Duration =
                DateTime.UtcNow - started
        };
    }

    private static async Task<InspectionResult>
        InspectCandidateAsync(
            FileInfo info,
            string extension,
            bool isBinary,
            bool isArchive,
            bool namedOrKeyword,
            ScanContext context,
            long maximumDeepFileSize,
            long maximumArchiveInspectionSize,
            TimeSpan timeout,
            CancellationToken outerToken)
    {
        SignatureResult? signature = null;
        string? hash = null;
        StaticAnalysisResult staticResult =
            StaticAnalysisResult.Empty;
        ArchiveInspection archive =
            ArchiveInspection.Empty;
        bool timedOut = false;
        string note = "";

        using var timeoutSource =
            CancellationTokenSource.CreateLinkedTokenSource(
                outerToken);

        timeoutSource.CancelAfter(timeout);

        try
        {
            CancellationToken token =
                timeoutSource.Token;

            if (isBinary)
            {
                signature =
                    SignatureVerifier.Verify(
                        info.FullName);

                if (
                    info.Length <=
                    maximumDeepFileSize)
                {
                    hash =
                        await HashService.TrySha256Async(
                            info.FullName,
                            token);

                    staticResult =
                        await StaticFileAnalyzer.AnalyzeFileAsync(
                            info.FullName,
                            token);
                }
                else
                {
                    note =
                        $"Deep content analysis skipped because the binary is larger than {maximumDeepFileSize / (1024 * 1024):N0} MB.";
                }
            }
            else if (
                extension.Equals(
                    ".zip",
                    StringComparison.OrdinalIgnoreCase) ||
                extension.Equals(
                    ".jar",
                    StringComparison.OrdinalIgnoreCase))
            {
                if (
                    info.Length <=
                    maximumArchiveInspectionSize)
                {
                    hash =
                        info.Length <=
                        maximumDeepFileSize
                            ? await HashService.TrySha256Async(
                                info.FullName,
                                token)
                            : null;

                    archive =
                        await InspectZipAsync(
                            info.FullName,
                            context.Rules,
                            context.Mode,
                            token);
                }
                else
                {
                    archive =
                        new ArchiveInspection(
                            0,
                            0,
                            0,
                            Array.Empty<string>(),
                            true,
                            true,
                            $"Archive content inspection skipped because the file is larger than {maximumArchiveInspectionSize / (1024 * 1024):N0} MB.");
                }
            }
            else if (isArchive)
            {
                if (
                    info.Length <=
                    maximumDeepFileSize &&
                    namedOrKeyword)
                {
                    hash =
                        await HashService.TrySha256Async(
                            info.FullName,
                            token);
                }

                archive =
                    new ArchiveInspection(
                        0,
                        0,
                        0,
                        Array.Empty<string>(),
                        true,
                        false,
                        "Archive contents require Microsoft Defender or a supported archive parser.");
            }
        }
        catch (OperationCanceledException)
            when (!outerToken.IsCancellationRequested)
        {
            timedOut = true;
            note =
                $"Deep inspection exceeded the {timeout.TotalSeconds:N0}-second per-file limit.";
        }
        catch
        {
            note =
                "Deep inspection failed safely; filename and metadata evidence remain available.";
        }

        return new InspectionResult(
            signature,
            hash,
            staticResult,
            archive,
            timedOut,
            note);
    }

    private static void ReportProgressIfNeeded(
        IProgress<ScanProgressUpdate>? progress,
        ScanMode mode,
        DateTime started,
        TimeSpan totalTimeLimit,
        int metadataCandidates,
        int metadataLimit,
        int deepInspected,
        string location,
        ref DateTime lastProgress)
    {
        DateTime now =
            DateTime.UtcNow;

        if (
            now - lastProgress <
            TimeSpan.FromSeconds(1))
            return;

        lastProgress = now;

        progress?.Report(
            new ScanProgressUpdate
            {
                Percent =
                    ComputeProgressPercent(
                        mode,
                        now - started,
                        totalTimeLimit,
                        metadataCandidates,
                        metadataLimit),
                Module =
                    "Downloaded and local file scan",
                Message =
                    $"Fast disk sweep: {metadataCandidates:N0} candidates, {deepInspected:N0} deep checks — {location}",
                ItemsChecked =
                    metadataCandidates
            });
    }

    private static int ComputeProgressPercent(
        ScanMode mode,
        TimeSpan elapsed,
        TimeSpan timeLimit,
        int metadataCandidates,
        int metadataLimit)
    {
        int start = mode == ScanMode.Quick
            ? 72
            : 81;

        int end = 89;

        double timeRatio =
            Math.Clamp(
                elapsed.TotalMilliseconds /
                Math.Max(
                    1,
                    timeLimit.TotalMilliseconds),
                0,
                1);

        double itemRatio =
            Math.Clamp(
                metadataCandidates /
                (double)Math.Max(
                    1,
                    metadataLimit),
                0,
                1);

        double ratio =
            Math.Max(
                timeRatio,
                itemRatio);

        return start +
               (int)Math.Round(
                   (end - start) *
                   ratio);
    }

    private static bool IsUnderPath(
        string candidate,
        string root)
    {
        if (
            string.IsNullOrWhiteSpace(candidate) ||
            string.IsNullOrWhiteSpace(root))
            return false;

        try
        {
            string fullCandidate =
                Path.GetFullPath(candidate);

            string fullRoot =
                Path.GetFullPath(root)
                    .TrimEnd(
                        Path.DirectorySeparatorChar,
                        Path.AltDirectorySeparatorChar) +
                Path.DirectorySeparatorChar;

            return fullCandidate.StartsWith(
                fullRoot,
                StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static string BuildDetail(
        SignatureResult? signature,
        StaticAnalysisResult staticResult,
        ArchiveInspection archive,
        bool isArchive,
        string inspectionNote)
    {
        var parts =
            new List<string>();

        if (signature is not null)
            parts.Add(signature.Status);

        if (staticResult.Score > 0)
        {
            parts.Add(
                $"Static score {staticResult.Score}/100: " +
                string.Join(
                    ", ",
                    staticResult.Indicators.Take(6)));
        }

        if (isArchive)
        {
            parts.Add(
                $"Archive entries: {archive.EntryCount}; executable/script payloads: {archive.ExecutableEntries}");

            if (archive.StaticScore > 0)
            {
                parts.Add(
                    $"Embedded static score: {archive.StaticScore}/100");
            }

            if (archive.Indicators.Count > 0)
            {
                parts.Add(
                    string.Join(
                        ", ",
                        archive.Indicators.Take(8)));
            }

            if (
                archive.Unreadable ||
                archive.Capped)
            {
                parts.Add(archive.Note);
            }
        }

        if (!string.IsNullOrWhiteSpace(
                inspectionNote))
        {
            parts.Add(inspectionNote);
        }

        return parts.Count == 0
            ? "Filename/path and recent file metadata"
            : string.Join(
                " | ",
                parts);
    }

    private static IEnumerable<string> EnumerateFiles(
        string root,
        ScanMode mode)
    {
        var stack =
            new Stack<string>();

        stack.Push(root);

        while (stack.Count > 0)
        {
            string current =
                stack.Pop();

            IEnumerable<string> files;

            try
            {
                files =
                    Directory.EnumerateFiles(
                        current,
                        "*",
                        EnumerationSettings);
            }
            catch
            {
                files =
                    Array.Empty<string>();
            }

            using (
                IEnumerator<string> enumerator =
                    files.GetEnumerator())
            {
                while (true)
                {
                    string file;

                    try
                    {
                        if (!enumerator.MoveNext())
                            break;

                        file =
                            enumerator.Current;
                    }
                    catch
                    {
                        break;
                    }

                    yield return file;
                }
            }

            IEnumerable<string> directories;

            try
            {
                directories =
                    Directory.EnumerateDirectories(
                        current,
                        "*",
                        EnumerationSettings);
            }
            catch
            {
                directories =
                    Array.Empty<string>();
            }

            using (
                IEnumerator<string> enumerator =
                    directories.GetEnumerator())
            {
                while (true)
                {
                    string directory;

                    try
                    {
                        if (!enumerator.MoveNext())
                            break;

                        directory =
                            enumerator.Current;
                    }
                    catch
                    {
                        break;
                    }

                    if (ShouldSkipDirectory(
                            directory,
                            mode))
                        continue;

                    stack.Push(directory);
                }
            }
        }
    }

    private static bool ShouldSkipDirectory(
        string path,
        ScanMode mode)
    {
        string name =
            Path.GetFileName(
                path.TrimEnd(
                    Path.DirectorySeparatorChar,
                    Path.AltDirectorySeparatorChar));

        if (
            name.Equals(
                "System Volume Information",
                StringComparison.OrdinalIgnoreCase) ||
            name.Equals(
                "$Recycle.Bin",
                StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (mode == ScanMode.Forensic)
            return false;

        string normalized =
            path.Replace(
                Path.AltDirectorySeparatorChar,
                Path.DirectorySeparatorChar);

        string[] componentCaches =
        {
            $"{Path.DirectorySeparatorChar}Windows{Path.DirectorySeparatorChar}WinSxS",
            $"{Path.DirectorySeparatorChar}Windows{Path.DirectorySeparatorChar}SoftwareDistribution",
            $"{Path.DirectorySeparatorChar}Windows{Path.DirectorySeparatorChar}Installer",
            $"{Path.DirectorySeparatorChar}Program Files{Path.DirectorySeparatorChar}WindowsApps",
            $"{Path.DirectorySeparatorChar}ProgramData{Path.DirectorySeparatorChar}Package Cache"
        };

        return componentCaches.Any(cache =>
            normalized.Contains(
                cache,
                StringComparison.OrdinalIgnoreCase));
    }

    private static async Task<ArchiveInspection> InspectZipAsync(
        string path,
        RuleSet rules,
        ScanMode mode,
        CancellationToken token)
    {
        int maximumEntries = mode switch
        {
            ScanMode.Quick => 300,
            ScanMode.Full => 1_000,
            _ => 2_500
        };

        long maximumEmbeddedBytes = mode switch
        {
            ScanMode.Quick => 16L * 1024 * 1024,
            ScanMode.Full => 64L * 1024 * 1024,
            _ => 128L * 1024 * 1024
        };

        int maximumEntryBytes = mode switch
        {
            ScanMode.Quick => 1 * 1024 * 1024,
            ScanMode.Full => 4 * 1024 * 1024,
            _ => 8 * 1024 * 1024
        };

        TimeSpan archiveTimeLimit = mode switch
        {
            ScanMode.Quick => TimeSpan.FromSeconds(4),
            ScanMode.Full => TimeSpan.FromSeconds(8),
            _ => TimeSpan.FromSeconds(12)
        };

        DateTime started =
            DateTime.UtcNow;

        int entries = 0;
        int executableEntries = 0;
        int staticScore = 0;
        long embeddedBytesRead = 0;
        bool unreadable = false;
        bool capped = false;

        var indicators =
            new List<string>();

        try
        {
            using ZipArchive archive =
                ZipFile.OpenRead(path);

            foreach (ZipArchiveEntry entry in
                     archive.Entries)
            {
                token.ThrowIfCancellationRequested();

                if (
                    entries >= maximumEntries ||
                    embeddedBytesRead >=
                    maximumEmbeddedBytes ||
                    DateTime.UtcNow - started >=
                    archiveTimeLimit)
                {
                    capped = true;
                    break;
                }

                entries++;

                string extension =
                    Path.GetExtension(
                        entry.FullName);

                string name =
                    entry.FullName;

                bool executablePayload =
                    ArchivePayloadExtensions.Contains(
                        extension);

                if (executablePayload)
                    executableEntries++;

                KnownCheatNameEntry? named =
                    RuleMatcher.FindKnownCheatName(
                        name,
                        rules);

                if (
                    named is not null ||
                    RuleMatcher.ContainsHigh(
                        name,
                        rules) ||
                    RuleMatcher.ContainsMedium(
                        name,
                        rules))
                {
                    indicators.Add(
                        named is not null
                            ? $"Named archive entry: {named.Name} — {name}"
                            : "Suspicious archive entry name: " + name);
                }

                if (
                    !executablePayload ||
                    entry.Length <= 0 ||
                    entry.Length >
                    maximumEntryBytes ||
                    staticScore >= 90 ||
                    embeddedBytesRead >=
                    maximumEmbeddedBytes)
                {
                    continue;
                }

                try
                {
                    await using Stream input =
                        entry.Open();

                    int remainingBudget =
                        (int)Math.Min(
                            maximumEntryBytes,
                            maximumEmbeddedBytes -
                            embeddedBytesRead);

                    int limit =
                        (int)Math.Min(
                            entry.Length,
                            remainingBudget);

                    byte[] bytes =
                        new byte[limit];

                    int offset = 0;

                    while (offset < bytes.Length)
                    {
                        int read =
                            await input.ReadAsync(
                                bytes.AsMemory(
                                    offset,
                                    bytes.Length -
                                    offset),
                                token);

                        if (read == 0)
                            break;

                        offset += read;
                    }

                    embeddedBytesRead += offset;

                    if (offset != bytes.Length)
                        Array.Resize(
                            ref bytes,
                            offset);

                    StaticAnalysisResult result =
                        StaticFileAnalyzer.AnalyzeBytes(
                            bytes);

                    staticScore =
                        Math.Max(
                            staticScore,
                            result.Score);

                    foreach (string indicator in
                             result.Indicators.Take(8))
                    {
                        indicators.Add(
                            $"{entry.FullName}: {indicator}");
                    }
                }
                catch
                {
                    unreadable = true;
                }
            }
        }
        catch
        {
            unreadable = true;
        }

        string note = capped
            ? "Archive inspection stopped at the per-file entry, byte, or time limit."
            : unreadable
                ? "Some archive content was encrypted, damaged, unsupported, or unavailable for read-only inspection."
                : "ZIP/JAR archive inspected without extracting files.";

        return new ArchiveInspection(
            entries,
            executableEntries,
            staticScore,
            indicators
                .Distinct(
                    StringComparer.OrdinalIgnoreCase)
                .Take(24)
                .ToArray(),
            unreadable,
            capped,
            note);
    }

    private sealed record ScanRoot(
        string Path,
        string Location,
        bool IsVolumeRoot);

    private sealed record InspectionResult(
        SignatureResult? Signature,
        string? Hash,
        StaticAnalysisResult StaticResult,
        ArchiveInspection Archive,
        bool TimedOut,
        string Note)
    {
        public static InspectionResult Skipped(
            string note) =>
            new(
                null,
                null,
                StaticAnalysisResult.Empty,
                ArchiveInspection.Empty,
                false,
                note);
    }

    private sealed record ArchiveInspection(
        int EntryCount,
        int ExecutableEntries,
        int StaticScore,
        IReadOnlyList<string> Indicators,
        bool Unreadable,
        bool Capped,
        string Note)
    {
        public static ArchiveInspection Empty { get; } =
            new(
                0,
                0,
                0,
                Array.Empty<string>(),
                false,
                false,
                "");
    }
}
