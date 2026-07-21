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

    private static readonly HashSet<string> Extensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".com", ".scr", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js",
        ".zip", ".rar", ".7z", ".jar", ".iso", ".img", ".lnk", ".url"
    };

    private static readonly HashSet<string> BinaryExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".com", ".scr", ".msi"
    };

    private static readonly HashSet<string> ArchiveExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".zip", ".rar", ".7z", ".jar", ".iso", ".img"
    };

    private static readonly HashSet<string> ArchivePayloadExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".com", ".scr", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js",
        ".zip", ".rar", ".7z", ".jar", ".iso", ".img"
    };

    public async Task<CollectorOutput> CollectAsync(ScanContext context, IProgress<ScanProgressUpdate>? progress, CancellationToken token)
    {
        DateTime started = DateTime.UtcNow;
        var evidence = new List<EvidenceRecord>();
        int checkedCount = 0;
        bool partial = false;

        int max = context.Mode switch
        {
            ScanMode.Quick => 40_000,
            ScanMode.Full => 150_000,
            _ => 300_000
        };

        int days = context.Mode switch
        {
            ScanMode.Quick => 180,
            ScanMode.Full => 1_095,
            _ => int.MaxValue
        };

        TimeSpan totalTimeLimit = context.Mode switch
        {
            ScanMode.Quick => TimeSpan.FromMinutes(3),
            ScanMode.Full => TimeSpan.FromMinutes(12),
            _ => TimeSpan.FromMinutes(25)
        };

        int perRootCandidateLimit = context.Mode switch
        {
            ScanMode.Quick => 30_000,
            ScanMode.Full => 120_000,
            _ => 250_000
        };

        bool recursive = true;
        DateTime cutoff = context.Mode == ScanMode.Forensic
            ? DateTime.MinValue
            : DateTime.UtcNow.AddDays(-days);

        string user = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string downloads = Path.Combine(user, "Downloads");
        string desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        string temp = Path.GetTempPath();
        string localTemp = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp");

        var roots = new List<(string Path, string Location)>
        {
            (downloads, "Downloads"),
            (desktop, "Desktop"),
            (temp, "Temporary files"),
            (localTemp, "Local temporary files")
        };

        foreach (DriveInfo drive in
                 DriveInfo.GetDrives()
                     .Where(item =>
                         item.IsReady &&
                         item.DriveType is
                             DriveType.Fixed or
                             DriveType.Removable))
        {
            roots.Add((
                drive.RootDirectory.FullName,
                $"{drive.DriveType} disk {drive.Name}"));
        }

        var seenFiles =
            new HashSet<string>(
                StringComparer.OrdinalIgnoreCase);

        bool stopAll = false;
        int volumeRootsVisited = 0;

        foreach ((string root, string location) in roots
                     .Where(item =>
                         !string.IsNullOrWhiteSpace(
                             item.Path))
                     .DistinctBy(
                         item =>
                             Path.GetFullPath(
                                 item.Path),
                         StringComparer.OrdinalIgnoreCase))
        {
            if (!Directory.Exists(root))
                continue;

            bool volumeRoot =
                Path.GetPathRoot(root)
                    ?.TrimEnd('\\')
                    .Equals(
                        root.TrimEnd('\\'),
                        StringComparison.OrdinalIgnoreCase) ==
                true;

            if (volumeRoot)
                volumeRootsVisited++;

            int rootCandidates = 0;

            progress?.Report(new ScanProgressUpdate
            {
                Percent =
                    context.Mode == ScanMode.Quick
                        ? 72
                        : 81,
                Module = Name,
                Message =
                    $"Searching executable, archive, shortcut, and named-family artifacts in {location}",
                ItemsChecked =
                    checkedCount
            });

            try
            {
                foreach (string file in
                         EnumerateFiles(
                             root,
                             recursive))
                {
                    token.ThrowIfCancellationRequested();

                    if (
                        checkedCount >= max ||
                        rootCandidates >=
                        perRootCandidateLimit ||
                        DateTime.UtcNow - started >=
                        totalTimeLimit)
                    {
                        partial = true;
                        stopAll =
                            checkedCount >= max ||
                            DateTime.UtcNow - started >=
                            totalTimeLimit;
                        break;
                    }

                    string extension =
                        Path.GetExtension(file);

                    if (!Extensions.Contains(
                            extension))
                        continue;

                    rootCandidates++;

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

                    FileInfo info;

                    try
                    {
                        info =
                            new FileInfo(file);
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

                    if (
                        namedPath is null &&
                        info.LastWriteTimeUtc <
                        cutoff)
                        continue;

                    checkedCount++;

                    bool isBinary =
                        BinaryExtensions.Contains(
                            extension);

                    bool isArchive =
                        ArchiveExtensions.Contains(
                            extension);

                    bool isRecent =
                        info.LastWriteTimeUtc >=
                        DateTime.UtcNow.AddDays(-30);

                    bool isDownload =
                        IsUnderPath(
                            fullPath,
                            downloads);

                    string effectiveLocation =
                        isDownload
                            ? "Downloads"
                            : location;

                    string? hash = null;
                    SignatureResult? signature = null;
                    StaticAnalysisResult staticResult = StaticAnalysisResult.Empty;
                    ArchiveInspection archive = ArchiveInspection.Empty;

                    if (isBinary)
                    {
                        signature = SignatureVerifier.Verify(file);
                        hash = await HashService.TrySha256Async(file, token);
                        staticResult = await StaticFileAnalyzer.AnalyzeFileAsync(file, token);
                    }
                    else if (extension.Equals(".zip", StringComparison.OrdinalIgnoreCase) ||
                             extension.Equals(".jar", StringComparison.OrdinalIgnoreCase))
                    {
                        hash = await HashService.TrySha256Async(file, token);
                        archive = await InspectZipAsync(file, context.Rules, token);
                    }
                    else if (isArchive)
                    {
                        hash = await HashService.TrySha256Async(file, token);
                        archive = new ArchiveInspection(0, 0, 0, Array.Empty<string>(), true,
                            "Archive contents require Microsoft Defender or an external archive parser.");
                    }

                    string combined = string.Join(" ", new[] { file }.Concat(archive.Indicators).Concat(staticResult.Indicators));
                    bool known = RuleMatcher.IsKnownHash(hash, context.Rules);
                    bool namedCheat =
                        namedPath is not null ||
                        RuleMatcher.FindKnownCheatName(
                            combined,
                            context.Rules) is not null;
                    bool highKeyword = RuleMatcher.ContainsHigh(combined, context.Rules);
                    bool mediumKeyword = RuleMatcher.ContainsMedium(combined, context.Rules);
                    bool unsignedUserBinary = isBinary && signature?.IsValid != true && RuleMatcher.IsUserWritable(file);
                    bool strongStatic = staticResult.Score >= 45;
                    bool archiveWithPayload = archive.ExecutableEntries > 0;
                    bool strongArchive = archive.StaticScore >= 40 || archive.Indicators.Count > 0;
                    bool recentOpaqueArchive = isArchive && archive.Unreadable && isDownload && isRecent;
                    bool recentDownloadedBinary = isDownload && isRecent && unsignedUserBinary;
                    bool recentDownloadedPayloadArchive = isDownload && isRecent && archiveWithPayload;
                    // Keep recent Downloads candidates even when their names are generic. This lets browser/file
                    // correlation and Defender evaluate a file that was downloaded but never executed.
                    bool recentDownloadedCandidate = isDownload && isRecent && (isBinary || isArchive);

                    bool relevant = known || namedCheat || highKeyword || strongStatic || strongArchive ||
                                    recentDownloadedCandidate || recentDownloadedBinary || recentDownloadedPayloadArchive || recentOpaqueArchive ||
                                    (mediumKeyword && (unsignedUserBinary || archiveWithPayload));
                    if (!relevant) continue;

                    string detail = BuildDetail(signature, staticResult, archive, isArchive);
                    var metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["RecordType"] = isDownload ? "RecentDownloadArtifact" : "LocalFileArtifact",
                        ["Location"] = effectiveLocation,
                        ["VolumeRoot"] =
                            Path.GetPathRoot(fullPath) ?? "",
                        ["AllDiskSweep"] = "True",
                        ["FileSize"] = info.Length.ToString(),
                        ["Extension"] = extension,
                        ["Created"] = info.CreationTime.ToString("O"),
                        ["LastWrite"] = info.LastWriteTime.ToString("O"),
                        ["Recent30Days"] = isRecent.ToString(),
                        ["StaticRiskScore"] = staticResult.Score.ToString(),
                        ["StaticIndicators"] = string.Join("; ", staticResult.Indicators),
                        ["ArchiveEntryCount"] = archive.EntryCount.ToString(),
                        ["ArchiveExecutableCount"] = archive.ExecutableEntries.ToString(),
                        ["ArchiveStaticScore"] = archive.StaticScore.ToString(),
                        ["ArchiveUnreadable"] = archive.Unreadable.ToString(),
                        ["ArchiveIndicators"] = string.Join("; ", archive.Indicators)
                    };

                    evidence.Add(new EvidenceRecord
                    {
                        Kind = EvidenceKind.FileArtifact,
                        Source = Name,
                        Name = info.Name,
                        Path = info.FullName,
                        HashSha256 = hash,
                        Publisher = signature?.Publisher,
                        IsSignatureValid = signature?.IsValid,
                        Timestamp = info.LastWriteTime,
                        Detail = detail,
                        Metadata = metadata
                    });

                    if (checkedCount % 100 == 0)
                    {
                        progress?.Report(new ScanProgressUpdate
                        {
                            Percent = context.Mode == ScanMode.Quick ? 76 : 82,
                            Module = Name,
                            Message = $"Inspecting disk artifact {checkedCount:N0} in {location}",
                            ItemsChecked = checkedCount
                        });
                    }
                }
            }
            catch
            {
                partial = true;
            }

            if (stopAll)
                break;
        }

        return new CollectorOutput
        {
            Module = Name,
            Status = checkedCount >= max || partial ? CoverageStatus.Partial : CoverageStatus.Completed,
            Summary = $"Checked {checkedCount:N0} executable/archive/shortcut candidates across {volumeRootsVisited:N0} ready fixed or removable volume root(s) and retained {evidence.Count:N0} relevant items. Named-family paths are checked regardless of age; mode-specific caps and time limits prevent an endless scan.",
            Evidence = evidence,
            ItemsChecked = checkedCount,
            Duration = DateTime.UtcNow - started
        };
    }

    private static bool IsUnderPath(
        string candidate,
        string root)
    {
        if (string.IsNullOrWhiteSpace(candidate) ||
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

    private static string BuildDetail(SignatureResult? signature, StaticAnalysisResult staticResult, ArchiveInspection archive, bool isArchive)
    {
        var parts = new List<string>();
        if (signature is not null) parts.Add(signature.Status);
        if (staticResult.Score > 0) parts.Add($"Static score {staticResult.Score}/100: {string.Join(", ", staticResult.Indicators.Take(6))}");
        if (isArchive)
        {
            parts.Add($"Archive entries: {archive.EntryCount}; executable/script payloads: {archive.ExecutableEntries}");
            if (archive.StaticScore > 0) parts.Add($"Embedded static score: {archive.StaticScore}/100");
            if (archive.Indicators.Count > 0) parts.Add(string.Join(", ", archive.Indicators.Take(8)));
            if (archive.Unreadable) parts.Add(archive.Note);
        }
        return parts.Count == 0 ? "Recent file metadata" : string.Join(" | ", parts);
    }

    private static IEnumerable<string> EnumerateFiles(string root, bool recursive)
    {
        if (!recursive)
        {
            string[] top;
            try { top = Directory.GetFiles(root); }
            catch { top = Array.Empty<string>(); }
            foreach (string file in top) yield return file;

            string[] firstLevel;
            try { firstLevel = Directory.GetDirectories(root); }
            catch { firstLevel = Array.Empty<string>(); }
            foreach (string directory in firstLevel.Take(100))
            {
                string[] files;
                try { files = Directory.GetFiles(directory); }
                catch { files = Array.Empty<string>(); }
                foreach (string file in files) yield return file;
            }
            yield break;
        }

        var stack = new Stack<string>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            string current = stack.Pop();
            string[] files;
            try { files = Directory.GetFiles(current); }
            catch { files = Array.Empty<string>(); }
            foreach (string file in files) yield return file;

            string[] directories;
            try { directories = Directory.GetDirectories(current); }
            catch { directories = Array.Empty<string>(); }
            foreach (string directory in directories)
            {
                try
                {
                    if ((new DirectoryInfo(directory).Attributes & FileAttributes.ReparsePoint) == 0)
                        stack.Push(directory);
                }
                catch { }
            }
        }
    }

    private static async Task<ArchiveInspection> InspectZipAsync(string path, RuleSet rules, CancellationToken token)
    {
        int entries = 0;
        int executableEntries = 0;
        int staticScore = 0;
        bool unreadable = false;
        var indicators = new List<string>();

        try
        {
            using ZipArchive archive = ZipFile.OpenRead(path);
            foreach (ZipArchiveEntry entry in archive.Entries.Take(5000))
            {
                token.ThrowIfCancellationRequested();
                entries++;
                string extension = Path.GetExtension(entry.FullName);
                string name = entry.FullName;
                bool executablePayload = ArchivePayloadExtensions.Contains(extension);
                if (executablePayload) executableEntries++;

                if (RuleMatcher.ContainsHigh(name, rules) || RuleMatcher.ContainsMedium(name, rules))
                    indicators.Add("Suspicious archive entry name: " + name);

                if (!executablePayload || entry.Length <= 0 || entry.Length > 24L * 1024 * 1024 || staticScore >= 90)
                    continue;

                try
                {
                    await using Stream input = entry.Open();
                    int limit = (int)Math.Min(entry.Length, 8L * 1024 * 1024);
                    byte[] bytes = new byte[limit];
                    int offset = 0;
                    while (offset < bytes.Length)
                    {
                        int read = await input.ReadAsync(bytes.AsMemory(offset, bytes.Length - offset), token);
                        if (read == 0) break;
                        offset += read;
                    }
                    if (offset != bytes.Length) Array.Resize(ref bytes, offset);
                    StaticAnalysisResult result = StaticFileAnalyzer.AnalyzeBytes(bytes);
                    staticScore = Math.Max(staticScore, result.Score);
                    foreach (string indicator in result.Indicators.Take(10))
                        indicators.Add($"{entry.FullName}: {indicator}");
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

        string note = unreadable
            ? "Some archive content was encrypted, damaged, unsupported, or unavailable for read-only inspection."
            : "ZIP/JAR archive inspected without extracting files.";
        return new ArchiveInspection(entries, executableEntries, staticScore,
            indicators.Distinct(StringComparer.OrdinalIgnoreCase).Take(24).ToArray(), unreadable, note);
    }

    private sealed record ArchiveInspection(
        int EntryCount,
        int ExecutableEntries,
        int StaticScore,
        IReadOnlyList<string> Indicators,
        bool Unreadable,
        string Note)
    {
        public static ArchiveInspection Empty { get; } = new(0, 0, 0, Array.Empty<string>(), false, "");
    }
}
