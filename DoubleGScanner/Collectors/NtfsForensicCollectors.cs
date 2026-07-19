using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using DoubleGScanner.Models;
using DoubleGScanner.Services;
using Microsoft.Win32.SafeHandles;

namespace DoubleGScanner.Collectors;

/// <summary>
/// Enumerates read-only NTFS MFT/USN metadata and samples unallocated clusters.
/// The collector never restores files to disk and never writes to the inspected volume.
/// </summary>
internal static class NtfsForensicNative
{
    internal const uint GenericRead = 0x80000000;
    internal const uint FileShareRead = 0x00000001;
    internal const uint FileShareWrite = 0x00000002;
    internal const uint FileShareDelete = 0x00000004;
    internal const uint OpenExisting = 3;
    internal const uint FileAttributeNormal = 0x00000080;

    internal const uint FsctlEnumUsnData = 0x000900B3;
    internal const uint FsctlReadUsnJournal = 0x000900BB;
    internal const uint FsctlQueryUsnJournal = 0x000900F4;
    internal const uint FsctlGetVolumeBitmap = 0x0009006F;

    internal const int ErrorMoreData = 234;
    internal const int ErrorHandleEof = 38;

    [StructLayout(LayoutKind.Sequential)]
    internal struct MftEnumDataV0
    {
        public ulong StartFileReferenceNumber;
        public long LowUsn;
        public long HighUsn;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct UsnJournalDataV0
    {
        public ulong UsnJournalId;
        public long FirstUsn;
        public long NextUsn;
        public long LowestValidUsn;
        public long MaxUsn;
        public ulong MaximumSize;
        public ulong AllocationDelta;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ReadUsnJournalDataV0
    {
        public long StartUsn;
        public uint ReasonMask;
        public uint ReturnOnlyOnClose;
        public ulong Timeout;
        public ulong BytesToWaitFor;
        public ulong UsnJournalId;
    }

    internal sealed record MftNode(ulong Parent, string Name);
    internal sealed record MftCandidate(
        ulong FileReference,
        ulong ParentReference,
        string Name,
        DateTimeOffset? Timestamp,
        uint Attributes,
        long Usn);

    internal sealed record FreeRun(long StartLcn, long ClusterCount);

    internal static IEnumerable<DriveInfo> NtfsFixedDrives()
    {
        foreach (DriveInfo drive in DriveInfo.GetDrives())
        {
            bool eligible;
            try
            {
                eligible = drive.IsReady &&
                           drive.DriveType == DriveType.Fixed &&
                           drive.DriveFormat.Equals("NTFS", StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                eligible = false;
            }

            if (eligible)
                yield return drive;
        }
    }

    internal static SafeFileHandle OpenVolume(DriveInfo drive)
    {
        string volume = $@"\\.\{drive.Name.TrimEnd('\\')}";
        return CreateFileW(
            volume,
            GenericRead,
            FileShareRead | FileShareWrite | FileShareDelete,
            IntPtr.Zero,
            OpenExisting,
            FileAttributeNormal,
            IntPtr.Zero);
    }

    internal static bool IsRelevantName(string name, RuleSet rules)
    {
        if (string.IsNullOrWhiteSpace(name))
            return false;

        return RuleMatcher.IsExecutableOrArchive(name) ||
               RuleMatcher.FindKnownCheatName(name, rules) is not null ||
               RuleMatcher.ContainsHigh(name, rules) ||
               RuleMatcher.ContainsMedium(name, rules);
    }

    internal static bool IsDeleteReason(uint reason) =>
        (reason & 0x00000200) != 0 || // FILE_DELETE
        (reason & 0x00001000) != 0;   // RENAME_OLD_NAME

    internal static string ReasonText(uint reason)
    {
        var values = new List<string>();

        Add(0x00000001, "DataOverwrite");
        Add(0x00000002, "DataExtend");
        Add(0x00000004, "DataTruncation");
        Add(0x00000100, "FileCreate");
        Add(0x00000200, "FileDelete");
        Add(0x00001000, "RenameOldName");
        Add(0x00002000, "RenameNewName");
        Add(0x00008000, "BasicInfoChange");
        Add(0x00010000, "HardLinkChange");
        Add(0x00020000, "CompressionChange");
        Add(0x00040000, "EncryptionChange");
        Add(0x00100000, "ReparsePointChange");
        Add(0x00200000, "StreamChange");
        Add(0x80000000, "Close");

        return values.Count == 0 ? $"0x{reason:X8}" : string.Join(", ", values);

        void Add(uint flag, string name)
        {
            if ((reason & flag) != 0)
                values.Add(name);
        }
    }

    internal static DateTimeOffset? FileTime(long value)
    {
        try
        {
            return value > 0 ? DateTimeOffset.FromFileTime(value) : null;
        }
        catch
        {
            return null;
        }
    }

    internal static string BuildMftPath(
        string root,
        ulong parentReference,
        string fileName,
        IReadOnlyDictionary<ulong, MftNode> directories)
    {
        var segments = new Stack<string>();
        var visited = new HashSet<ulong>();
        ulong current = parentReference;

        for (int depth = 0; depth < 80 && current != 0 && current != 5; depth++)
        {
            if (!visited.Add(current) ||
                !directories.TryGetValue(current, out MftNode? node))
                break;

            if (!string.IsNullOrWhiteSpace(node.Name) && node.Name != ".")
                segments.Push(node.Name);

            current = node.Parent;
        }

        string path = root;
        while (segments.Count > 0)
            path = Path.Combine(path, segments.Pop());

        return Path.Combine(path, fileName);
    }

    internal static KnownCheatNameEntry? FindKnownNameInBytes(
        ReadOnlySpan<byte> bytes,
        RuleSet rules)
    {
        if (bytes.IsEmpty)
            return null;

        string latin;
        string unicode;

        try
        {
            latin = Encoding.Latin1.GetString(bytes);
            unicode = Encoding.Unicode.GetString(bytes);
        }
        catch
        {
            return null;
        }

        foreach (KnownCheatNameEntry entry in rules.KnownCheatNames)
        {
            foreach (string candidate in entry.Aliases.Prepend(entry.Name))
            {
                if (string.IsNullOrWhiteSpace(candidate))
                    continue;

                string normalized = RuleMatcher.NormalizeName(candidate);
                if (normalized.Length < 4)
                    continue;

                if (latin.Contains(candidate, StringComparison.OrdinalIgnoreCase) ||
                    unicode.Contains(candidate, StringComparison.OrdinalIgnoreCase))
                    return entry;
            }
        }

        return null;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern SafeFileHandle CreateFileW(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", EntryPoint = "DeviceIoControl", SetLastError = true)]
    internal static extern bool DeviceIoControlMft(
        SafeFileHandle device,
        uint controlCode,
        ref MftEnumDataV0 input,
        int inputSize,
        [Out] byte[] output,
        int outputSize,
        out int bytesReturned,
        IntPtr overlapped);

    [DllImport("kernel32.dll", EntryPoint = "DeviceIoControl", SetLastError = true)]
    internal static extern bool DeviceIoControlQueryUsn(
        SafeFileHandle device,
        uint controlCode,
        IntPtr input,
        int inputSize,
        out UsnJournalDataV0 output,
        int outputSize,
        out int bytesReturned,
        IntPtr overlapped);

    [DllImport("kernel32.dll", EntryPoint = "DeviceIoControl", SetLastError = true)]
    internal static extern bool DeviceIoControlReadUsn(
        SafeFileHandle device,
        uint controlCode,
        ref ReadUsnJournalDataV0 input,
        int inputSize,
        [Out] byte[] output,
        int outputSize,
        out int bytesReturned,
        IntPtr overlapped);

    [DllImport("kernel32.dll", EntryPoint = "DeviceIoControl", SetLastError = true)]
    internal static extern bool DeviceIoControlBitmap(
        SafeFileHandle device,
        uint controlCode,
        ref long startingLcn,
        int inputSize,
        [Out] byte[] output,
        int outputSize,
        out int bytesReturned,
        IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool SetFilePointerEx(
        SafeFileHandle file,
        long distanceToMove,
        out long newFilePointer,
        uint moveMethod);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool ReadFile(
        SafeFileHandle file,
        [Out] byte[] buffer,
        int bytesToRead,
        out int bytesRead,
        IntPtr overlapped);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern bool GetDiskFreeSpaceW(
        string rootPathName,
        out uint sectorsPerCluster,
        out uint bytesPerSector,
        out uint numberOfFreeClusters,
        out uint totalNumberOfClusters);
}

public sealed class NtfsMftCollector : IScanCollector
{
    public string Name => "NTFS MFT metadata";
    public bool Supports(ScanMode mode) => mode == ScanMode.Forensic;

    public Task<CollectorOutput> CollectAsync(
        ScanContext context,
        IProgress<ScanProgressUpdate>? progress,
        CancellationToken token)
    {
        DateTime started = DateTime.UtcNow;
        var evidence = new List<EvidenceRecord>();
        int checkedRecords = 0;
        bool partial = false;
        bool available = false;

        if (!SystemProfileCollector.IsAdministrator())
        {
            return Task.FromResult(new CollectorOutput
            {
                Module = Name,
                Status = CoverageStatus.Unavailable,
                Summary = "Administrator access is required for read-only MFT enumeration.",
                Evidence = evidence,
                ItemsChecked = 0,
                Duration = DateTime.UtcNow - started
            });
        }

        const int maxRecords = 350_000;
        TimeSpan timeLimit = TimeSpan.FromSeconds(35);

        foreach (DriveInfo drive in NtfsForensicNative.NtfsFixedDrives())
        {
            token.ThrowIfCancellationRequested();
            using SafeFileHandle volume = NtfsForensicNative.OpenVolume(drive);
            if (volume.IsInvalid)
            {
                partial = true;
                continue;
            }

            available = true;
            var directories = new Dictionary<ulong, NtfsForensicNative.MftNode>();
            var candidates = new List<NtfsForensicNative.MftCandidate>();
            ulong nextReference = 0;
            var input = new NtfsForensicNative.MftEnumDataV0
            {
                StartFileReferenceNumber = 0,
                LowUsn = 0,
                HighUsn = long.MaxValue
            };
            byte[] buffer = new byte[1024 * 1024];

            while (checkedRecords < maxRecords &&
                   DateTime.UtcNow - started < timeLimit)
            {
                token.ThrowIfCancellationRequested();
                input.StartFileReferenceNumber = nextReference;

                bool ok = NtfsForensicNative.DeviceIoControlMft(
                    volume,
                    NtfsForensicNative.FsctlEnumUsnData,
                    ref input,
                    Marshal.SizeOf<NtfsForensicNative.MftEnumDataV0>(),
                    buffer,
                    buffer.Length,
                    out int bytesReturned,
                    IntPtr.Zero);

                int error = Marshal.GetLastWin32Error();
                if (!ok &&
                    error != NtfsForensicNative.ErrorMoreData &&
                    error != NtfsForensicNative.ErrorHandleEof)
                {
                    partial = true;
                    break;
                }

                if (bytesReturned < sizeof(ulong))
                    break;

                ulong returnedNext = BitConverter.ToUInt64(buffer, 0);
                int offset = sizeof(ulong);

                while (offset + 60 <= bytesReturned &&
                       checkedRecords < maxRecords)
                {
                    token.ThrowIfCancellationRequested();

                    uint recordLength = BitConverter.ToUInt32(buffer, offset);
                    if (recordLength < 60 || offset + recordLength > bytesReturned)
                        break;

                    ushort major = BitConverter.ToUInt16(buffer, offset + 4);
                    if (major == 2)
                    {
                        ulong fileReference = BitConverter.ToUInt64(buffer, offset + 8);
                        ulong parentReference = BitConverter.ToUInt64(buffer, offset + 16);
                        long usn = BitConverter.ToInt64(buffer, offset + 24);
                        long fileTime = BitConverter.ToInt64(buffer, offset + 32);
                        uint attributes = BitConverter.ToUInt32(buffer, offset + 52);
                        ushort nameLength = BitConverter.ToUInt16(buffer, offset + 56);
                        ushort nameOffset = BitConverter.ToUInt16(buffer, offset + 58);

                        if (nameLength > 0 &&
                            nameOffset >= 60 &&
                            nameOffset + nameLength <= recordLength)
                        {
                            string name = Encoding.Unicode.GetString(
                                buffer,
                                offset + nameOffset,
                                nameLength);

                            bool directory = (attributes & 0x10) != 0;
                            if (directory)
                            {
                                directories[fileReference] =
                                    new NtfsForensicNative.MftNode(parentReference, name);
                            }
                            else if (NtfsForensicNative.IsRelevantName(name, context.Rules))
                            {
                                candidates.Add(new NtfsForensicNative.MftCandidate(
                                    fileReference,
                                    parentReference,
                                    name,
                                    NtfsForensicNative.FileTime(fileTime),
                                    attributes,
                                    usn));
                            }
                        }
                    }

                    checkedRecords++;
                    offset += (int)recordLength;
                }

                progress?.Report(new ScanProgressUpdate
                {
                    Percent = 75,
                    Module = Name,
                    Message = $"Enumerating {drive.Name} MFT metadata...",
                    ItemsChecked = checkedRecords
                });

                if (returnedNext <= nextReference ||
                    error == NtfsForensicNative.ErrorHandleEof)
                    break;

                nextReference = returnedNext;
                if (ok && offset == sizeof(ulong))
                    break;
            }

            foreach (NtfsForensicNative.MftCandidate candidate in candidates.Take(8_000))
            {
                string path = NtfsForensicNative.BuildMftPath(
                    drive.RootDirectory.FullName,
                    candidate.ParentReference,
                    candidate.Name,
                    directories);

                evidence.Add(new EvidenceRecord
                {
                    Kind = EvidenceKind.NtfsMetadata,
                    Source = Name,
                    Name = candidate.Name,
                    Path = path,
                    Timestamp = candidate.Timestamp,
                    Detail = "Read-only MFT metadata record. This record does not by itself prove deletion or execution.",
                    Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["Volume"] = drive.Name,
                        ["FileReferenceNumber"] = candidate.FileReference.ToString(),
                        ["ParentFileReferenceNumber"] = candidate.ParentReference.ToString(),
                        ["Usn"] = candidate.Usn.ToString(),
                        ["FileAttributes"] = $"0x{candidate.Attributes:X8}",
                        ["RecordType"] = "MftMetadata"
                    }
                });
            }

            if (checkedRecords >= maxRecords ||
                DateTime.UtcNow - started >= timeLimit)
                partial = true;
        }

        CoverageStatus status = !available
            ? CoverageStatus.Unavailable
            : partial
                ? CoverageStatus.Partial
                : CoverageStatus.Completed;

        return Task.FromResult(new CollectorOutput
        {
            Module = Name,
            Status = status,
            Summary = !available
                ? "No readable NTFS fixed volume was available."
                : $"Enumerated {checkedRecords:N0} MFT records and retained {evidence.Count:N0} relevant executable/archive metadata entries.",
            Evidence = evidence,
            ItemsChecked = checkedRecords,
            Duration = DateTime.UtcNow - started
        });
    }
}

public sealed class UsnJournalCollector : IScanCollector
{
    public string Name => "USN change journal";
    public bool Supports(ScanMode mode) => mode == ScanMode.Forensic;

    public Task<CollectorOutput> CollectAsync(
        ScanContext context,
        IProgress<ScanProgressUpdate>? progress,
        CancellationToken token)
    {
        DateTime started = DateTime.UtcNow;
        var evidence = new List<EvidenceRecord>();
        int checkedRecords = 0;
        bool partial = false;
        bool available = false;

        if (!SystemProfileCollector.IsAdministrator())
        {
            return Task.FromResult(new CollectorOutput
            {
                Module = Name,
                Status = CoverageStatus.Unavailable,
                Summary = "Administrator access is required for read-only USN Journal inspection.",
                Evidence = evidence,
                ItemsChecked = 0,
                Duration = DateTime.UtcNow - started
            });
        }

        const int maxRecords = 300_000;
        TimeSpan timeLimit = TimeSpan.FromSeconds(35);

        foreach (DriveInfo drive in NtfsForensicNative.NtfsFixedDrives())
        {
            token.ThrowIfCancellationRequested();
            using SafeFileHandle volume = NtfsForensicNative.OpenVolume(drive);
            if (volume.IsInvalid)
            {
                partial = true;
                continue;
            }

            bool queried = NtfsForensicNative.DeviceIoControlQueryUsn(
                volume,
                NtfsForensicNative.FsctlQueryUsnJournal,
                IntPtr.Zero,
                0,
                out NtfsForensicNative.UsnJournalDataV0 journal,
                Marshal.SizeOf<NtfsForensicNative.UsnJournalDataV0>(),
                out _,
                IntPtr.Zero);

            if (!queried)
            {
                partial = true;
                continue;
            }

            available = true;
            long recentWindow = 512L * 1024 * 1024;
            long startingUsn = Math.Max(journal.FirstUsn, journal.NextUsn - recentWindow);
            bool tailOnly = startingUsn > journal.FirstUsn;

            var input = new NtfsForensicNative.ReadUsnJournalDataV0
            {
                StartUsn = startingUsn,
                ReasonMask = uint.MaxValue,
                ReturnOnlyOnClose = 0,
                Timeout = 0,
                BytesToWaitFor = 0,
                UsnJournalId = journal.UsnJournalId
            };

            byte[] buffer = new byte[1024 * 1024];

            while (input.StartUsn < journal.NextUsn &&
                   checkedRecords < maxRecords &&
                   DateTime.UtcNow - started < timeLimit)
            {
                token.ThrowIfCancellationRequested();

                bool ok = NtfsForensicNative.DeviceIoControlReadUsn(
                    volume,
                    NtfsForensicNative.FsctlReadUsnJournal,
                    ref input,
                    Marshal.SizeOf<NtfsForensicNative.ReadUsnJournalDataV0>(),
                    buffer,
                    buffer.Length,
                    out int bytesReturned,
                    IntPtr.Zero);

                int error = Marshal.GetLastWin32Error();
                if (!ok &&
                    error != NtfsForensicNative.ErrorMoreData &&
                    error != NtfsForensicNative.ErrorHandleEof)
                {
                    partial = true;
                    break;
                }

                if (bytesReturned < sizeof(long))
                    break;

                long nextUsn = BitConverter.ToInt64(buffer, 0);
                int offset = sizeof(long);

                while (offset + 60 <= bytesReturned &&
                       checkedRecords < maxRecords)
                {
                    token.ThrowIfCancellationRequested();

                    uint recordLength = BitConverter.ToUInt32(buffer, offset);
                    if (recordLength < 60 || offset + recordLength > bytesReturned)
                        break;

                    ushort major = BitConverter.ToUInt16(buffer, offset + 4);
                    if (major == 2)
                    {
                        ulong fileReference = BitConverter.ToUInt64(buffer, offset + 8);
                        ulong parentReference = BitConverter.ToUInt64(buffer, offset + 16);
                        long usn = BitConverter.ToInt64(buffer, offset + 24);
                        long fileTime = BitConverter.ToInt64(buffer, offset + 32);
                        uint reason = BitConverter.ToUInt32(buffer, offset + 40);
                        uint attributes = BitConverter.ToUInt32(buffer, offset + 52);
                        ushort nameLength = BitConverter.ToUInt16(buffer, offset + 56);
                        ushort nameOffset = BitConverter.ToUInt16(buffer, offset + 58);

                        if (nameLength > 0 &&
                            nameOffset >= 60 &&
                            nameOffset + nameLength <= recordLength)
                        {
                            string name = Encoding.Unicode.GetString(
                                buffer,
                                offset + nameOffset,
                                nameLength);

                            bool relevant = NtfsForensicNative.IsRelevantName(
                                name,
                                context.Rules);

                            bool deleteEvent = NtfsForensicNative.IsDeleteReason(reason);
                            if (relevant &&
                                (deleteEvent ||
                                 RuleMatcher.FindKnownCheatName(name, context.Rules) is not null ||
                                 RuleMatcher.ContainsHigh(name, context.Rules)))
                            {
                                evidence.Add(new EvidenceRecord
                                {
                                    Kind = EvidenceKind.UsnJournal,
                                    Source = Name,
                                    Name = name,
                                    Path = $"{drive.Name}{name}",
                                    Timestamp = NtfsForensicNative.FileTime(fileTime),
                                    Detail = $"USN event: {NtfsForensicNative.ReasonText(reason)}",
                                    Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                                    {
                                        ["Volume"] = drive.Name,
                                        ["FileReferenceNumber"] = fileReference.ToString(),
                                        ["ParentFileReferenceNumber"] = parentReference.ToString(),
                                        ["Usn"] = usn.ToString(),
                                        ["Reason"] = $"0x{reason:X8}",
                                        ["ReasonText"] = NtfsForensicNative.ReasonText(reason),
                                        ["IsDeleteEvent"] = deleteEvent.ToString(),
                                        ["FileAttributes"] = $"0x{attributes:X8}",
                                        ["RecordType"] = deleteEvent
                                            ? "DeletedUsnTrace"
                                            : "UsnChangeTrace"
                                    }
                                });
                            }
                        }
                    }

                    checkedRecords++;
                    offset += (int)recordLength;
                }

                progress?.Report(new ScanProgressUpdate
                {
                    Percent = 79,
                    Module = Name,
                    Message = $"Reading recent {drive.Name} USN events...",
                    ItemsChecked = checkedRecords
                });

                if (nextUsn <= input.StartUsn ||
                    error == NtfsForensicNative.ErrorHandleEof)
                    break;

                input.StartUsn = nextUsn;
            }

            if (tailOnly ||
                checkedRecords >= maxRecords ||
                DateTime.UtcNow - started >= timeLimit)
                partial = true;
        }

        CoverageStatus status = !available
            ? CoverageStatus.Unavailable
            : partial
                ? CoverageStatus.Partial
                : CoverageStatus.Completed;

        return Task.FromResult(new CollectorOutput
        {
            Module = Name,
            Status = status,
            Summary = !available
                ? "The USN Journal was unavailable on readable NTFS volumes."
                : $"Checked {checkedRecords:N0} recent journal records and retained {evidence.Count:N0} relevant file-change or deletion traces.",
            Evidence = evidence,
            ItemsChecked = checkedRecords,
            Duration = DateTime.UtcNow - started
        });
    }
}

public sealed class UnallocatedSpaceCollector : IScanCollector
{
    public string Name => "Unallocated-space signature scan";
    public bool Supports(ScanMode mode) => mode == ScanMode.Forensic;

    private const int SampleSize = 1024 * 1024;
    private const long MaxBytesPerVolume = 256L * 1024 * 1024;
    private const int MaxCandidates = 160;

    public Task<CollectorOutput> CollectAsync(
        ScanContext context,
        IProgress<ScanProgressUpdate>? progress,
        CancellationToken token)
    {
        DateTime started = DateTime.UtcNow;
        var evidence = new List<EvidenceRecord>();
        long bytesReadTotal = 0;
        int samplesRead = 0;
        bool partial = false;
        bool available = false;

        if (!SystemProfileCollector.IsAdministrator())
        {
            return Task.FromResult(new CollectorOutput
            {
                Module = Name,
                Status = CoverageStatus.Unavailable,
                Summary = "Administrator access is required for read-only raw-volume sampling.",
                Evidence = evidence,
                ItemsChecked = 0,
                Duration = DateTime.UtcNow - started
            });
        }

        foreach (DriveInfo drive in NtfsForensicNative.NtfsFixedDrives())
        {
            token.ThrowIfCancellationRequested();

            if (!NtfsForensicNative.GetDiskFreeSpaceW(
                    drive.RootDirectory.FullName,
                    out uint sectorsPerCluster,
                    out uint bytesPerSector,
                    out _,
                    out _))
            {
                partial = true;
                continue;
            }

            long clusterSize = (long)sectorsPerCluster * bytesPerSector;
            if (clusterSize <= 0)
            {
                partial = true;
                continue;
            }

            using SafeFileHandle volume = NtfsForensicNative.OpenVolume(drive);
            if (volume.IsInvalid)
            {
                partial = true;
                continue;
            }

            available = true;
            IReadOnlyList<NtfsForensicNative.FreeRun> runs =
                ReadFreeRuns(volume, token, out bool bitmapPartial);

            if (bitmapPartial)
                partial = true;

            if (runs.Count == 0)
                continue;

            int maxSamples = (int)Math.Max(1, MaxBytesPerVolume / SampleSize);
            int selectedSamples = Math.Min(maxSamples, runs.Count);

            for (int sampleIndex = 0;
                 sampleIndex < selectedSamples &&
                 evidence.Count < MaxCandidates;
                 sampleIndex++)
            {
                token.ThrowIfCancellationRequested();

                int runIndex = selectedSamples == 1
                    ? 0
                    : (int)Math.Round(
                        sampleIndex * (runs.Count - 1d) /
                        (selectedSamples - 1d));

                NtfsForensicNative.FreeRun run = runs[runIndex];
                long runBytes = checked(run.ClusterCount * clusterSize);
                int readLength = (int)Math.Min(SampleSize, runBytes);
                readLength -= readLength % (int)Math.Max(1, bytesPerSector);

                if (readLength <= 0)
                    continue;

                long diskOffset = checked(run.StartLcn * clusterSize);
                byte[] buffer = new byte[readLength];

                if (!NtfsForensicNative.SetFilePointerEx(
                        volume,
                        diskOffset,
                        out _,
                        0) ||
                    !NtfsForensicNative.ReadFile(
                        volume,
                        buffer,
                        buffer.Length,
                        out int bytesRead,
                        IntPtr.Zero) ||
                    bytesRead <= 0)
                {
                    partial = true;
                    continue;
                }

                samplesRead++;
                bytesReadTotal += bytesRead;
                AnalyzeSample(
                    drive,
                    diskOffset,
                    buffer.AsSpan(0, bytesRead),
                    context.Rules,
                    evidence);

                progress?.Report(new ScanProgressUpdate
                {
                    Percent = 84,
                    Module = Name,
                    Message = $"Sampling free clusters on {drive.Name} without restoring content...",
                    ItemsChecked = samplesRead
                });
            }

            if (runs.Count > selectedSamples)
                partial = true;
        }

        CoverageStatus status = !available
            ? CoverageStatus.Unavailable
            : partial
                ? CoverageStatus.Partial
                : CoverageStatus.Completed;

        return Task.FromResult(new CollectorOutput
        {
            Module = Name,
            Status = status,
            Summary = !available
                ? "No readable NTFS volume was available for raw signature sampling."
                : $"Read {bytesReadTotal / (1024d * 1024d):N1} MB from free clusters in {samplesRead:N0} read-only samples and retained {evidence.Count:N0} suspicious executable/archive fragments. No file was restored or saved.",
            Evidence = evidence,
            ItemsChecked = samplesRead,
            Duration = DateTime.UtcNow - started
        });
    }

    private static IReadOnlyList<NtfsForensicNative.FreeRun> ReadFreeRuns(
        SafeFileHandle volume,
        CancellationToken token,
        out bool partial)
    {
        partial = false;
        var runs = new List<NtfsForensicNative.FreeRun>();
        byte[] output = new byte[4 * 1024 * 1024];
        long requestedLcn = 0;
        long pendingStart = -1;
        long pendingCount = 0;

        while (runs.Count < 200_000)
        {
            token.ThrowIfCancellationRequested();

            bool ok = NtfsForensicNative.DeviceIoControlBitmap(
                volume,
                NtfsForensicNative.FsctlGetVolumeBitmap,
                ref requestedLcn,
                sizeof(long),
                output,
                output.Length,
                out int bytesReturned,
                IntPtr.Zero);

            int error = Marshal.GetLastWin32Error();
            if (!ok &&
                error != NtfsForensicNative.ErrorMoreData &&
                error != NtfsForensicNative.ErrorHandleEof)
            {
                partial = true;
                break;
            }

            if (bytesReturned < 16)
                break;

            long returnedStart = BitConverter.ToInt64(output, 0);
            long bitmapSize = BitConverter.ToInt64(output, 8);
            long availableBits = (bytesReturned - 16L) * 8L;
            long bits = Math.Min(bitmapSize, availableBits);

            for (long bit = 0; bit < bits; bit++)
            {
                int byteIndex = 16 + (int)(bit / 8);
                int mask = 1 << (int)(bit % 8);
                bool allocated = (output[byteIndex] & mask) != 0;
                long lcn = returnedStart + bit;

                if (!allocated)
                {
                    if (pendingStart < 0)
                        pendingStart = lcn;

                    pendingCount++;
                }
                else if (pendingStart >= 0)
                {
                    runs.Add(new NtfsForensicNative.FreeRun(
                        pendingStart,
                        pendingCount));
                    pendingStart = -1;
                    pendingCount = 0;

                    if (runs.Count >= 200_000)
                        break;
                }
            }

            if (pendingStart >= 0 &&
                (ok || error == NtfsForensicNative.ErrorHandleEof))
            {
                runs.Add(new NtfsForensicNative.FreeRun(
                    pendingStart,
                    pendingCount));
                pendingStart = -1;
                pendingCount = 0;
            }

            long next = returnedStart + bits;
            if (next <= requestedLcn ||
                ok ||
                error == NtfsForensicNative.ErrorHandleEof)
                break;

            requestedLcn = next;
        }

        if (runs.Count >= 200_000)
            partial = true;

        return runs;
    }

    private static void AnalyzeSample(
        DriveInfo drive,
        long baseOffset,
        ReadOnlySpan<byte> sample,
        RuleSet rules,
        List<EvidenceRecord> evidence)
    {
        foreach ((int offset, string type) in FindSignatures(sample))
        {
            if (evidence.Count >= MaxCandidates)
                return;

            int fragmentLength = Math.Min(
                sample.Length - offset,
                1024 * 1024);

            if (fragmentLength <= 0)
                continue;

            ReadOnlySpan<byte> fragment =
                sample.Slice(offset, fragmentLength);

            KnownCheatNameEntry? named =
                NtfsForensicNative.FindKnownNameInBytes(
                    fragment,
                    rules);

            StaticAnalysisResult staticResult =
                type == "PE executable"
                    ? StaticFileAnalyzer.AnalyzeBytes(fragment)
                    : StaticAnalysisResult.Empty;

            string text;
            try
            {
                text = Encoding.Latin1.GetString(fragment);
            }
            catch
            {
                text = "";
            }

            bool high = RuleMatcher.ContainsHigh(text, rules);
            bool relevant = named is not null ||
                            staticResult.Score >= 45 ||
                            high;

            if (!relevant)
                continue;

            long absoluteOffset = baseOffset + offset;
            string fragmentHash =
                Convert.ToHexString(SHA256.HashData(fragment));

            evidence.Add(new EvidenceRecord
            {
                Kind = EvidenceKind.RawDeletedFile,
                Source = "Unallocated-space signature scan",
                Name = named?.Name ?? $"{type} fragment",
                Path = $"{drive.Name} [unallocated offset 0x{absoluteOffset:X}]",
                HashSha256 = fragmentHash,
                Detail = "Read-only in-memory signature fragment from a cluster marked free at scan time. The content was not restored or written to disk.",
                Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["Volume"] = drive.Name,
                    ["DiskOffset"] = absoluteOffset.ToString(),
                    ["DiskOffsetHex"] = $"0x{absoluteOffset:X}",
                    ["SignatureType"] = type,
                    ["FragmentLength"] = fragmentLength.ToString(),
                    ["StaticRiskScore"] = staticResult.Score.ToString(),
                    ["StaticIndicators"] = string.Join("; ", staticResult.Indicators),
                    ["DetectedName"] = named?.Name ?? "",
                    ["CheatFamily"] = named?.Family ?? "",
                    ["AllocationState"] = "Free at scan time",
                    ["RecoveredToDisk"] = "False",
                    ["RecordType"] = "RawDeletedSignature"
                }
            });
        }
    }

    private static IEnumerable<(int Offset, string Type)> FindSignatures(
        ReadOnlySpan<byte> data)
    {
        int found = 0;

        for (int index = 0;
             index + 8 < data.Length && found < 24;
             index++)
        {
            if (data[index] == (byte)'M' &&
                data[index + 1] == (byte)'Z' &&
                IsPortableExecutable(data, index))
            {
                yield return (index, "PE executable");
                found++;
                index += 63;
                continue;
            }

            if (data[index] == 0x50 &&
                data[index + 1] == 0x4B &&
                data[index + 2] == 0x03 &&
                data[index + 3] == 0x04)
            {
                yield return (index, "ZIP archive");
                found++;
                index += 31;
                continue;
            }

            if (data[index] == 0x52 &&
                data[index + 1] == 0x61 &&
                data[index + 2] == 0x72 &&
                data[index + 3] == 0x21 &&
                data[index + 4] == 0x1A &&
                data[index + 5] == 0x07)
            {
                yield return (index, "RAR archive");
                found++;
                index += 15;
                continue;
            }

            if (data[index] == 0x37 &&
                data[index + 1] == 0x7A &&
                data[index + 2] == 0xBC &&
                data[index + 3] == 0xAF &&
                data[index + 4] == 0x27 &&
                data[index + 5] == 0x1C)
            {
                yield return (index, "7-Zip archive");
                found++;
                index += 15;
                continue;
            }

            if (data[index] == 0xD0 &&
                data[index + 1] == 0xCF &&
                data[index + 2] == 0x11 &&
                data[index + 3] == 0xE0 &&
                data[index + 4] == 0xA1 &&
                data[index + 5] == 0xB1 &&
                data[index + 6] == 0x1A &&
                data[index + 7] == 0xE1)
            {
                yield return (index, "OLE/MSI container");
                found++;
                index += 15;
            }
        }
    }

    private static bool IsPortableExecutable(
        ReadOnlySpan<byte> data,
        int mzOffset)
    {
        if (mzOffset + 0x40 > data.Length)
            return false;

        int peOffset;
        try
        {
            peOffset = BitConverter.ToInt32(
                data.Slice(mzOffset + 0x3C, 4));
        }
        catch
        {
            return false;
        }

        if (peOffset <= 0 ||
            peOffset > 4 * 1024 * 1024)
            return false;

        int signature = mzOffset + peOffset;
        return signature + 4 <= data.Length &&
               data[signature] == (byte)'P' &&
               data[signature + 1] == (byte)'E' &&
               data[signature + 2] == 0 &&
               data[signature + 3] == 0;
    }
}
