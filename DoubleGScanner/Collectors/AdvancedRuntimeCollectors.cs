using System.Collections;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using DoubleGScanner.Models;
using DoubleGScanner.Services;
using Microsoft.Win32;

namespace DoubleGScanner.Collectors;

/// <summary>
/// Enumerates system process handles and identifies processes that currently hold
/// a handle to cs2.exe. The collector never reads or writes CS2 memory.
/// </summary>
public sealed class Cs2HandleAccessCollector : IScanCollector
{
    public string Name => "CS2 process-handle access";
    public bool Supports(ScanMode mode) => true;

    public async Task<CollectorOutput> CollectAsync(
        ScanContext context,
        IProgress<ScanProgressUpdate>? progress,
        CancellationToken token)
    {
        DateTime started = DateTime.UtcNow;
        var evidence = new List<EvidenceRecord>();
        Process[] cs2Processes = Process.GetProcessesByName("cs2");
        if (cs2Processes.Length == 0)
        {
            return new CollectorOutput
            {
                Module = Name,
                Status = CoverageStatus.Partial,
                Summary = "CS2 was not running; live process-handle inspection was unavailable.",
                Evidence = evidence,
                ItemsChecked = 0,
                Duration = DateTime.UtcNow - started
            };
        }

        var targetPids = cs2Processes.Select(process => process.Id).ToHashSet();
        foreach (Process process in cs2Processes) process.Dispose();

        progress?.Report(new ScanProgressUpdate
        {
            Percent = 23,
            Module = Name,
            Message = "Enumerating live handles that target cs2.exe...",
            ItemsChecked = 0
        });

        bool partial = false;
        int checkedHandles = 0;
        IntPtr buffer = IntPtr.Zero;
        var ownerHandles = new Dictionary<int, IntPtr>();

        try
        {
            int length = 1 << 20;
            int returnLength = 0;
            int status;

            for (int attempt = 0; attempt < 8; attempt++)
            {
                token.ThrowIfCancellationRequested();
                buffer = Marshal.AllocHGlobal(length);
                status = NtQuerySystemInformation(
                    SystemExtendedHandleInformation,
                    buffer,
                    length,
                    ref returnLength);

                if (status == StatusInfoLengthMismatch)
                {
                    Marshal.FreeHGlobal(buffer);
                    buffer = IntPtr.Zero;
                    length = Math.Max(length * 2, returnLength + (1 << 20));
                    continue;
                }

                if (status < 0)
                {
                    partial = true;
                    return new CollectorOutput
                    {
                        Module = Name,
                        Status = CoverageStatus.Partial,
                        Summary = $"System handle enumeration was unavailable (NTSTATUS 0x{status:X8}).",
                        Evidence = evidence,
                        ItemsChecked = checkedHandles,
                        Duration = DateTime.UtcNow - started
                    };
                }

                break;
            }

            if (buffer == IntPtr.Zero)
            {
                return new CollectorOutput
                {
                    Module = Name,
                    Status = CoverageStatus.Partial,
                    Summary = "System handle enumeration did not return a usable buffer.",
                    Evidence = evidence,
                    ItemsChecked = checkedHandles,
                    Duration = DateTime.UtcNow - started
                };
            }

            ulong totalHandles = UIntPtr.Size == 8
                ? unchecked((ulong)Marshal.ReadInt64(buffer))
                : unchecked((uint)Marshal.ReadInt32(buffer));

            int entrySize = Marshal.SizeOf<SystemHandleTableEntryInfoEx>();
            IntPtr entryPointer = IntPtr.Add(buffer, IntPtr.Size * 2);
            ulong cap = context.Mode switch
            {
                ScanMode.Quick => 300_000UL,
                ScanMode.Full => 800_000UL,
                _ => 2_000_000UL
            };

            ulong entriesToCheck = Math.Min(totalHandles, cap);
            if (totalHandles > cap) partial = true;

            var candidates = new List<HandleCandidate>();
            int currentPid = Environment.ProcessId;

            for (ulong index = 0; index < entriesToCheck; index++)
            {
                token.ThrowIfCancellationRequested();
                checkedHandles++;

                SystemHandleTableEntryInfoEx entry =
                    Marshal.PtrToStructure<SystemHandleTableEntryInfoEx>(entryPointer);
                entryPointer = IntPtr.Add(entryPointer, entrySize);

                int ownerPid = unchecked((int)entry.UniqueProcessId.ToUInt64());
                if (ownerPid <= 4 || ownerPid == currentPid || targetPids.Contains(ownerPid))
                    continue;

                if (!HasRelevantProcessAccess(entry.GrantedAccess))
                    continue;

                if (!ownerHandles.TryGetValue(ownerPid, out IntPtr ownerProcess))
                {
                    ownerProcess = OpenProcess(
                        ProcessDuplicateHandle | ProcessQueryLimitedInformation,
                        false,
                        ownerPid);
                    ownerHandles[ownerPid] = ownerProcess;
                }

                if (ownerProcess == IntPtr.Zero)
                {
                    partial = true;
                    continue;
                }

                if (!DuplicateHandle(
                        ownerProcess,
                        new IntPtr(unchecked((long)entry.HandleValue.ToUInt64())),
                        GetCurrentProcess(),
                        out IntPtr duplicated,
                        0,
                        false,
                        DuplicateSameAccess))
                {
                    partial = true;
                    continue;
                }

                try
                {
                    int targetPid = GetProcessId(duplicated);
                    if (!targetPids.Contains(targetPid)) continue;

                    candidates.Add(new HandleCandidate(
                        ownerPid,
                        targetPid,
                        entry.GrantedAccess,
                        DecodeProcessAccess(entry.GrantedAccess)));
                }
                finally
                {
                    CloseHandle(duplicated);
                }

                if (checkedHandles % 25_000 == 0)
                {
                    progress?.Report(new ScanProgressUpdate
                    {
                        Percent = 25,
                        Module = Name,
                        Message = $"Checked {checkedHandles:N0} system handles; found {candidates.Count:N0} CS2 handle(s)...",
                        ItemsChecked = checkedHandles
                    });
                }
            }

            foreach (HandleCandidate candidate in candidates
                         .GroupBy(item => new { item.OwnerPid, item.TargetPid, item.Access })
                         .Select(group => group.First()))
            {
                token.ThrowIfCancellationRequested();
                string processName = TryGetProcessName(candidate.OwnerPid);
                string? path = TryGetProcessPath(candidate.OwnerPid);
                SignatureResult? signature = null;
                string? hash = null;

                bool dangerous = HasWriteOrInjectionAccess(candidate.Access);
                if (!string.IsNullOrWhiteSpace(path) && File.Exists(path) && dangerous)
                {
                    signature = SignatureVerifier.Verify(path);
                    hash = await HashService.TrySha256Async(path, token).ConfigureAwait(false);
                }

                evidence.Add(new EvidenceRecord
                {
                    Kind = EvidenceKind.ProcessHandle,
                    Source = Name,
                    Name = processName,
                    Path = path,
                    HashSha256 = hash,
                    Publisher = signature?.Publisher,
                    IsSignatureValid = signature?.IsValid,
                    ProcessId = candidate.OwnerPid,
                    Detail = $"PID {candidate.OwnerPid} holds a live handle to cs2.exe PID {candidate.TargetPid}.",
                    Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["RecordType"] = "Cs2ProcessHandle",
                        ["OwnerProcessId"] = candidate.OwnerPid.ToString(),
                        ["TargetProcessId"] = candidate.TargetPid.ToString(),
                        ["GrantedAccessHex"] = $"0x{candidate.Access:X8}",
                        ["AccessRights"] = candidate.AccessText,
                        ["HasVmRead"] = HasAccess(candidate.Access, ProcessVmRead).ToString(),
                        ["HasVmWrite"] = HasAccess(candidate.Access, ProcessVmWrite).ToString(),
                        ["HasVmOperation"] = HasAccess(candidate.Access, ProcessVmOperation).ToString(),
                        ["HasCreateThread"] = HasAccess(candidate.Access, ProcessCreateThread).ToString(),
                        ["HasDuplicateHandle"] = HasAccess(candidate.Access, ProcessDuplicateHandle).ToString(),
                        ["DangerousWriteOrInjectionAccess"] = dangerous.ToString()
                    }
                });
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            partial = true;
        }
        finally
        {
            foreach (IntPtr handle in ownerHandles.Values)
            {
                if (handle != IntPtr.Zero) CloseHandle(handle);
            }

            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
        }

        string summary = evidence.Count == 0
            ? $"Checked {checkedHandles:N0} system handles; no relevant live CS2 process handle was retained."
            : $"Checked {checkedHandles:N0} system handles and retained {evidence.Count:N0} process(es) with relevant access to cs2.exe.";

        return new CollectorOutput
        {
            Module = Name,
            Status = partial ? CoverageStatus.Partial : CoverageStatus.Completed,
            Summary = summary,
            Evidence = evidence,
            ItemsChecked = checkedHandles,
            Duration = DateTime.UtcNow - started
        };
    }

    private static bool HasRelevantProcessAccess(uint access) =>
        HasAccess(access, ProcessVmRead) ||
        HasAccess(access, ProcessVmWrite) ||
        HasAccess(access, ProcessVmOperation) ||
        HasAccess(access, ProcessCreateThread) ||
        HasAccess(access, ProcessDuplicateHandle) ||
        HasAccess(access, ProcessSuspendResume) ||
        HasAccess(access, ProcessSetInformation);

    private static bool HasWriteOrInjectionAccess(uint access) =>
        HasAccess(access, ProcessVmWrite) ||
        HasAccess(access, ProcessVmOperation) ||
        HasAccess(access, ProcessCreateThread);

    private static bool HasAccess(uint access, uint flag) => (access & flag) == flag;

    private static string DecodeProcessAccess(uint access)
    {
        var rights = new List<string>();
        Add(ProcessTerminate, "TERMINATE");
        Add(ProcessCreateThread, "CREATE_THREAD");
        Add(ProcessVmOperation, "VM_OPERATION");
        Add(ProcessVmRead, "VM_READ");
        Add(ProcessVmWrite, "VM_WRITE");
        Add(ProcessDuplicateHandle, "DUP_HANDLE");
        Add(ProcessSetInformation, "SET_INFORMATION");
        Add(ProcessSuspendResume, "SUSPEND_RESUME");
        Add(ProcessQueryInformation, "QUERY_INFORMATION");
        Add(ProcessQueryLimitedInformation, "QUERY_LIMITED_INFORMATION");
        return rights.Count == 0 ? $"0x{access:X8}" : string.Join(" | ", rights);

        void Add(uint flag, string name)
        {
            if (HasAccess(access, flag)) rights.Add(name);
        }
    }

    private static string TryGetProcessName(int pid)
    {
        try
        {
            using Process process = Process.GetProcessById(pid);
            return process.ProcessName;
        }
        catch
        {
            return $"PID {pid}";
        }
    }

    private static string? TryGetProcessPath(int pid)
    {
        IntPtr process = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (process == IntPtr.Zero) return null;
        try
        {
            int capacity = 32_768;
            var builder = new StringBuilder(capacity);
            return QueryFullProcessImageName(process, 0, builder, ref capacity)
                ? builder.ToString()
                : null;
        }
        finally
        {
            CloseHandle(process);
        }
    }

    private sealed record HandleCandidate(int OwnerPid, int TargetPid, uint Access, string AccessText);

    private const int SystemExtendedHandleInformation = 64;
    private const int StatusInfoLengthMismatch = unchecked((int)0xC0000004);
    private const uint DuplicateSameAccess = 0x00000002;
    private const uint ProcessTerminate = 0x0001;
    private const uint ProcessCreateThread = 0x0002;
    private const uint ProcessVmOperation = 0x0008;
    private const uint ProcessVmRead = 0x0010;
    private const uint ProcessVmWrite = 0x0020;
    private const uint ProcessDuplicateHandle = 0x0040;
    private const uint ProcessSetInformation = 0x0200;
    private const uint ProcessQueryInformation = 0x0400;
    private const uint ProcessSuspendResume = 0x0800;
    private const uint ProcessQueryLimitedInformation = 0x1000;

    [StructLayout(LayoutKind.Sequential)]
    private struct SystemHandleTableEntryInfoEx
    {
        public IntPtr Object;
        public UIntPtr UniqueProcessId;
        public UIntPtr HandleValue;
        public uint GrantedAccess;
        public ushort CreatorBackTraceIndex;
        public ushort ObjectTypeIndex;
        public uint HandleAttributes;
        public uint Reserved;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(
        int systemInformationClass,
        IntPtr systemInformation,
        int systemInformationLength,
        ref int returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DuplicateHandle(
        IntPtr sourceProcessHandle,
        IntPtr sourceHandle,
        IntPtr targetProcessHandle,
        out IntPtr targetHandle,
        uint desiredAccess,
        bool inheritHandle,
        uint options);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    private static extern int GetProcessId(IntPtr processHandle);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool QueryFullProcessImageName(
        IntPtr process,
        int flags,
        StringBuilder executableName,
        ref int size);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);
}

/// <summary>
/// Reviews top-level windows that substantially overlap the CS2 render window.
/// Layered/topmost/click-through windows are retained as review evidence.
/// </summary>
public sealed class OverlayWindowCollector : IScanCollector
{
    public string Name => "CS2 overlay windows";
    public bool Supports(ScanMode mode) => true;

    public async Task<CollectorOutput> CollectAsync(
        ScanContext context,
        IProgress<ScanProgressUpdate>? progress,
        CancellationToken token)
    {
        DateTime started = DateTime.UtcNow;
        var evidence = new List<EvidenceRecord>();
        Process[] cs2Processes = Process.GetProcessesByName("cs2");
        if (cs2Processes.Length == 0)
        {
            return new CollectorOutput
            {
                Module = Name,
                Status = CoverageStatus.Partial,
                Summary = "CS2 was not running; live overlay-window inspection was unavailable.",
                Evidence = evidence,
                ItemsChecked = 0,
                Duration = DateTime.UtcNow - started
            };
        }

        var cs2Pids = cs2Processes.Select(process => process.Id).ToHashSet();
        foreach (Process process in cs2Processes) process.Dispose();

        var cs2Windows = new List<(IntPtr Handle, Rect Bounds, int Pid)>();
        int windowsChecked = 0;
        bool partial = false;

        EnumWindows((window, _) =>
        {
            GetWindowThreadProcessId(window, out uint pid);
            if (cs2Pids.Contains(unchecked((int)pid)) &&
                IsWindowVisible(window) &&
                GetWindowRect(window, out Rect bounds) &&
                bounds.Area > 0)
            {
                cs2Windows.Add((window, bounds, unchecked((int)pid)));
            }
            return true;
        }, IntPtr.Zero);

        if (cs2Windows.Count == 0)
        {
            return new CollectorOutput
            {
                Module = Name,
                Status = CoverageStatus.Partial,
                Summary = "cs2.exe was running, but its visible top-level render window was not available.",
                Evidence = evidence,
                ItemsChecked = 0,
                Duration = DateTime.UtcNow - started
            };
        }

        progress?.Report(new ScanProgressUpdate
        {
            Percent = 29,
            Module = Name,
            Message = "Reviewing layered/topmost windows overlapping CS2...",
            ItemsChecked = 0
        });

        var candidates = new List<OverlayCandidate>();
        EnumWindows((window, _) =>
        {
            if (token.IsCancellationRequested) return false;
            windowsChecked++;

            if (!IsWindowVisible(window)) return true;
            GetWindowThreadProcessId(window, out uint ownerPidRaw);
            int ownerPid = unchecked((int)ownerPidRaw);
            if (ownerPid <= 0 || cs2Pids.Contains(ownerPid) || ownerPid == Environment.ProcessId)
                return true;

            if (!GetWindowRect(window, out Rect bounds) || bounds.Area <= 0)
                return true;

            int cloaked = 0;
            if (DwmGetWindowAttribute(window, DwmwaCloaked, out cloaked, sizeof(int)) == 0 && cloaked != 0)
                return true;

            double maximumOverlap = cs2Windows.Max(item => IntersectionRatio(bounds, item.Bounds));
            if (maximumOverlap < 0.50) return true;

            long exStyle = GetWindowLongPtr(window, GwlExStyle).ToInt64();
            bool layered = (exStyle & WsExLayered) != 0;
            bool topmost = (exStyle & WsExTopmost) != 0;
            bool transparent = (exStyle & WsExTransparent) != 0;
            bool toolWindow = (exStyle & WsExToolWindow) != 0;
            bool noActivate = (exStyle & WsExNoActivate) != 0;
            bool strongPattern = layered && topmost && (transparent || noActivate) && maximumOverlap >= 0.75;

            if (!layered && !topmost && !transparent && !strongPattern)
                return true;

            candidates.Add(new OverlayCandidate(
                window,
                ownerPid,
                bounds,
                maximumOverlap,
                exStyle,
                layered,
                topmost,
                transparent,
                toolWindow,
                noActivate,
                strongPattern,
                GetWindowTextValue(window),
                GetClassNameValue(window)));
            return true;
        }, IntPtr.Zero);
        token.ThrowIfCancellationRequested();

        foreach (OverlayCandidate candidate in candidates)
        {
            token.ThrowIfCancellationRequested();
            string processName = TryGetProcessName(candidate.ProcessId);
            string? path = TryGetProcessPath(candidate.ProcessId);
            SignatureResult? signature = null;
            string? hash = null;

            if (candidate.StrongPattern && !string.IsNullOrWhiteSpace(path) && File.Exists(path))
            {
                signature = SignatureVerifier.Verify(path);
                hash = await HashService.TrySha256Async(path, token).ConfigureAwait(false);
            }

            evidence.Add(new EvidenceRecord
            {
                Kind = EvidenceKind.Overlay,
                Source = Name,
                Name = processName,
                Path = path,
                HashSha256 = hash,
                Publisher = signature?.Publisher,
                IsSignatureValid = signature?.IsValid,
                ProcessId = candidate.ProcessId,
                Detail = $"Window overlaps {candidate.Overlap:P0} of the CS2 window.",
                Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["RecordType"] = "Cs2OverlayWindow",
                    ["WindowTitle"] = candidate.Title,
                    ["WindowClass"] = candidate.ClassName,
                    ["ExtendedStyleHex"] = $"0x{candidate.ExtendedStyle:X}",
                    ["Layered"] = candidate.Layered.ToString(),
                    ["Topmost"] = candidate.Topmost.ToString(),
                    ["ClickThrough"] = candidate.Transparent.ToString(),
                    ["ToolWindow"] = candidate.ToolWindow.ToString(),
                    ["NoActivate"] = candidate.NoActivate.ToString(),
                    ["StrongOverlayPattern"] = candidate.StrongPattern.ToString(),
                    ["OverlapRatio"] = candidate.Overlap.ToString("0.000", System.Globalization.CultureInfo.InvariantCulture),
                    ["WindowBounds"] = $"{candidate.Bounds.Left},{candidate.Bounds.Top},{candidate.Bounds.Right},{candidate.Bounds.Bottom}"
                }
            });
        }

        string summary = evidence.Count == 0
            ? $"Checked {windowsChecked:N0} top-level windows; no overlay-style window substantially overlapping CS2 was retained."
            : $"Checked {windowsChecked:N0} top-level windows and retained {evidence.Count:N0} overlay-style candidate(s).";

        return new CollectorOutput
        {
            Module = Name,
            Status = partial ? CoverageStatus.Partial : CoverageStatus.Completed,
            Summary = summary,
            Evidence = evidence,
            ItemsChecked = windowsChecked,
            Duration = DateTime.UtcNow - started
        };
    }

    private static string TryGetProcessName(int pid)
    {
        try
        {
            using Process process = Process.GetProcessById(pid);
            return process.ProcessName;
        }
        catch
        {
            return $"PID {pid}";
        }
    }

    private static string? TryGetProcessPath(int pid)
    {
        IntPtr process = OpenProcess(ProcessQueryLimitedInformation, false, pid);
        if (process == IntPtr.Zero) return null;
        try
        {
            int capacity = 32_768;
            var builder = new StringBuilder(capacity);
            return QueryFullProcessImageName(process, 0, builder, ref capacity)
                ? builder.ToString()
                : null;
        }
        finally
        {
            CloseHandle(process);
        }
    }

    private static double IntersectionRatio(Rect candidate, Rect target)
    {
        long left = Math.Max(candidate.Left, target.Left);
        long top = Math.Max(candidate.Top, target.Top);
        long right = Math.Min(candidate.Right, target.Right);
        long bottom = Math.Min(candidate.Bottom, target.Bottom);
        long width = Math.Max(0, right - left);
        long height = Math.Max(0, bottom - top);
        long intersection = width * height;
        return target.Area <= 0 ? 0 : intersection / (double)target.Area;
    }

    private static string GetWindowTextValue(IntPtr window)
    {
        int length = GetWindowTextLength(window);
        if (length <= 0) return "";
        var builder = new StringBuilder(Math.Min(length + 1, 4096));
        GetWindowText(window, builder, builder.Capacity);
        return builder.ToString();
    }

    private static string GetClassNameValue(IntPtr window)
    {
        var builder = new StringBuilder(512);
        return GetClassName(window, builder, builder.Capacity) > 0 ? builder.ToString() : "";
    }

    private sealed record OverlayCandidate(
        IntPtr Window,
        int ProcessId,
        Rect Bounds,
        double Overlap,
        long ExtendedStyle,
        bool Layered,
        bool Topmost,
        bool Transparent,
        bool ToolWindow,
        bool NoActivate,
        bool StrongPattern,
        string Title,
        string ClassName);

    [StructLayout(LayoutKind.Sequential)]
    private struct Rect
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
        public long Area => Math.Max(0, Right - Left) * (long)Math.Max(0, Bottom - Top);
    }

    private delegate bool EnumWindowsProc(IntPtr window, IntPtr parameter);

    private const int GwlExStyle = -20;
    private const long WsExTopmost = 0x00000008L;
    private const long WsExTransparent = 0x00000020L;
    private const long WsExToolWindow = 0x00000080L;
    private const long WsExLayered = 0x00080000L;
    private const long WsExNoActivate = 0x08000000L;
    private const int DwmwaCloaked = 14;
    private const uint ProcessQueryLimitedInformation = 0x1000;

    [DllImport("user32.dll")]
    private static extern bool EnumWindows(EnumWindowsProc callback, IntPtr parameter);

    [DllImport("user32.dll")]
    private static extern bool IsWindowVisible(IntPtr window);

    [DllImport("user32.dll")]
    private static extern bool GetWindowRect(IntPtr window, out Rect bounds);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);

    [DllImport("user32.dll", EntryPoint = "GetWindowLongPtrW")]
    private static extern IntPtr GetWindowLongPtr64(IntPtr window, int index);

    [DllImport("user32.dll", EntryPoint = "GetWindowLongW")]
    private static extern IntPtr GetWindowLong32(IntPtr window, int index);

    private static IntPtr GetWindowLongPtr(IntPtr window, int index) =>
        IntPtr.Size == 8 ? GetWindowLongPtr64(window, index) : GetWindowLong32(window, index);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowText(IntPtr window, StringBuilder text, int maximumCount);

    [DllImport("user32.dll")]
    private static extern int GetWindowTextLength(IntPtr window);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetClassName(IntPtr window, StringBuilder className, int maximumCount);

    [DllImport("dwmapi.dll")]
    private static extern int DwmGetWindowAttribute(
        IntPtr window,
        int attribute,
        out int value,
        int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool QueryFullProcessImageName(
        IntPtr process,
        int flags,
        StringBuilder executableName,
        ref int size);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);
}

/// <summary>
/// Collects non-driver Windows services and Task Scheduler executable actions.
/// </summary>
public sealed class ServiceTaskCollector : IScanCollector
{
    public string Name => "Services and scheduled tasks";
    public bool Supports(ScanMode mode) => mode is ScanMode.Full or ScanMode.Forensic;

    public async Task<CollectorOutput> CollectAsync(
        ScanContext context,
        IProgress<ScanProgressUpdate>? progress,
        CancellationToken token)
    {
        DateTime started = DateTime.UtcNow;
        var evidence = new List<EvidenceRecord>();
        int checkedItems = 0;
        bool partial = false;

        progress?.Report(new ScanProgressUpdate
        {
            Percent = 73,
            Module = Name,
            Message = "Reviewing Windows services and scheduled-task actions...",
            ItemsChecked = 0
        });

        try
        {
            using RegistryKey? services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (services is not null)
            {
                foreach (string serviceName in services.GetSubKeyNames())
                {
                    token.ThrowIfCancellationRequested();
                    using RegistryKey? key = services.OpenSubKey(serviceName);
                    if (key is null) continue;

                    int type = key.GetValue("Type") is int typeValue ? typeValue : 0;
                    bool win32Service = (type & 0x10) != 0 || (type & 0x20) != 0;
                    bool driver = (type & 0x01) != 0 || (type & 0x02) != 0;
                    if (!win32Service || driver) continue;

                    checkedItems++;
                    string rawCommand = Convert.ToString(key.GetValue("ImagePath")) ?? "";
                    string? serviceDll = null;
                    using (RegistryKey? parameters = key.OpenSubKey("Parameters"))
                        serviceDll = Convert.ToString(parameters?.GetValue("ServiceDll"));

                    string? path = ResolveExecutablePath(rawCommand);
                    int startValue = key.GetValue("Start") is int start ? start : -1;
                    bool automatic = startValue == 2;
                    bool suspiciousContext = RuleMatcher.IsUserWritable(path) ||
                                             RuleMatcher.ContainsHigh(string.Join(" ", serviceName, rawCommand, serviceDll), context.Rules) ||
                                             RuleMatcher.FindKnownCheatName(string.Join(" ", serviceName, rawCommand, serviceDll), context.Rules) is not null;
                    SignatureResult? signature = null;
                    string? hash = null;
                    if (suspiciousContext && !string.IsNullOrWhiteSpace(path) && File.Exists(path))
                    {
                        signature = SignatureVerifier.Verify(path);
                        hash = await HashService.TrySha256Async(path, token).ConfigureAwait(false);
                    }

                    evidence.Add(new EvidenceRecord
                    {
                        Kind = EvidenceKind.Persistence,
                        Source = Name,
                        Name = serviceName,
                        Path = path ?? rawCommand,
                        HashSha256 = hash,
                        Publisher = signature?.Publisher,
                        IsSignatureValid = signature?.IsValid,
                        Detail = "Registered Windows service metadata.",
                        Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                        {
                            ["RecordType"] = "WindowsService",
                            ["ServiceCommand"] = rawCommand,
                            ["ServiceDll"] = serviceDll ?? "",
                            ["DisplayName"] = Convert.ToString(key.GetValue("DisplayName")) ?? serviceName,
                            ["Description"] = Convert.ToString(key.GetValue("Description")) ?? "",
                            ["ObjectName"] = Convert.ToString(key.GetValue("ObjectName")) ?? "",
                            ["StartValue"] = startValue.ToString(),
                            ["AutomaticStart"] = automatic.ToString(),
                            ["ServiceType"] = type.ToString(),
                            ["UserWritableTarget"] = RuleMatcher.IsUserWritable(path).ToString()
                        }
                    });
                }
            }
        }
        catch
        {
            partial = true;
        }

        try
        {
            int before = evidence.Count;
            checkedItems += await CollectScheduledTasksAsync(context, evidence, token).ConfigureAwait(false);
            if (evidence.Count == before)
            {
                // An empty task list can be valid, but it is uncommon. Keep the module honest.
                partial = true;
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            partial = true;
        }

        return new CollectorOutput
        {
            Module = Name,
            Status = partial ? CoverageStatus.Partial : CoverageStatus.Completed,
            Summary = $"Checked {checkedItems:N0} service/task record(s) and retained {evidence.Count:N0} persistence action(s).",
            Evidence = evidence,
            ItemsChecked = checkedItems,
            Duration = DateTime.UtcNow - started
        };
    }

    private static async Task<int> CollectScheduledTasksAsync(
        ScanContext context,
        List<EvidenceRecord> evidence,
        CancellationToken token)
    {
        Type? schedulerType = Type.GetTypeFromProgID("Schedule.Service");
        if (schedulerType is null) return 0;

        object? service = null;
        object? root = null;
        int checkedItems = 0;
        try
        {
            service = Activator.CreateInstance(schedulerType);
            if (service is null) return 0;
            dynamic scheduler = service;
            scheduler.Connect();
            root = scheduler.GetFolder("\\");
            await WalkFolderAsync(root, context, evidence, token, count => checkedItems += count).ConfigureAwait(false);
            return checkedItems;
        }
        finally
        {
            ReleaseCom(root);
            ReleaseCom(service);
        }
    }

    private static async Task WalkFolderAsync(
        object folderObject,
        ScanContext context,
        List<EvidenceRecord> evidence,
        CancellationToken token,
        Action<int> addChecked)
    {
        dynamic folder = folderObject;
        object? tasksObject = null;
        object? foldersObject = null;
        try
        {
            tasksObject = folder.GetTasks(1);
            dynamic tasks = tasksObject;
            int taskCount = Convert.ToInt32(tasks.Count);
            for (int taskIndex = 1; taskIndex <= taskCount; taskIndex++)
            {
                token.ThrowIfCancellationRequested();
                object? taskObject = null;
                object? definitionObject = null;
                object? actionsObject = null;
                try
                {
                    taskObject = tasks.Item(taskIndex);
                    dynamic task = taskObject;
                    definitionObject = task.Definition;
                    dynamic definition = definitionObject;
                    actionsObject = definition.Actions;
                    dynamic actions = actionsObject;
                    int actionCount = Convert.ToInt32(actions.Count);
                    addChecked(1);

                    for (int actionIndex = 1; actionIndex <= actionCount; actionIndex++)
                    {
                        token.ThrowIfCancellationRequested();
                        object? actionObject = null;
                        try
                        {
                            actionObject = actions.Item(actionIndex);
                            dynamic action = actionObject;
                            int actionType = SafeInt(() => action.Type, -1);
                            if (actionType != 0) continue; // TASK_ACTION_EXEC

                            string command = SafeString(() => action.Path);
                            string arguments = SafeString(() => action.Arguments);
                            string workingDirectory = SafeString(() => action.WorkingDirectory);
                            string taskPath = SafeString(() => task.Path);
                            string taskName = SafeString(() => task.Name);
                            string? path = ResolveExecutablePath(command);
                            string combined = string.Join(" ", taskPath, taskName, command, arguments, workingDirectory);
                            bool suspiciousContext = RuleMatcher.IsUserWritable(path) ||
                                                     RuleMatcher.ContainsHigh(combined, context.Rules) ||
                                                     RuleMatcher.FindKnownCheatName(combined, context.Rules) is not null;
                            SignatureResult? signature = null;
                            string? hash = null;
                            if (suspiciousContext && !string.IsNullOrWhiteSpace(path) && File.Exists(path))
                            {
                                signature = SignatureVerifier.Verify(path);
                                hash = await HashService.TrySha256Async(path, token).ConfigureAwait(false);
                            }

                            evidence.Add(new EvidenceRecord
                            {
                                Kind = EvidenceKind.Persistence,
                                Source = "Task Scheduler",
                                Name = string.IsNullOrWhiteSpace(taskName) ? taskPath : taskName,
                                Path = path ?? command,
                                HashSha256 = hash,
                                Publisher = signature?.Publisher,
                                IsSignatureValid = signature?.IsValid,
                                Detail = "Task Scheduler executable action metadata.",
                                Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                                {
                                    ["RecordType"] = "ScheduledTask",
                                    ["TaskPath"] = taskPath,
                                    ["TaskCommand"] = command,
                                    ["Arguments"] = arguments,
                                    ["WorkingDirectory"] = workingDirectory,
                                    ["Enabled"] = SafeBool(() => task.Enabled, false).ToString(),
                                    ["State"] = SafeString(() => task.State),
                                    ["LastRunTime"] = SafeString(() => task.LastRunTime),
                                    ["NextRunTime"] = SafeString(() => task.NextRunTime),
                                    ["UserWritableTarget"] = RuleMatcher.IsUserWritable(path).ToString()
                                }
                            });
                        }
                        finally
                        {
                            ReleaseCom(actionObject);
                        }
                    }
                }
                finally
                {
                    ReleaseCom(actionsObject);
                    ReleaseCom(definitionObject);
                    ReleaseCom(taskObject);
                }
            }

            foldersObject = folder.GetFolders(0);
            dynamic folders = foldersObject;
            int folderCount = Convert.ToInt32(folders.Count);
            for (int folderIndex = 1; folderIndex <= folderCount; folderIndex++)
            {
                token.ThrowIfCancellationRequested();
                object? child = null;
                try
                {
                    child = folders.Item(folderIndex);
                    await WalkFolderAsync(child, context, evidence, token, addChecked).ConfigureAwait(false);
                }
                finally
                {
                    ReleaseCom(child);
                }
            }
        }
        finally
        {
            ReleaseCom(tasksObject);
            ReleaseCom(foldersObject);
        }
    }

    private static string? ResolveExecutablePath(string? command)
    {
        if (string.IsNullOrWhiteSpace(command)) return null;
        string value = Environment.ExpandEnvironmentVariables(command.Trim());
        if (value.StartsWith(@"\??\", StringComparison.OrdinalIgnoreCase)) value = value[4..];
        if (value.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            value = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), value[12..]);

        if (value.StartsWith('"'))
        {
            int endQuote = value.IndexOf('"', 1);
            if (endQuote > 1) value = value[1..endQuote];
        }
        else
        {
            int bestEnd = -1;
            foreach (string extension in new[] { ".exe", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".dll", ".sys" })
            {
                int index = value.IndexOf(extension, StringComparison.OrdinalIgnoreCase);
                if (index >= 0)
                {
                    int end = index + extension.Length;
                    if (bestEnd < 0 || end < bestEnd) bestEnd = end;
                }
            }
            if (bestEnd > 0) value = value[..bestEnd];
        }

        value = value.Trim().Trim('"');
        if (value.StartsWith("System32\\", StringComparison.OrdinalIgnoreCase))
            value = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), value);
        return value;
    }

    private static string SafeString(Func<object?> getter)
    {
        try { return Convert.ToString(getter()) ?? ""; }
        catch { return ""; }
    }

    private static int SafeInt(Func<object?> getter, int fallback)
    {
        try { return Convert.ToInt32(getter()); }
        catch { return fallback; }
    }

    private static bool SafeBool(Func<object?> getter, bool fallback)
    {
        try { return Convert.ToBoolean(getter()); }
        catch { return fallback; }
    }

    private static void ReleaseCom(object? value)
    {
        if (value is null || !Marshal.IsComObject(value)) return;
        try { Marshal.FinalReleaseComObject(value); }
        catch { }
    }
}

/// <summary>
/// Reviews committed executable regions in cs2.exe without reading region bytes.
/// Private executable regions and thread start addresses outside known images are
/// retained as possible manual-map/injection indicators.
/// </summary>
public sealed class Cs2MemoryMapCollector : IScanCollector
{
    public string Name => "CS2 executable-memory map";
    public bool Supports(ScanMode mode) => mode == ScanMode.Forensic;

    public Task<CollectorOutput> CollectAsync(
        ScanContext context,
        IProgress<ScanProgressUpdate>? progress,
        CancellationToken token)
    {
        DateTime started = DateTime.UtcNow;
        var evidence = new List<EvidenceRecord>();
        int checkedRegions = 0;
        bool partial = false;
        Process[] processes = Process.GetProcessesByName("cs2");

        if (processes.Length == 0)
        {
            return Task.FromResult(new CollectorOutput
            {
                Module = Name,
                Status = CoverageStatus.Partial,
                Summary = "CS2 was not running; executable-memory map inspection was unavailable.",
                Evidence = evidence,
                ItemsChecked = 0,
                Duration = DateTime.UtcNow - started
            });
        }

        progress?.Report(new ScanProgressUpdate
        {
            Percent = 34,
            Module = Name,
            Message = "Reviewing executable private/mapped regions and thread start addresses...",
            ItemsChecked = 0
        });

        foreach (Process process in processes)
        {
            using (process)
            {
                token.ThrowIfCancellationRequested();
                IntPtr handle = OpenProcess(ProcessQueryInformation | ProcessVmRead, false, process.Id);
                if (handle == IntPtr.Zero)
                {
                    partial = true;
                    continue;
                }

                try
                {
                    List<ModuleRange> modules = GetModuleRanges(process, ref partial);
                    List<MemoryRegionSnapshot> suspiciousRegions = EnumerateExecutableRegions(
                        handle,
                        process.Id,
                        modules,
                        token,
                        ref checkedRegions,
                        ref partial);

                    Dictionary<ulong, int> threadStarts = GetThreadStartCounts(process, suspiciousRegions, ref partial);
                    foreach (MemoryRegionSnapshot region in suspiciousRegions.Take(500))
                    {
                        token.ThrowIfCancellationRequested();
                        int starts = threadStarts.GetValueOrDefault(region.BaseAddress);
                        evidence.Add(new EvidenceRecord
                        {
                            Kind = EvidenceKind.MemoryRegion,
                            Source = Name,
                            Name = $"Executable region 0x{region.BaseAddress:X}",
                            Path = region.MappedPath,
                            ProcessId = process.Id,
                            Detail = region.Type == MemPrivate
                                ? "Committed executable private memory region in cs2.exe."
                                : "Committed executable mapped region without a normal image-module classification.",
                            Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                            {
                                ["RecordType"] = region.Type == MemPrivate ? "PrivateExecutableRegion" : "MappedExecutableRegion",
                                ["ProcessName"] = "cs2.exe",
                                ["BaseAddress"] = $"0x{region.BaseAddress:X}",
                                ["RegionSize"] = region.Size.ToString(),
                                ["Protection"] = ProtectionText(region.Protection),
                                ["ProtectionHex"] = $"0x{region.Protection:X8}",
                                ["MemoryType"] = region.Type == MemPrivate ? "MEM_PRIVATE" : "MEM_MAPPED",
                                ["InsideKnownModule"] = region.InsideKnownModule.ToString(),
                                ["MappedPath"] = region.MappedPath ?? "",
                                ["ThreadStartCount"] = starts.ToString(),
                                ["ExecutablePrivateMemory"] = (region.Type == MemPrivate).ToString()
                            }
                        });
                    }

                    if (suspiciousRegions.Count > 500) partial = true;
                }
                finally
                {
                    CloseHandle(handle);
                }
            }
        }

        string summary = evidence.Count == 0
            ? $"Reviewed {checkedRegions:N0} committed memory region(s); no executable private/unbacked region was retained."
            : $"Reviewed {checkedRegions:N0} committed memory region(s) and retained {evidence.Count:N0} executable private/mapped region(s) for correlation.";

        return Task.FromResult(new CollectorOutput
        {
            Module = Name,
            Status = partial ? CoverageStatus.Partial : CoverageStatus.Completed,
            Summary = summary,
            Evidence = evidence,
            ItemsChecked = checkedRegions,
            Duration = DateTime.UtcNow - started
        });
    }

    private static List<ModuleRange> GetModuleRanges(Process process, ref bool partial)
    {
        var result = new List<ModuleRange>();
        try
        {
            foreach (ProcessModule module in process.Modules)
            {
                ulong start = unchecked((ulong)module.BaseAddress.ToInt64());
                result.Add(new ModuleRange(start, start + unchecked((uint)module.ModuleMemorySize)));
            }
        }
        catch
        {
            partial = true;
        }
        return result;
    }

    private static List<MemoryRegionSnapshot> EnumerateExecutableRegions(
        IntPtr process,
        int processId,
        IReadOnlyList<ModuleRange> modules,
        CancellationToken token,
        ref int checkedRegions,
        ref bool partial)
    {
        var output = new List<MemoryRegionSnapshot>();
        GetNativeSystemInfo(out SystemInfo systemInfo);
        ulong address = 0;
        ulong maximum = unchecked((ulong)systemInfo.MaximumApplicationAddress.ToInt64());
        int structureSize = Marshal.SizeOf<MemoryBasicInformation>();

        while (address < maximum)
        {
            token.ThrowIfCancellationRequested();
            UIntPtr queried = VirtualQueryEx(
                process,
                new IntPtr(unchecked((long)address)),
                out MemoryBasicInformation information,
                new UIntPtr(unchecked((uint)structureSize)));
            if (queried == UIntPtr.Zero)
            {
                partial = true;
                break;
            }

            checkedRegions++;
            ulong baseAddress = unchecked((ulong)information.BaseAddress.ToInt64());
            ulong regionSize = information.RegionSize.ToUInt64();
            if (regionSize == 0) break;

            bool committed = information.State == MemCommit;
            bool executable = IsExecutableProtection(information.Protect);
            bool privateOrMapped = information.Type is MemPrivate or MemMapped;
            bool insideModule = modules.Any(module => baseAddress >= module.Start && baseAddress < module.End);

            if (committed && executable && privateOrMapped && !insideModule)
            {
                string? mappedPath = information.Type == MemMapped
                    ? TryGetMappedFileName(process, information.BaseAddress)
                    : null;
                output.Add(new MemoryRegionSnapshot(
                    baseAddress,
                    regionSize,
                    information.Protect,
                    information.Type,
                    insideModule,
                    mappedPath));
            }

            ulong next = baseAddress + regionSize;
            if (next <= address) break;
            address = next;
        }

        return output;
    }

    private static Dictionary<ulong, int> GetThreadStartCounts(
        Process process,
        IReadOnlyList<MemoryRegionSnapshot> regions,
        ref bool partial)
    {
        var starts = new Dictionary<ulong, int>();
        try
        {
            foreach (ProcessThread thread in process.Threads)
            {
                IntPtr threadHandle = OpenThread(ThreadQueryInformation | ThreadQueryLimitedInformation, false, unchecked((uint)thread.Id));
                if (threadHandle == IntPtr.Zero)
                {
                    partial = true;
                    continue;
                }

                try
                {
                    IntPtr startAddress = IntPtr.Zero;
                    int status = NtQueryInformationThread(
                        threadHandle,
                        ThreadQuerySetWin32StartAddress,
                        ref startAddress,
                        IntPtr.Size,
                        IntPtr.Zero);
                    if (status < 0 || startAddress == IntPtr.Zero) continue;
                    ulong value = unchecked((ulong)startAddress.ToInt64());
                    MemoryRegionSnapshot? region = regions.FirstOrDefault(item =>
                        value >= item.BaseAddress && value < item.BaseAddress + item.Size);
                    if (region is null) continue;
                    starts[region.BaseAddress] = starts.GetValueOrDefault(region.BaseAddress) + 1;
                }
                finally
                {
                    CloseHandle(threadHandle);
                }
            }
        }
        catch
        {
            partial = true;
        }

        return starts;
    }

    private static string? TryGetMappedFileName(IntPtr process, IntPtr address)
    {
        var builder = new StringBuilder(32_768);
        int length = GetMappedFileName(process, address, builder, builder.Capacity);
        return length > 0 ? builder.ToString() : null;
    }

    private static bool IsExecutableProtection(uint protection)
    {
        uint baseProtection = protection & 0xFF;
        bool guardedOrNoAccess = (protection & PageGuard) != 0 || baseProtection == PageNoAccess;
        if (guardedOrNoAccess) return false;
        return baseProtection is PageExecute or PageExecuteRead or PageExecuteReadWrite or PageExecuteWriteCopy;
    }

    private static string ProtectionText(uint protection)
    {
        uint baseProtection = protection & 0xFF;
        string text = baseProtection switch
        {
            PageExecute => "PAGE_EXECUTE",
            PageExecuteRead => "PAGE_EXECUTE_READ",
            PageExecuteReadWrite => "PAGE_EXECUTE_READWRITE",
            PageExecuteWriteCopy => "PAGE_EXECUTE_WRITECOPY",
            _ => $"0x{baseProtection:X}"
        };
        if ((protection & PageGuard) != 0) text += " | PAGE_GUARD";
        return text;
    }

    private sealed record ModuleRange(ulong Start, ulong End);
    private sealed record MemoryRegionSnapshot(
        ulong BaseAddress,
        ulong Size,
        uint Protection,
        uint Type,
        bool InsideKnownModule,
        string? MappedPath);

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryBasicInformation
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public UIntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SystemInfo
    {
        public ushort ProcessorArchitecture;
        public ushort Reserved;
        public uint PageSize;
        public IntPtr MinimumApplicationAddress;
        public IntPtr MaximumApplicationAddress;
        public UIntPtr ActiveProcessorMask;
        public uint NumberOfProcessors;
        public uint ProcessorType;
        public uint AllocationGranularity;
        public ushort ProcessorLevel;
        public ushort ProcessorRevision;
    }

    private const uint ProcessVmRead = 0x0010;
    private const uint ProcessQueryInformation = 0x0400;
    private const uint ThreadQueryInformation = 0x0040;
    private const uint ThreadQueryLimitedInformation = 0x0800;
    private const int ThreadQuerySetWin32StartAddress = 9;
    private const uint MemCommit = 0x1000;
    private const uint MemPrivate = 0x20000;
    private const uint MemMapped = 0x40000;
    private const uint PageNoAccess = 0x01;
    private const uint PageExecute = 0x10;
    private const uint PageExecuteRead = 0x20;
    private const uint PageExecuteReadWrite = 0x40;
    private const uint PageExecuteWriteCopy = 0x80;
    private const uint PageGuard = 0x100;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

    [DllImport("kernel32.dll")]
    private static extern UIntPtr VirtualQueryEx(
        IntPtr process,
        IntPtr address,
        out MemoryBasicInformation buffer,
        UIntPtr length);

    [DllImport("kernel32.dll")]
    private static extern void GetNativeSystemInfo(out SystemInfo systemInfo);

    [DllImport("psapi.dll", CharSet = CharSet.Unicode)]
    private static extern int GetMappedFileName(
        IntPtr process,
        IntPtr address,
        StringBuilder fileName,
        int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenThread(uint desiredAccess, bool inheritHandle, uint threadId);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationThread(
        IntPtr threadHandle,
        int threadInformationClass,
        ref IntPtr threadInformation,
        int threadInformationLength,
        IntPtr returnLength);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);
}

/// <summary>
/// Enumerates PCI/USB PnP metadata and retains DMA/FPGA-related aliases as review
/// evidence. Device names can be spoofed; this module never treats hardware name
/// matching alone as a confirmed cheat detection.
/// </summary>
public sealed class DmaDeviceCollector : IScanCollector
{
    public string Name => "PCIe and DMA device review";
    public bool Supports(ScanMode mode) => mode == ScanMode.Forensic;

    private static readonly string[] StrongDmaAliases =
    {
        "pcileech", "leechcore", "screamer", "captain dma", "captain-dma",
        "lambda concept", "raptor dma", "enigma-x1", "enigma x1",
        "usb3380", "dma card", "dma board"
    };

    private static readonly string[] FpgaReviewAliases =
    {
        "xilinx", "altera", "intel fpga", "spartan-6", "spartan 6",
        "artix-7", "artix 7", "kintex", "ft601", "ftd3xx", "fpga"
    };

    public Task<CollectorOutput> CollectAsync(
        ScanContext context,
        IProgress<ScanProgressUpdate>? progress,
        CancellationToken token)
    {
        DateTime started = DateTime.UtcNow;
        var evidence = new List<EvidenceRecord>();
        int checkedDevices = 0;
        bool partial = false;

        progress?.Report(new ScanProgressUpdate
        {
            Percent = 68,
            Module = Name,
            Message = "Reviewing PCI/USB PnP metadata for DMA/FPGA indicators...",
            ItemsChecked = 0
        });

        foreach (string bus in new[] { "PCI", "USB" })
        {
            try
            {
                using RegistryKey? root = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Enum\{bus}");
                if (root is null)
                {
                    partial = true;
                    continue;
                }

                foreach (string deviceId in root.GetSubKeyNames())
                {
                    token.ThrowIfCancellationRequested();
                    using RegistryKey? device = root.OpenSubKey(deviceId);
                    if (device is null) continue;

                    foreach (string instanceId in device.GetSubKeyNames())
                    {
                        token.ThrowIfCancellationRequested();
                        using RegistryKey? instance = device.OpenSubKey(instanceId);
                        if (instance is null) continue;
                        checkedDevices++;

                        string friendlyName = Value(instance, "FriendlyName");
                        string description = Value(instance, "DeviceDesc");
                        string manufacturer = Value(instance, "Mfg");
                        string service = Value(instance, "Service");
                        string className = Value(instance, "Class");
                        string classGuid = Value(instance, "ClassGUID");
                        string location = Value(instance, "LocationInformation");
                        string[] hardwareIds = MultiValue(instance, "HardwareID");
                        string[] compatibleIds = MultiValue(instance, "CompatibleIDs");
                        string combined = string.Join(" ", bus, deviceId, instanceId, friendlyName, description,
                            manufacturer, service, className, classGuid, location,
                            string.Join(" ", hardwareIds), string.Join(" ", compatibleIds));

                        string? strongAlias = StrongDmaAliases.FirstOrDefault(alias =>
                            combined.Contains(alias, StringComparison.OrdinalIgnoreCase));
                        string? fpgaAlias = FpgaReviewAliases.FirstOrDefault(alias =>
                            combined.Contains(alias, StringComparison.OrdinalIgnoreCase));
                        bool strong = strongAlias is not null;
                        bool review = fpgaAlias is not null;
                        if (!strong && !review) continue;

                        evidence.Add(new EvidenceRecord
                        {
                            Kind = EvidenceKind.DmaDevice,
                            Source = Name,
                            Name = FirstNonEmpty(friendlyName, description, deviceId),
                            Path = $@"HKLM\SYSTEM\CurrentControlSet\Enum\{bus}\{deviceId}\{instanceId}",
                            Detail = strong
                                ? "PnP metadata contains a distinctive DMA-tooling/device alias. Hardware identity can be spoofed and requires correlation."
                                : "PnP metadata contains an FPGA-related alias. FPGA hardware has legitimate uses and is review-only evidence.",
                            Metadata = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                            {
                                ["RecordType"] = "PnpDmaDeviceReview",
                                ["Bus"] = bus,
                                ["DeviceId"] = deviceId,
                                ["InstanceId"] = instanceId,
                                ["FriendlyName"] = friendlyName,
                                ["DeviceDescription"] = description,
                                ["Manufacturer"] = manufacturer,
                                ["Service"] = service,
                                ["DeviceClass"] = className,
                                ["ClassGuid"] = classGuid,
                                ["Location"] = location,
                                ["HardwareIds"] = string.Join(" | ", hardwareIds),
                                ["CompatibleIds"] = string.Join(" | ", compatibleIds),
                                ["DmaAliasMatch"] = strong.ToString(),
                                ["DmaAlias"] = strongAlias ?? "",
                                ["FpgaReviewMatch"] = review.ToString(),
                                ["FpgaAlias"] = fpgaAlias ?? "",
                                ["HardwareNameIsNotProof"] = "True"
                            }
                        });
                    }
                }
            }
            catch
            {
                partial = true;
            }
        }

        string summary = evidence.Count == 0
            ? $"Checked {checkedDevices:N0} PCI/USB device instance(s); no configured DMA/FPGA alias was retained."
            : $"Checked {checkedDevices:N0} PCI/USB device instance(s) and retained {evidence.Count:N0} DMA/FPGA review item(s).";

        return Task.FromResult(new CollectorOutput
        {
            Module = Name,
            Status = partial ? CoverageStatus.Partial : CoverageStatus.Completed,
            Summary = summary,
            Evidence = evidence,
            ItemsChecked = checkedDevices,
            Duration = DateTime.UtcNow - started
        });
    }

    private static string Value(RegistryKey key, string name)
    {
        object? value = key.GetValue(name);
        return value switch
        {
            null => "",
            string text => StripResourcePrefix(text),
            string[] values => string.Join(" | ", values),
            _ => Convert.ToString(value) ?? ""
        };
    }

    private static string[] MultiValue(RegistryKey key, string name)
    {
        object? value = key.GetValue(name);
        return value switch
        {
            string[] values => values,
            string text when !string.IsNullOrWhiteSpace(text) => new[] { text },
            _ => Array.Empty<string>()
        };
    }

    private static string StripResourcePrefix(string value)
    {
        int separator = value.LastIndexOf(';');
        return separator >= 0 && separator < value.Length - 1 ? value[(separator + 1)..] : value;
    }

    private static string FirstNonEmpty(params string[] values) =>
        values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? "Unknown device";
}
