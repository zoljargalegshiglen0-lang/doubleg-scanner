using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using DoubleGScanner.Models;
using DoubleGScanner.Services;
using Microsoft.Win32;

namespace DoubleGScanner.Collectors;

/// <summary>
/// Forensic kernel and driver integrity inspection backed by the read-only
/// DoubleGKernel.sys KMDF driver. The driver exposes only bounded module
/// enumeration and never exposes arbitrary memory access or kernel addresses.
/// </summary>
public sealed class KernelIntegrityCollector : IScanCollector
{
    public string Name => "Kernel & driver integrity";
    public bool Supports(ScanMode mode) => mode == ScanMode.Forensic;

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
            Percent = 5,
            Module = Name,
            Message = "Reading kernel security posture and loaded driver metadata...",
            ItemsChecked = 0
        });

        bool seDebugEnabled = TryEnablePrivilege("SeDebugPrivilege");
        DeviceGuardSnapshot deviceGuard =
            await ReadDeviceGuardSnapshotAsync(token);

        evidence.Add(BuildSecurityPostureEvidence(
            seDebugEnabled,
            deviceGuard));
        checkedItems++;

        IReadOnlyDictionary<string, string> registeredPaths =
            ReadRegisteredDriverPaths();

        LoadedDriverResult loadedResult =
            await ReadLoadedDriversAsync(
                context,
                registeredPaths,
                progress,
                token);

        evidence.AddRange(loadedResult.Evidence);
        checkedItems += loadedResult.ItemsChecked;
        partial |= loadedResult.Partial;

        if (context.Mode != ScanMode.Quick)
        {
            int days = context.Mode == ScanMode.Forensic
                ? 180
                : 45;

            int limit = context.Mode == ScanMode.Forensic
                ? 320
                : 160;

            progress?.Report(new ScanProgressUpdate
            {
                Percent = context.Mode == ScanMode.Forensic ? 70 : 58,
                Module = Name,
                Message = "Reading recent Windows Code Integrity driver events...",
                ItemsChecked = checkedItems
            });

            EventQueryResult codeIntegrity =
                await ReadEventLogAsync(
                    "Microsoft-Windows-CodeIntegrity/Operational",
                    BuildTimeQuery(days),
                    limit,
                    TimeSpan.FromSeconds(10),
                    ParseCodeIntegrityEvent,
                    token);

            evidence.AddRange(codeIntegrity.Evidence);
            checkedItems += codeIntegrity.ItemsChecked;
            partial |= codeIntegrity.Partial;

            progress?.Report(new ScanProgressUpdate
            {
                Percent = context.Mode == ScanMode.Forensic ? 72 : 61,
                Module = Name,
                Message = "Reading recent driver-service installation events...",
                ItemsChecked = checkedItems
            });

            EventQueryResult serviceEvents =
                await ReadEventLogAsync(
                    "System",
                    BuildServiceInstallQuery(days),
                    context.Mode == ScanMode.Forensic ? 180 : 80,
                    TimeSpan.FromSeconds(8),
                    ParseDriverServiceEvent,
                    token);

            evidence.AddRange(serviceEvents.Evidence);
            checkedItems += serviceEvents.ItemsChecked;
            partial |= serviceEvents.Partial;
        }

        int loadedDrivers = evidence.Count(item =>
            item.Kind == EvidenceKind.KernelDriver &&
            MetaBool(item, "Loaded"));

        int integrityEvents = evidence.Count(item =>
            item.Kind == EvidenceKind.CodeIntegrity);

        string summary =
            loadedResult.KernelDriverActive
                ? $"DoubleGKernel.sys performed kernel-mode module enumeration; inspected {loadedDrivers:N0} loaded driver record(s) and retained {integrityEvents:N0} relevant Code Integrity / driver-service event(s). No arbitrary memory or kernel addresses were exposed."
                : $"Kernel-level enumeration was not completed: {loadedResult.StatusMessage} User-mode posture and event evidence may still be present.";

        return new CollectorOutput
        {
            Module = Name,
            Status = !loadedResult.KernelDriverActive
                ? CoverageStatus.Unavailable
                : partial
                    ? CoverageStatus.Partial
                    : CoverageStatus.Completed,
            Summary = summary,
            Evidence = evidence,
            ItemsChecked = checkedItems,
            Duration = DateTime.UtcNow - started
        };
    }

    private static EvidenceRecord BuildSecurityPostureEvidence(
        bool seDebugEnabled,
        DeviceGuardSnapshot snapshot)
    {
        string secureBoot = ReadDwordState(
            Registry.LocalMachine,
            @"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
            "UEFISecureBootEnabled");

        string hvciConfigured = ReadDwordState(
            Registry.LocalMachine,
            @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
            "Enabled");

        string hvciLocked = ReadDwordState(
            Registry.LocalMachine,
            @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
            "Locked");

        string vulnerableBlocklist = ReadDwordState(
            Registry.LocalMachine,
            @"SYSTEM\CurrentControlSet\Control\CI\Config",
            "VulnerableDriverBlocklistEnable");

        bool dmaAvailable =
            snapshot.AvailableSecurityProperties.Contains(3);

        bool memoryIntegrityRunning =
            snapshot.SecurityServicesRunning.Contains(2);

        return new EvidenceRecord
        {
            Kind = EvidenceKind.KernelSecurity,
            Source = "Kernel & driver integrity",
            Name = "Windows kernel security posture",
            Detail =
                "Read-only Windows security state. Configuration values do not by themselves prove that a cheat is present.",
            Metadata =
                new Dictionary<string, string>(
                    StringComparer.OrdinalIgnoreCase)
                {
                    ["RecordType"] = "KernelSecurityPosture",
                    ["SecureBoot"] = secureBoot,
                    ["MemoryIntegrityConfigured"] = hvciConfigured,
                    ["MemoryIntegrityLocked"] = hvciLocked,
                    ["MemoryIntegrityRunning"] =
                        snapshot.Available
                            ? memoryIntegrityRunning.ToString()
                            : "Unavailable",
                    ["VirtualizationBasedSecurityStatus"] =
                        snapshot.Available
                            ? VbsStatus(snapshot.VirtualizationBasedSecurityStatus)
                            : "Unavailable",
                    ["CodeIntegrityPolicyStatus"] =
                        snapshot.Available
                            ? CiPolicyStatus(snapshot.CodeIntegrityPolicyEnforcementStatus)
                            : "Unavailable",
                    ["UserModeCodeIntegrityPolicyStatus"] =
                        snapshot.Available
                            ? CiPolicyStatus(snapshot.UsermodeCodeIntegrityPolicyEnforcementStatus)
                            : "Unavailable",
                    ["KernelDmaProtectionAvailable"] =
                        snapshot.Available
                            ? dmaAvailable.ToString()
                            : "Unavailable",
                    ["AvailableSecurityProperties"] =
                        snapshot.Available
                            ? string.Join(
                                ",",
                                snapshot.AvailableSecurityProperties)
                            : "Unavailable",
                    ["SecurityServicesRunning"] =
                        snapshot.Available
                            ? string.Join(
                                ",",
                                snapshot.SecurityServicesRunning)
                            : "Unavailable",
                    ["VulnerableDriverBlocklistConfigured"] =
                        vulnerableBlocklist,
                    ["SeDebugPrivilegeEnabled"] =
                        seDebugEnabled.ToString(),
                    ["CollectionMode"] =
                        "User-mode read-only"
                }
        };
    }

    private static async Task<LoadedDriverResult> ReadLoadedDriversAsync(
        ScanContext context,
        IReadOnlyDictionary<string, string> registeredPaths,
        IProgress<ScanProgressUpdate>? progress,
        CancellationToken token)
    {
        var evidence =
            new List<EvidenceRecord>();

        KernelDriverSnapshot snapshot =
            await KernelDriverClient.ReadAsync(
                token);

        if (!snapshot.Available ||
            snapshot.Version is null)
        {
            evidence.Add(
                new EvidenceRecord
                {
                    Kind =
                        EvidenceKind.KernelSecurity,
                    Source =
                        "DoubleG kernel driver",
                    Name =
                        "Kernel driver unavailable",
                    Detail =
                        snapshot.Status,
                    Metadata =
                        new Dictionary<string, string>(
                            StringComparer.OrdinalIgnoreCase)
                        {
                            ["RecordType"] =
                                "KernelDriverSession",
                            ["KernelDriverActive"] =
                                "False",
                            ["RequiredDriver"] =
                                "DoubleGKernel.sys",
                            ["CollectionMode"] =
                                "Kernel driver unavailable",
                            ["ArbitraryMemoryAccessExposed"] =
                                "False",
                            ["KernelAddressesExposed"] =
                                "False"
                        }
                });

            return new LoadedDriverResult(
                evidence,
                0,
                true,
                false,
                snapshot.Status);
        }

        evidence.Add(
            new EvidenceRecord
            {
                Kind =
                    EvidenceKind.KernelSecurity,
                Source =
                    "DoubleG kernel driver",
                Name =
                    $"DoubleGKernel.sys v{snapshot.Version.DisplayVersion}",
                Detail =
                    snapshot.Status,
                Metadata =
                    new Dictionary<string, string>(
                        StringComparer.OrdinalIgnoreCase)
                    {
                        ["RecordType"] =
                            "KernelDriverSession",
                        ["KernelDriverActive"] =
                            "True",
                        ["ProtocolVersion"] =
                            $"0x{snapshot.Version.ProtocolVersion:X8}",
                        ["DriverVersion"] =
                            snapshot.Version.DisplayVersion,
                        ["Capabilities"] =
                            $"0x{snapshot.Version.Capabilities:X8}",
                        ["MaxRecordsPerCall"] =
                            snapshot.Version.MaxRecordsPerCall.ToString(),
                        ["CollectionMode"] =
                            "DoubleGKernel.sys / AuxKlibQueryModuleInformation",
                        ["ArbitraryMemoryAccessExposed"] =
                            "False",
                        ["KernelAddressesExposed"] =
                            "False"
                    }
            });

        bool partial = false;

        KernelModuleSnapshot[] modules =
            snapshot.Modules
                .Where(item =>
                    !string.IsNullOrWhiteSpace(
                        item.Path))
                .DistinctBy(
                    item =>
                        item.Path,
                    StringComparer.OrdinalIgnoreCase)
                .Take(2_048)
                .ToArray();

        for (int index = 0;
             index < modules.Length;
             index++)
        {
            token.ThrowIfCancellationRequested();

            KernelModuleSnapshot module =
                modules[index];

            string rawPath =
                module.Path;

            string? resolvedPath =
                ResolveKernelPath(
                    rawPath);

            string baseName =
                Path.GetFileName(
                    resolvedPath ?? rawPath);

            if ((string.IsNullOrWhiteSpace(resolvedPath) ||
                 !File.Exists(resolvedPath)) &&
                !string.IsNullOrWhiteSpace(baseName) &&
                registeredPaths.TryGetValue(
                    baseName,
                    out string? registeredPath))
            {
                resolvedPath =
                    registeredPath;
            }

            SignatureResult? signature = null;
            string? hash = null;
            DateTimeOffset? timestamp = null;
            long fileSize = 0;

            if (!string.IsNullOrWhiteSpace(resolvedPath) &&
                File.Exists(resolvedPath))
            {
                signature =
                    SignatureVerifier.Verify(
                        resolvedPath);

                hash =
                    await HashService.TrySha256Async(
                        resolvedPath,
                        token);

                try
                {
                    var fileInfo =
                        new FileInfo(
                            resolvedPath);

                    timestamp =
                        fileInfo.LastWriteTime;

                    fileSize =
                        fileInfo.Length;
                }
                catch
                {
                    partial = true;
                }
            }
            else
            {
                partial = true;
            }

            KnownVulnerableDriverEntry? vulnerableName =
                RuleMatcher.FindKnownVulnerableDriverByName(
                    baseName,
                    resolvedPath,
                    context.Rules);

            KnownVulnerableDriverEntry? vulnerableHash =
                RuleMatcher.FindKnownVulnerableDriverByHash(
                    hash,
                    context.Rules);

            bool systemPath =
                IsWindowsDriverPath(
                    resolvedPath);

            bool userWritable =
                RuleMatcher.IsUserWritable(
                    resolvedPath);

            evidence.Add(
                new EvidenceRecord
                {
                    Kind =
                        EvidenceKind.KernelDriver,
                    Source =
                        "DoubleG kernel driver",
                    Name =
                        string.IsNullOrWhiteSpace(baseName)
                            ? rawPath
                            : baseName,
                    Path =
                        resolvedPath ?? rawPath,
                    HashSha256 =
                        hash,
                    Publisher =
                        signature?.Publisher,
                    IsSignatureValid =
                        signature?.IsValid,
                    Timestamp =
                        timestamp,
                    Detail =
                        signature is null
                            ? "The kernel driver returned a loaded image path; file signature metadata was unavailable in user mode."
                            : signature.Status,
                    Metadata =
                        new Dictionary<string, string>(
                            StringComparer.OrdinalIgnoreCase)
                        {
                            ["RecordType"] =
                                "LoadedKernelDriver",
                            ["Loaded"] =
                                "True",
                            ["RawKernelPath"] =
                                rawPath,
                            ["ResolvedPath"] =
                                resolvedPath ?? "",
                            ["KernelReportedImageSize"] =
                                module.ImageSize.ToString(),
                            ["KernelReportedFlags"] =
                                $"0x{module.Flags:X8}",
                            ["IsSystemDriverPath"] =
                                systemPath.ToString(),
                            ["IsUserWritablePath"] =
                                userWritable.ToString(),
                            ["FileSize"] =
                                fileSize.ToString(),
                            ["FilenameHeuristicMatch"] =
                                (vulnerableName is not null)
                                    .ToString(),
                            ["FilenameHeuristicName"] =
                                vulnerableName?.Name ?? "",
                            ["ExactVulnerableHashMatch"] =
                                (vulnerableHash is not null)
                                    .ToString(),
                            ["ExactVulnerableDriverName"] =
                                vulnerableHash?.Name ?? "",
                            ["SignatureStatus"] =
                                signature?.Status ??
                                "Unavailable",
                            ["CollectionMode"] =
                                "DoubleGKernel.sys / AuxKlibQueryModuleInformation",
                            ["KernelAddressExposed"] =
                                "False"
                        }
                });

            if (index % 12 == 0 ||
                index == modules.Length - 1)
            {
                progress?.Report(
                    new ScanProgressUpdate
                    {
                        Percent = 16,
                        Module =
                            "Kernel & driver integrity",
                        Message =
                            $"Kernel driver validated module {index + 1}/{modules.Length}: {baseName}",
                        ItemsChecked =
                            evidence.Count
                    });
            }
        }

        return new LoadedDriverResult(
            evidence,
            modules.Length,
            partial,
            true,
            snapshot.Status);
    }

    private static async Task<DeviceGuardSnapshot>
        ReadDeviceGuardSnapshotAsync(
            CancellationToken token)
    {
        const string script =
            "$d=Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard " +
            "-ClassName Win32_DeviceGuard -ErrorAction Stop;" +
            "[pscustomobject]@{" +
            "VirtualizationBasedSecurityStatus=[int]$d.VirtualizationBasedSecurityStatus;" +
            "SecurityServicesRunning=@($d.SecurityServicesRunning);" +
            "AvailableSecurityProperties=@($d.AvailableSecurityProperties);" +
            "CodeIntegrityPolicyEnforcementStatus=[int]$d.CodeIntegrityPolicyEnforcementStatus;" +
            "UsermodeCodeIntegrityPolicyEnforcementStatus=[int]$d.UsermodeCodeIntegrityPolicyEnforcementStatus" +
            "}|ConvertTo-Json -Compress -Depth 4";

        CommandResult command =
            await RunCommandAsync(
                "powershell.exe",
                new[]
                {
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    script
                },
                TimeSpan.FromSeconds(7),
                token);

        if (command.TimedOut ||
            command.ExitCode != 0 ||
            string.IsNullOrWhiteSpace(
                command.Output))
        {
            return DeviceGuardSnapshot.Unavailable;
        }

        try
        {
            using JsonDocument document =
                JsonDocument.Parse(
                    command.Output.Trim());

            JsonElement root =
                document.RootElement;

            return new DeviceGuardSnapshot(
                true,
                IntValue(
                    root,
                    "VirtualizationBasedSecurityStatus"),
                IntArray(
                    root,
                    "SecurityServicesRunning"),
                IntArray(
                    root,
                    "AvailableSecurityProperties"),
                IntValue(
                    root,
                    "CodeIntegrityPolicyEnforcementStatus"),
                IntValue(
                    root,
                    "UsermodeCodeIntegrityPolicyEnforcementStatus"));
        }
        catch
        {
            return DeviceGuardSnapshot.Unavailable;
        }
    }

    private static async Task<EventQueryResult> ReadEventLogAsync(
        string logName,
        string query,
        int limit,
        TimeSpan timeout,
        Func<XElement, EvidenceRecord?> parser,
        CancellationToken token)
    {
        CommandResult command =
            await RunCommandAsync(
                "wevtutil.exe",
                new[]
                {
                    "qe",
                    logName,
                    $"/q:{query}",
                    "/f:xml",
                    $"/c:{limit}",
                    "/rd:true"
                },
                timeout,
                token);

        if (command.TimedOut)
        {
            return new EventQueryResult(
                Array.Empty<EvidenceRecord>(),
                0,
                true);
        }

        if (command.ExitCode != 0 ||
            string.IsNullOrWhiteSpace(
                command.Output))
        {
            return new EventQueryResult(
                Array.Empty<EvidenceRecord>(),
                0,
                command.ExitCode != 0);
        }

        try
        {
            XDocument document =
                ParseEventXml(
                    command.Output);

            XElement[] events =
                document
                    .Descendants()
                    .Where(element =>
                        element.Name.LocalName ==
                        "Event")
                    .Take(limit)
                    .ToArray();

            var evidence =
                new List<EvidenceRecord>();

            foreach (XElement eventElement in events)
            {
                token.ThrowIfCancellationRequested();

                EvidenceRecord? item =
                    parser(eventElement);

                if (item is not null)
                    evidence.Add(item);
            }

            return new EventQueryResult(
                evidence,
                events.Length,
                false);
        }
        catch
        {
            return new EventQueryResult(
                Array.Empty<EvidenceRecord>(),
                0,
                true);
        }
    }

    private static EvidenceRecord? ParseCodeIntegrityEvent(
        XElement eventElement)
    {
        EventData data =
            ReadEventData(
                eventElement);

        string combined =
            data.Combined;

        string? driverPath =
            FindDriverPath(
                combined);

        if (string.IsNullOrWhiteSpace(driverPath) &&
            !combined.Contains(
                "driver",
                StringComparison.OrdinalIgnoreCase) &&
            !combined.Contains(
                "kernel",
                StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return new EvidenceRecord
        {
            Kind = EvidenceKind.CodeIntegrity,
            Source = "Windows Code Integrity",
            Name =
                string.IsNullOrWhiteSpace(driverPath)
                    ? $"Code Integrity event {data.EventId}"
                    : Path.GetFileName(driverPath),
            Path = driverPath,
            Timestamp = data.Timestamp,
            Detail =
                Truncate(
                    combined,
                    1600),
            Metadata =
                new Dictionary<string, string>(
                    StringComparer.OrdinalIgnoreCase)
                {
                    ["RecordType"] =
                        "CodeIntegrityEvent",
                    ["EventId"] =
                        data.EventId.ToString(),
                    ["Level"] =
                        data.Level.ToString(),
                    ["Provider"] =
                        data.Provider,
                    ["OperationalErrorEvent"] =
                        "True",
                    ["DriverPath"] =
                        driverPath ?? "",
                    ["EventData"] =
                        Truncate(
                            combined,
                            3000)
                }
        };
    }

    private static EvidenceRecord? ParseDriverServiceEvent(
        XElement eventElement)
    {
        EventData data =
            ReadEventData(
                eventElement);

        if (data.EventId != 7045)
            return null;

        string imagePath =
            data.Values
                .FirstOrDefault(value =>
                    value.Contains(
                        ".sys",
                        StringComparison.OrdinalIgnoreCase)) ??
            "";

        string combined =
            data.Combined;

        bool driverLike =
            !string.IsNullOrWhiteSpace(imagePath) ||
            combined.Contains(
                "kernel mode driver",
                StringComparison.OrdinalIgnoreCase) ||
            combined.Contains(
                "file system driver",
                StringComparison.OrdinalIgnoreCase);

        if (!driverLike)
            return null;

        string resolvedPath =
            ResolveServiceImagePath(
                imagePath) ??
            imagePath;

        return new EvidenceRecord
        {
            Kind = EvidenceKind.CodeIntegrity,
            Source =
                "Service Control Manager",
            Name =
                data.Values.FirstOrDefault() ??
                "Driver service installed",
            Path =
                resolvedPath,
            Timestamp =
                data.Timestamp,
            Detail =
                "Windows recorded installation of a driver-like service.",
            Metadata =
                new Dictionary<string, string>(
                    StringComparer.OrdinalIgnoreCase)
                {
                    ["RecordType"] =
                        "DriverServiceInstallEvent",
                    ["EventId"] =
                        data.EventId.ToString(),
                    ["Provider"] =
                        data.Provider,
                    ["ImagePath"] =
                        imagePath,
                    ["ResolvedPath"] =
                        resolvedPath,
                    ["EventData"] =
                        Truncate(
                            combined,
                            3000)
                }
        };
    }

    private static EventData ReadEventData(
        XElement eventElement)
    {
        XElement? system =
            eventElement
                .Elements()
                .FirstOrDefault(element =>
                    element.Name.LocalName ==
                    "System");

        int eventId =
            ParseInt(
                system?
                    .Elements()
                    .FirstOrDefault(element =>
                        element.Name.LocalName ==
                        "EventID")
                    ?.Value);

        int level =
            ParseInt(
                system?
                    .Elements()
                    .FirstOrDefault(element =>
                        element.Name.LocalName ==
                        "Level")
                    ?.Value);

        string provider =
            system?
                .Elements()
                .FirstOrDefault(element =>
                    element.Name.LocalName ==
                    "Provider")
                ?.Attributes()
                .FirstOrDefault(attribute =>
                    attribute.Name.LocalName ==
                    "Name")
                ?.Value ??
            "";

        DateTimeOffset? timestamp =
            ParseTimestamp(
                system?
                    .Elements()
                    .FirstOrDefault(element =>
                        element.Name.LocalName ==
                        "TimeCreated")
                    ?.Attributes()
                    .FirstOrDefault(attribute =>
                        attribute.Name.LocalName ==
                        "SystemTime")
                    ?.Value);

        string[] values =
            eventElement
                .Descendants()
                .Where(element =>
                    element.Name.LocalName ==
                    "Data")
                .Select(element =>
                    element.Value.Trim())
                .Where(value =>
                    !string.IsNullOrWhiteSpace(
                        value))
                .ToArray();

        if (values.Length == 0)
        {
            values =
                eventElement
                    .Descendants()
                    .Where(element =>
                        !element.HasElements &&
                        element.Name.LocalName is not
                            ("EventID" or
                             "Level" or
                             "Task" or
                             "Opcode" or
                             "Keywords" or
                             "EventRecordID" or
                             "Channel" or
                             "Computer"))
                    .Select(element =>
                        element.Value.Trim())
                    .Where(value =>
                        !string.IsNullOrWhiteSpace(
                            value))
                    .Distinct(
                        StringComparer.OrdinalIgnoreCase)
                    .ToArray();
        }

        return new EventData(
            eventId,
            level,
            provider,
            timestamp,
            values,
            string.Join(
                " | ",
                values));
    }

    private static XDocument ParseEventXml(
        string output)
    {
        string text =
            output
                .Trim()
                .TrimStart('\uFEFF');

        text = Regex.Replace(
            text,
            @"<\?xml[^>]*\?>",
            "",
            RegexOptions.IgnoreCase);

        if (!text.StartsWith(
                "<Events",
                StringComparison.OrdinalIgnoreCase))
        {
            text =
                "<Events>" +
                text +
                "</Events>";
        }

        return XDocument.Parse(
            text,
            LoadOptions.None);
    }

    private static async Task<CommandResult> RunCommandAsync(
        string fileName,
        IEnumerable<string> arguments,
        TimeSpan timeout,
        CancellationToken token)
    {
        var startInfo =
            new ProcessStartInfo
            {
                FileName = fileName,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

        foreach (string argument in arguments)
            startInfo.ArgumentList.Add(
                argument);

        using var process =
            new Process
            {
                StartInfo = startInfo,
                EnableRaisingEvents = true
            };

        var output =
            new StringBuilder();

        object sync =
            new();

        process.OutputDataReceived +=
            (_, args) =>
            {
                if (args.Data is null)
                    return;

                lock (sync)
                    output.AppendLine(
                        args.Data);
            };

        process.ErrorDataReceived +=
            (_, args) =>
            {
                if (args.Data is null)
                    return;

                lock (sync)
                    output.AppendLine(
                        args.Data);
            };

        try
        {
            if (!process.Start())
            {
                return new CommandResult(
                    -1,
                    "",
                    false);
            }

            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            DateTime started =
                DateTime.UtcNow;

            while (!process.HasExited)
            {
                token.ThrowIfCancellationRequested();

                if (DateTime.UtcNow - started >=
                    timeout)
                {
                    StopProcessTree(
                        process);

                    return new CommandResult(
                        -1,
                        ReadOutput(
                            output,
                            sync),
                        true);
                }

                await Task.Delay(
                    150,
                    token);
            }

            try
            {
                process.WaitForExit(
                    1500);
            }
            catch
            {
            }

            return new CommandResult(
                process.ExitCode,
                ReadOutput(
                    output,
                    sync),
                false);
        }
        catch (OperationCanceledException)
        {
            StopProcessTree(
                process);
            throw;
        }
        catch
        {
            StopProcessTree(
                process);

            return new CommandResult(
                -1,
                ReadOutput(
                    output,
                    sync),
                false);
        }
    }

    private static string ReadOutput(
        StringBuilder output,
        object sync)
    {
        lock (sync)
            return output.ToString();
    }

    private static void StopProcessTree(
        Process process)
    {
        try
        {
            if (!process.HasExited)
                process.Kill(
                    entireProcessTree: true);
        }
        catch
        {
        }
    }

    private static IReadOnlyDictionary<string, string>
        ReadRegisteredDriverPaths()
    {
        var result =
            new Dictionary<string, string>(
                StringComparer.OrdinalIgnoreCase);

        try
        {
            using RegistryKey? services =
                Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services");

            if (services is null)
                return result;

            foreach (string serviceName in
                     services.GetSubKeyNames())
            {
                using RegistryKey? service =
                    services.OpenSubKey(
                        serviceName);

                if (service is null)
                    continue;

                int type =
                    service.GetValue("Type") is int value
                        ? value
                        : 0;

                if ((type & 1) == 0 &&
                    (type & 2) == 0)
                    continue;

                string raw =
                    Convert.ToString(
                        service.GetValue(
                            "ImagePath")) ??
                    "";

                string? resolved =
                    ResolveServiceImagePath(
                        raw);

                if (string.IsNullOrWhiteSpace(
                        resolved))
                    continue;

                string fileName =
                    Path.GetFileName(
                        resolved);

                if (!string.IsNullOrWhiteSpace(
                        fileName))
                {
                    result[fileName] =
                        resolved;
                }

                result[serviceName] =
                    resolved;
            }
        }
        catch
        {
        }

        return result;
    }

    private static string? ResolveKernelPath(
        string rawPath)
    {
        if (string.IsNullOrWhiteSpace(
                rawPath))
            return null;

        string value =
            Environment.ExpandEnvironmentVariables(
                rawPath
                    .Trim()
                    .Trim('"'));

        string windows =
            Environment.GetFolderPath(
                Environment.SpecialFolder.Windows);

        if (value.StartsWith(
                @"\SystemRoot\",
                StringComparison.OrdinalIgnoreCase))
        {
            return Path.Combine(
                windows,
                value[
                    @"\SystemRoot\".Length..]);
        }

        if (value.StartsWith(
                @"System32\",
                StringComparison.OrdinalIgnoreCase))
        {
            return Path.Combine(
                windows,
                value);
        }

        if (value.StartsWith(
                @"\??\",
                StringComparison.OrdinalIgnoreCase))
        {
            value =
                value[4..];
        }

        if (Path.IsPathRooted(
                value) &&
            !value.StartsWith(
                @"\Device\",
                StringComparison.OrdinalIgnoreCase))
        {
            return TrimDriverArguments(
                value);
        }

        if (value.StartsWith(
                @"\Device\",
                StringComparison.OrdinalIgnoreCase))
        {
            foreach (DriveInfo drive in
                     DriveInfo.GetDrives())
            {
                string root =
                    drive.Name.TrimEnd('\\');

                var device =
                    new StringBuilder(
                        2048);

                if (QueryDosDeviceW(
                        root,
                        device,
                        device.Capacity) == 0)
                    continue;

                string devicePath =
                    device.ToString();

                if (!value.StartsWith(
                        devicePath,
                        StringComparison.OrdinalIgnoreCase))
                    continue;

                return TrimDriverArguments(
                    root +
                    value[devicePath.Length..]);
            }
        }

        return TrimDriverArguments(
            value);
    }

    private static string? ResolveServiceImagePath(
        string rawPath)
    {
        if (string.IsNullOrWhiteSpace(
                rawPath))
            return null;

        string value =
            Environment.ExpandEnvironmentVariables(
                rawPath
                    .Trim()
                    .Trim('"'));

        int sysIndex =
            value.IndexOf(
                ".sys",
                StringComparison.OrdinalIgnoreCase);

        if (sysIndex >= 0)
        {
            value =
                value[..(
                    sysIndex + 4)];
        }

        if (value.StartsWith(
                @"\??\",
                StringComparison.OrdinalIgnoreCase))
        {
            value =
                value[4..];
        }

        if (value.StartsWith(
                @"\SystemRoot\",
                StringComparison.OrdinalIgnoreCase))
        {
            return Path.Combine(
                Environment.GetFolderPath(
                    Environment.SpecialFolder.Windows),
                value[
                    @"\SystemRoot\".Length..]);
        }

        if (value.StartsWith(
                @"System32\",
                StringComparison.OrdinalIgnoreCase))
        {
            return Path.Combine(
                Environment.GetFolderPath(
                    Environment.SpecialFolder.Windows),
                value);
        }

        return ResolveKernelPath(
            value);
    }

    private static string TrimDriverArguments(
        string value)
    {
        int sysIndex =
            value.IndexOf(
                ".sys",
                StringComparison.OrdinalIgnoreCase);

        return sysIndex >= 0
            ? value[..(
                sysIndex + 4)]
            : value;
    }

    private static bool IsWindowsDriverPath(
        string? path)
    {
        if (string.IsNullOrWhiteSpace(
                path))
            return false;

        try
        {
            string full =
                Path.GetFullPath(
                    path);

            string windows =
                Path.GetFullPath(
                    Environment.GetFolderPath(
                        Environment.SpecialFolder.Windows));

            return full.StartsWith(
                windows,
                StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static string? FindDriverPath(
        string combined)
    {
        if (string.IsNullOrWhiteSpace(
                combined))
            return null;

        Match match =
            Regex.Match(
                combined,
                @"(?i)(?<path>(?:[A-Z]:\\|\\SystemRoot\\|\\\?\?\\|\\Device\\)[^|""\r\n]*?\.sys)");

        if (!match.Success)
            return null;

        return ResolveServiceImagePath(
            match.Groups["path"].Value) ??
            match.Groups["path"].Value;
    }

    private static string BuildTimeQuery(
        int days)
    {
        long milliseconds =
            (long)TimeSpan
                .FromDays(days)
                .TotalMilliseconds;

        return
            $"*[System[TimeCreated[timediff(@SystemTime) <= {milliseconds}]]]";
    }

    private static string BuildServiceInstallQuery(
        int days)
    {
        long milliseconds =
            (long)TimeSpan
                .FromDays(days)
                .TotalMilliseconds;

        return
            $"*[System[(EventID=7045) and TimeCreated[timediff(@SystemTime) <= {milliseconds}]]]";
    }

    private static string ReadDwordState(
        RegistryKey root,
        string path,
        string name)
    {
        try
        {
            using RegistryKey? key =
                root.OpenSubKey(
                    path);

            object? value =
                key?.GetValue(
                    name);

            return value switch
            {
                int number when number == 1 =>
                    "Enabled",
                int number when number == 0 =>
                    "Disabled",
                long number when number == 1 =>
                    "Enabled",
                long number when number == 0 =>
                    "Disabled",
                null =>
                    "Not explicitly configured",
                _ =>
                    Convert.ToString(
                        value) ??
                    "Unavailable"
            };
        }
        catch
        {
            return "Unavailable";
        }
    }

    private static bool TryEnablePrivilege(
        string privilegeName)
    {
        IntPtr tokenHandle =
            IntPtr.Zero;

        try
        {
            using Process process =
                Process.GetCurrentProcess();

            if (!OpenProcessToken(
                    process.Handle,
                    TokenAdjustPrivileges |
                    TokenQuery,
                    out tokenHandle))
            {
                return false;
            }

            if (!LookupPrivilegeValueW(
                    null,
                    privilegeName,
                    out Luid luid))
            {
                return false;
            }

            var privileges =
                new TokenPrivileges
                {
                    PrivilegeCount = 1,
                    Privileges =
                        new LuidAndAttributes
                        {
                            Luid = luid,
                            Attributes =
                                SePrivilegeEnabled
                        }
                };

            Marshal.SetLastPInvokeError(
                0);

            bool adjusted =
                AdjustTokenPrivileges(
                    tokenHandle,
                    false,
                    ref privileges,
                    0,
                    IntPtr.Zero,
                    IntPtr.Zero);

            return adjusted &&
                   Marshal.GetLastPInvokeError() == 0;
        }
        catch
        {
            return false;
        }
        finally
        {
            if (tokenHandle != IntPtr.Zero)
                CloseHandle(
                    tokenHandle);
        }
    }

    private static int[] IntArray(
        JsonElement root,
        string property)
    {
        if (!root.TryGetProperty(
                property,
                out JsonElement value))
        {
            return Array.Empty<int>();
        }

        if (value.ValueKind ==
            JsonValueKind.Array)
        {
            return value
                .EnumerateArray()
                .Where(item =>
                    item.TryGetInt32(
                        out _))
                .Select(item =>
                    item.GetInt32())
                .ToArray();
        }

        return value.TryGetInt32(
            out int single)
            ? new[] { single }
            : Array.Empty<int>();
    }

    private static int IntValue(
        JsonElement root,
        string property)
    {
        return root.TryGetProperty(
                   property,
                   out JsonElement value) &&
               value.TryGetInt32(
                   out int result)
            ? result
            : -1;
    }

    private static int ParseInt(
        string? value)
    {
        return int.TryParse(
            value,
            out int result)
            ? result
            : 0;
    }

    private static DateTimeOffset? ParseTimestamp(
        string? value)
    {
        return DateTimeOffset.TryParse(
            value,
            out DateTimeOffset result)
            ? result
            : null;
    }

    private static string VbsStatus(
        int value) =>
        value switch
        {
            0 => "Off",
            1 => "Enabled but not running",
            2 => "Enabled and running",
            _ => "Unknown"
        };

    private static string CiPolicyStatus(
        int value) =>
        value switch
        {
            0 => "Off",
            1 => "Audit",
            2 => "Enforced",
            _ => "Unknown"
        };

    private static string Truncate(
        string value,
        int length)
    {
        return value.Length <= length
            ? value
            : value[..length] + "...";
    }

    private static bool MetaBool(
        EvidenceRecord item,
        string key)
    {
        return item.Metadata.TryGetValue(
                   key,
                   out string? value) &&
               bool.TryParse(
                   value,
                   out bool parsed) &&
               parsed;
    }

    private const uint TokenAdjustPrivileges =
        0x0020;

    private const uint TokenQuery =
        0x0008;

    private const uint SePrivilegeEnabled =
        0x00000002;


    [DllImport(
        "kernel32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern uint QueryDosDeviceW(
        string deviceName,
        StringBuilder targetPath,
        int max);

    [DllImport(
        "advapi32.dll",
        SetLastError = true)]
    private static extern bool OpenProcessToken(
        IntPtr processHandle,
        uint desiredAccess,
        out IntPtr tokenHandle);

    [DllImport(
        "advapi32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern bool LookupPrivilegeValueW(
        string? systemName,
        string name,
        out Luid luid);

    [DllImport(
        "advapi32.dll",
        SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(
        IntPtr tokenHandle,
        bool disableAllPrivileges,
        ref TokenPrivileges newState,
        int bufferLength,
        IntPtr previousState,
        IntPtr returnLength);

    [DllImport(
        "kernel32.dll",
        SetLastError = true)]
    private static extern bool CloseHandle(
        IntPtr handle);


    [StructLayout(
        LayoutKind.Sequential)]
    private struct Luid
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(
        LayoutKind.Sequential)]
    private struct LuidAndAttributes
    {
        public Luid Luid;
        public uint Attributes;
    }

    [StructLayout(
        LayoutKind.Sequential)]
    private struct TokenPrivileges
    {
        public uint PrivilegeCount;
        public LuidAndAttributes Privileges;
    }

    private sealed record LoadedDriverResult(
        IReadOnlyList<EvidenceRecord> Evidence,
        int ItemsChecked,
        bool Partial,
        bool KernelDriverActive,
        string StatusMessage);

    private sealed record DeviceGuardSnapshot(
        bool Available,
        int VirtualizationBasedSecurityStatus,
        int[] SecurityServicesRunning,
        int[] AvailableSecurityProperties,
        int CodeIntegrityPolicyEnforcementStatus,
        int UsermodeCodeIntegrityPolicyEnforcementStatus)
    {
        public static DeviceGuardSnapshot Unavailable { get; } =
            new(
                false,
                -1,
                Array.Empty<int>(),
                Array.Empty<int>(),
                -1,
                -1);
    }

    private sealed record CommandResult(
        int ExitCode,
        string Output,
        bool TimedOut);

    private sealed record EventQueryResult(
        IReadOnlyList<EvidenceRecord> Evidence,
        int ItemsChecked,
        bool Partial);

    private sealed record EventData(
        int EventId,
        int Level,
        string Provider,
        DateTimeOffset? Timestamp,
        IReadOnlyList<string> Values,
        string Combined);
}
