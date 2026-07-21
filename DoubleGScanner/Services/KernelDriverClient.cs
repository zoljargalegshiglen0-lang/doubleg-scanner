using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace DoubleGScanner.Services;

public sealed record KernelModuleSnapshot(
    string Path,
    uint ImageSize,
    uint Flags);

public sealed record KernelDriverVersionSnapshot(
    uint ProtocolVersion,
    uint Major,
    uint Minor,
    uint Patch,
    uint Capabilities,
    uint MaxRecordsPerCall)
{
    public string DisplayVersion =>
        $"{Major}.{Minor}.{Patch}";
}

public sealed record KernelDriverSnapshot(
    bool Available,
    string Status,
    KernelDriverVersionSnapshot? Version,
    IReadOnlyList<KernelModuleSnapshot> Modules);

public static class KernelDriverClient
{
    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint OpenExisting = 3;
    private const uint FileAttributeNormal = 0x00000080;

    private const uint FileDeviceUnknown = 0x00000022;
    private const uint MethodBuffered = 0;
    private const uint FileReadAccess = 0x00000001;

    private const uint ProtocolVersion = 0x00020000;
    private const int VersionSize = 32;
    private const int EnumRequestSize = 16;
    private const int EnumHeaderSize = 24;
    private const int ModulePathSize = 256;
    private const int ModuleRecordSize = 272;
    private const int OutputBufferSize = 64 * 1024;

    private static readonly uint IoctlGetVersion =
        CtlCode(
            FileDeviceUnknown,
            0x800,
            MethodBuffered,
            FileReadAccess);

    private static readonly uint IoctlEnumModules =
        CtlCode(
            FileDeviceUnknown,
            0x801,
            MethodBuffered,
            FileReadAccess);

    public static async Task<KernelDriverSnapshot> ReadAsync(
        CancellationToken token)
    {
        return await Task.Run(
            () => Read(token),
            token);
    }

    private static KernelDriverSnapshot Read(
        CancellationToken token)
    {
        token.ThrowIfCancellationRequested();

        using SafeFileHandle? handle =
            OpenDevice();

        if (handle is null ||
            handle.IsInvalid)
        {
            TryStartInstalledService();

            handle?.Dispose();

            using SafeFileHandle? retry =
                OpenDevice();

            if (retry is null ||
                retry.IsInvalid)
            {
                int error =
                    Marshal.GetLastWin32Error();

                return new KernelDriverSnapshot(
                    false,
                    error == 2
                        ? "DoubleGKernel.sys is not installed or its service is not running."
                        : $"DoubleGKernel.sys could not be opened: {new Win32Exception(error).Message}",
                    null,
                    Array.Empty<KernelModuleSnapshot>());
            }

            return ReadFromHandle(
                retry,
                token);
        }

        return ReadFromHandle(
            handle,
            token);
    }

    private static KernelDriverSnapshot ReadFromHandle(
        SafeFileHandle handle,
        CancellationToken token)
    {
        byte[] versionBuffer =
            new byte[VersionSize];

        if (!DeviceIoControl(
                handle,
                IoctlGetVersion,
                null,
                0,
                versionBuffer,
                versionBuffer.Length,
                out int versionBytes,
                IntPtr.Zero))
        {
            int error =
                Marshal.GetLastWin32Error();

            return new KernelDriverSnapshot(
                false,
                $"Kernel-driver version query failed: {new Win32Exception(error).Message}",
                null,
                Array.Empty<KernelModuleSnapshot>());
        }

        if (versionBytes < VersionSize)
        {
            return new KernelDriverSnapshot(
                false,
                "Kernel-driver version response was shorter than expected.",
                null,
                Array.Empty<KernelModuleSnapshot>());
        }

        uint structSize =
            ReadUInt32(
                versionBuffer,
                0);

        uint protocol =
            ReadUInt32(
                versionBuffer,
                4);

        if (structSize != VersionSize ||
            protocol != ProtocolVersion)
        {
            return new KernelDriverSnapshot(
                false,
                $"Kernel-driver protocol mismatch. Expected 0x{ProtocolVersion:X8}, received 0x{protocol:X8}.",
                null,
                Array.Empty<KernelModuleSnapshot>());
        }

        var version =
            new KernelDriverVersionSnapshot(
                protocol,
                ReadUInt32(versionBuffer, 8),
                ReadUInt32(versionBuffer, 12),
                ReadUInt32(versionBuffer, 16),
                ReadUInt32(versionBuffer, 20),
                ReadUInt32(versionBuffer, 24));

        var modules =
            new List<KernelModuleSnapshot>();

        uint startIndex = 0;
        uint totalModules = uint.MaxValue;
        int pageCount = 0;

        while (
            startIndex < totalModules &&
            pageCount < 32)
        {
            token.ThrowIfCancellationRequested();
            pageCount++;

            byte[] input =
                new byte[EnumRequestSize];

            WriteUInt32(
                input,
                0,
                (uint)EnumRequestSize);

            WriteUInt32(
                input,
                4,
                startIndex);

            WriteUInt32(
                input,
                8,
                Math.Clamp(
                    version.MaxRecordsPerCall,
                    1u,
                    224u));

            byte[] output =
                new byte[OutputBufferSize];

            if (!DeviceIoControl(
                    handle,
                    IoctlEnumModules,
                    input,
                    input.Length,
                    output,
                    output.Length,
                    out int bytesReturned,
                    IntPtr.Zero))
            {
                int error =
                    Marshal.GetLastWin32Error();

                return new KernelDriverSnapshot(
                    false,
                    $"Loaded-module query failed: {new Win32Exception(error).Message}",
                    version,
                    modules);
            }

            if (bytesReturned < EnumHeaderSize)
            {
                return new KernelDriverSnapshot(
                    false,
                    "Loaded-module response was shorter than expected.",
                    version,
                    modules);
            }

            uint headerSize =
                ReadUInt32(
                    output,
                    0);

            uint responseProtocol =
                ReadUInt32(
                    output,
                    4);

            totalModules =
                ReadUInt32(
                    output,
                    8);

            uint returnedModules =
                ReadUInt32(
                    output,
                    12);

            uint nextIndex =
                ReadUInt32(
                    output,
                    16);

            uint recordSize =
                ReadUInt32(
                    output,
                    20);

            if (headerSize != EnumHeaderSize ||
                responseProtocol != ProtocolVersion ||
                recordSize < ModuleRecordSize)
            {
                return new KernelDriverSnapshot(
                    false,
                    "Loaded-module response failed protocol validation.",
                    version,
                    modules);
            }

            ulong required =
                (ulong)EnumHeaderSize +
                ((ulong)returnedModules *
                 recordSize);

            if (required >
                (ulong)bytesReturned)
            {
                return new KernelDriverSnapshot(
                    false,
                    "Loaded-module response length was inconsistent.",
                    version,
                    modules);
            }

            for (uint index = 0;
                 index < returnedModules;
                 index++)
            {
                int offset =
                    checked(
                        EnumHeaderSize +
                        (int)(index *
                            recordSize));

                uint itemStructSize =
                    ReadUInt32(
                        output,
                        offset);

                if (itemStructSize <
                    ModuleRecordSize)
                    continue;

                uint imageSize =
                    ReadUInt32(
                        output,
                        offset + 4);

                uint flags =
                    ReadUInt32(
                        output,
                        offset + 8);

                uint pathLength =
                    Math.Min(
                        ReadUInt32(
                            output,
                            offset + 12),
                        ModulePathSize - 1);

                string path =
                    pathLength == 0
                        ? ""
                        : Encoding.Latin1.GetString(
                            output,
                            offset + 16,
                            checked((int)pathLength));

                path =
                    path.TrimEnd('\0');

                if (!string.IsNullOrWhiteSpace(
                        path))
                {
                    modules.Add(
                        new KernelModuleSnapshot(
                            path,
                            imageSize,
                            flags));
                }
            }

            if (returnedModules == 0 ||
                nextIndex <= startIndex)
                break;

            startIndex =
                nextIndex;
        }

        if (modules.Count == 0)
        {
            return new KernelDriverSnapshot(
                false,
                "DoubleGKernel.sys responded but returned no loaded modules.",
                version,
                modules);
        }

        return new KernelDriverSnapshot(
            true,
            $"DoubleGKernel.sys v{version.DisplayVersion} returned {modules.Count:N0} loaded module record(s).",
            version,
            modules);
    }

    private static SafeFileHandle? OpenDevice()
    {
        SafeFileHandle handle =
            CreateFileW(
                @"\\.\DoubleGKernel",
                GenericRead,
                FileShareRead |
                FileShareWrite,
                IntPtr.Zero,
                OpenExisting,
                FileAttributeNormal,
                IntPtr.Zero);

        return handle;
    }

    private static void TryStartInstalledService()
    {
        try
        {
            using Process? process =
                Process.Start(
                    new ProcessStartInfo
                    {
                        FileName = "sc.exe",
                        Arguments =
                            "start DoubleGKernel",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true
                    });

            process?.WaitForExit(5000);
        }
        catch
        {
            // Opening the device after this best-effort start attempt
            // determines the final availability state.
        }
    }

    private static uint CtlCode(
        uint deviceType,
        uint function,
        uint method,
        uint access)
    {
        return
            (deviceType << 16) |
            (access << 14) |
            (function << 2) |
            method;
    }

    private static uint ReadUInt32(
        byte[] buffer,
        int offset)
    {
        return BinaryPrimitives.ReadUInt32LittleEndian(
            buffer.AsSpan(
                offset,
                sizeof(uint)));
    }

    private static void WriteUInt32(
        byte[] buffer,
        int offset,
        uint value)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(
            buffer.AsSpan(
                offset,
                sizeof(uint)),
            value);
    }

    [DllImport(
        "kernel32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport(
        "kernel32.dll",
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeviceIoControl(
        SafeFileHandle device,
        uint ioControlCode,
        byte[]? inputBuffer,
        int inputBufferSize,
        byte[] outputBuffer,
        int outputBufferSize,
        out int bytesReturned,
        IntPtr overlapped);
}
