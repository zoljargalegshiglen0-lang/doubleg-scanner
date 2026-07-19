using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using DoubleGScanner.Models;

namespace DoubleGScanner.Services;

public sealed record SignatureResult(bool IsSigned, bool IsValid, string? Publisher, string Status);

public static class HashService
{
    public static async Task<string?> TrySha256Async(string path, CancellationToken token)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length > 512L * 1024 * 1024) return null;
            await using FileStream stream = new(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete, 1024 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            byte[] hash = await SHA256.HashDataAsync(stream, token);
            return Convert.ToHexString(hash);
        }
        catch { return null; }
    }
    public static string? TrySha256(string path)
    {
        try
        {
            using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return Convert.ToHexString(SHA256.HashData(stream));
        }
        catch { return null; }
    }
}

public static class SignatureVerifier
{
    private static readonly Guid Action = new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");
    public static SignatureResult Verify(string filePath)
    {
        if (!File.Exists(filePath)) return new(false, false, null, "File unavailable");
        string? publisher = null; bool signed = false;
        try
        {
            using X509Certificate cert = X509Certificate.CreateFromSignedFile(filePath);
            using var cert2 = new X509Certificate2(cert);
            publisher = cert2.GetNameInfo(X509NameType.SimpleName, false);
            signed = true;
        }
        catch { }

        IntPtr fiPtr = IntPtr.Zero, dataPtr = IntPtr.Zero;
        try
        {
            var fi = new WinTrustFileInfo(filePath);
            fiPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
            Marshal.StructureToPtr(fi, fiPtr, false);
            var data = new WinTrustData(fiPtr);
            dataPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustData>());
            Marshal.StructureToPtr(data, dataPtr, false);
            uint result = WinVerifyTrust(IntPtr.Zero, Action, dataPtr);
            bool valid = result == 0;
            return new(signed, valid, publisher,
                valid ? "Valid Authenticode signature" : signed ? $"Invalid signature (0x{result:X8})" : "Unsigned");
        }
        catch (Exception ex) { return new(signed, false, publisher, "Signature check unavailable: " + ex.GetType().Name); }
        finally
        {
            if (dataPtr != IntPtr.Zero) { Marshal.DestroyStructure<WinTrustData>(dataPtr); Marshal.FreeHGlobal(dataPtr); }
            if (fiPtr != IntPtr.Zero) { Marshal.DestroyStructure<WinTrustFileInfo>(fiPtr); Marshal.FreeHGlobal(fiPtr); }
        }
    }

    [DllImport("wintrust.dll", ExactSpelling=true, CharSet=CharSet.Unicode)]
    private static extern uint WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid action, IntPtr data);

    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    private struct WinTrustFileInfo
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string path;
        public IntPtr hFile;
        public IntPtr knownSubject;
        public WinTrustFileInfo(string p)
        {
            cbStruct=(uint)Marshal.SizeOf<WinTrustFileInfo>(); path=p; hFile=IntPtr.Zero; knownSubject=IntPtr.Zero;
        }
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        public uint cbStruct; public IntPtr policy; public IntPtr sip; public uint uiChoice; public uint revocation;
        public uint unionChoice; public IntPtr file; public uint stateAction; public IntPtr stateData; public IntPtr url;
        public uint flags; public uint uiContext;
        public WinTrustData(IntPtr f)
        {
            cbStruct=(uint)Marshal.SizeOf<WinTrustData>(); policy=IntPtr.Zero; sip=IntPtr.Zero; uiChoice=2;
            revocation=0; unionChoice=1; file=f; stateAction=0; stateData=IntPtr.Zero; url=IntPtr.Zero;
            flags=0x00001000; uiContext=0;
        }
    }
}

public static class RuleLoader
{
    public static async Task<RuleSet> LoadAsync(CancellationToken token)
    {
        string path=Path.Combine(AppContext.BaseDirectory,"Data","rules.json");
        if (!File.Exists(path)) return new();
        try
        {
            string json=await File.ReadAllTextAsync(path,token);
            return JsonSerializer.Deserialize<RuleSet>(json,new JsonSerializerOptions{PropertyNameCaseInsensitive=true}) ?? new();
        }
        catch { return new(); }
    }
}

public static class RuleMatcher
{
    public static bool ContainsHigh(string? value, RuleSet r) => ContainsAny(value,r.HighRiskKeywords);
    public static bool ContainsMedium(string? value, RuleSet r) => ContainsAny(value,r.MediumRiskKeywords);
    public static KnownCheatEntry? FindKnownCheat(string? hash, RuleSet r)
    {
        if (string.IsNullOrWhiteSpace(hash)) return null;
        return r.KnownCheats.FirstOrDefault(x =>
            !string.IsNullOrWhiteSpace(x.HashSha256) &&
            x.HashSha256.Equals(hash, StringComparison.OrdinalIgnoreCase));
    }

    public static bool IsKnownHash(string? hash, RuleSet r) =>
        FindKnownCheat(hash, r) is not null ||
        (!string.IsNullOrWhiteSpace(hash) && r.KnownHashes.Contains(hash,StringComparer.OrdinalIgnoreCase));

    public static KnownCheatNameEntry? FindKnownCheatName(string? value, RuleSet r)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        string normalizedValue = NormalizeName(value);
        string fileStem = NormalizeName(Path.GetFileNameWithoutExtension(value));

        foreach (KnownCheatNameEntry entry in r.KnownCheatNames)
        {
            IEnumerable<string> candidates = entry.Aliases.Prepend(entry.Name);
            foreach (string candidate in candidates)
            {
                if (string.IsNullOrWhiteSpace(candidate)) continue;
                string normalizedCandidate = NormalizeName(candidate);
                if (normalizedCandidate.Length < 4) continue;

                if (normalizedValue.Contains(normalizedCandidate, StringComparison.OrdinalIgnoreCase) ||
                    fileStem.Equals(normalizedCandidate, StringComparison.OrdinalIgnoreCase))
                    return entry;
            }
        }
        return null;
    }

    public static bool IsBinary(string? path) =>
        Path.GetExtension(path ?? "").ToLowerInvariant() is ".exe" or ".dll" or ".sys" or ".com" or ".scr" or ".msi";

    public static string NormalizeName(string? value) =>
        string.IsNullOrWhiteSpace(value)
            ? ""
            : new string(value.ToLowerInvariant().Where(char.IsLetterOrDigit).ToArray());
    public static bool IsKnownDomain(string? url, RuleSet r)
    {
        if (!Uri.TryCreate(url,UriKind.Absolute,out Uri? u)) return false;
        return r.KnownDomains.Any(d=>u.Host.Equals(d,StringComparison.OrdinalIgnoreCase) ||
            u.Host.EndsWith("."+d,StringComparison.OrdinalIgnoreCase));
    }
    public static bool IsTrustedPublisher(string? p, RuleSet r) =>
        !string.IsNullOrWhiteSpace(p) && r.TrustedPublishers.Any(x=>p.Contains(x,StringComparison.OrdinalIgnoreCase));
    public static bool IsUserWritable(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        try
        {
            string full=Path.GetFullPath(path);
            string user=Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string temp=Path.GetTempPath();
            string pd=Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            return full.StartsWith(user,StringComparison.OrdinalIgnoreCase) ||
                   full.StartsWith(temp,StringComparison.OrdinalIgnoreCase) ||
                   full.StartsWith(pd,StringComparison.OrdinalIgnoreCase);
        }
        catch { return false; }
    }
    public static bool IsExecutableOrArchive(string? path) =>
        Path.GetExtension(path??"").ToLowerInvariant() is ".exe" or ".dll" or ".sys" or ".com" or ".scr" or ".msi" or ".bat" or ".cmd" or ".ps1" or ".vbs" or ".js" or ".zip" or ".rar" or ".7z" or ".jar" or ".iso" or ".img" or ".lnk";
    private static bool ContainsAny(string? v,IEnumerable<string> terms) =>
        !string.IsNullOrWhiteSpace(v) && terms.Any(t=>!string.IsNullOrWhiteSpace(t)&&v.Contains(t,StringComparison.OrdinalIgnoreCase));
}

public sealed record StaticAnalysisResult(
    int Score,
    IReadOnlyList<string> Indicators,
    bool HasCs2Reference,
    bool HasInjectionPattern,
    bool HasCheatTerm)
{
    public static StaticAnalysisResult Empty { get; } = new(0, Array.Empty<string>(), false, false, false);
}

public static class StaticFileAnalyzer
{
    private static readonly string[] Cs2Terms =
    {
        "cs2.exe", "client.dll", "engine2.dll", "schemasystem.dll", "counter-strike 2", "counter strike 2"
    };

    private static readonly string[] CheatTerms =
    {
        "aimbot", "wallhack", "triggerbot", "silent aim", "silentaim", "ragebot", "antiaim", "anti-aim",
        "skin changer", "skinchanger", "vac bypass", "manual map", "manualmap", "esp hack", "bhop",
        "cheat loader", "cheat injector", "external cheat", "internal cheat", "dma cheat", "kdmapper"
    };

    private static readonly string[] InjectionTerms =
    {
        "writeprocessmemory", "createremotethread", "virtualallocex", "ntwritevirtualmemory",
        "ntcreatethreadex", "setwindowshookex", "openprocess", "readprocessmemory",
        "createtoolhelp32snapshot", "process32first", "process32next", "queueuserapc",
        "rtlcreateuserthread", "zwmapviewofsection", "ntmapviewofsection"
    };

    private static readonly string[] DriverTerms =
    {
        "iqvw64e.sys", "dbk64.sys", "gdrv.sys", "rtcore64.sys", "capcom.sys", "kdmapper"
    };

    public static async Task<StaticAnalysisResult> AnalyzeFileAsync(string path, CancellationToken token)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length <= 0) return StaticAnalysisResult.Empty;
            int length = (int)Math.Min(info.Length, 24L * 1024 * 1024);
            byte[] bytes = new byte[length];
            await using FileStream stream = new(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete, 1024 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            int offset = 0;
            while (offset < bytes.Length)
            {
                int read = await stream.ReadAsync(bytes.AsMemory(offset, bytes.Length - offset), token);
                if (read == 0) break;
                offset += read;
            }
            if (offset != bytes.Length) Array.Resize(ref bytes, offset);
            return AnalyzeBytes(bytes);
        }
        catch { return StaticAnalysisResult.Empty; }
    }

    public static StaticAnalysisResult AnalyzeBytes(ReadOnlySpan<byte> bytes)
    {
        if (bytes.IsEmpty) return StaticAnalysisResult.Empty;
        string ascii;
        string unicode;
        try
        {
            ascii = System.Text.Encoding.Latin1.GetString(bytes).ToLowerInvariant();
            unicode = System.Text.Encoding.Unicode.GetString(bytes).ToLowerInvariant();
        }
        catch { return StaticAnalysisResult.Empty; }

        string joined = ascii + "\n" + unicode;
        var indicators = new List<string>();

        int cs2Count = MatchTerms(joined, Cs2Terms, indicators, "CS2 reference");
        int cheatCount = MatchTerms(joined, CheatTerms, indicators, "Cheat-related string");
        int injectionCount = MatchTerms(joined, InjectionTerms, indicators, "Process/memory API");
        int driverCount = MatchTerms(joined, DriverTerms, indicators, "Driver/mapper string");

        bool hasCs2 = cs2Count > 0;
        bool hasCheat = cheatCount > 0;
        bool hasInjection = injectionCount >= 2;

        int score = 0;
        if (hasCs2) score += 20;
        if (hasCheat) score += Math.Min(35, 20 + cheatCount * 5);
        if (injectionCount >= 2) score += Math.Min(30, 15 + injectionCount * 3);
        if (driverCount > 0) score += Math.Min(30, 18 + driverCount * 5);
        if (hasCs2 && hasCheat) score += 25;
        if (hasCs2 && hasInjection) score += 20;
        if (hasCheat && hasInjection) score += 15;

        return new(Math.Min(100, score), indicators.Distinct(StringComparer.OrdinalIgnoreCase).Take(24).ToArray(),
            hasCs2, hasInjection, hasCheat);
    }

    private static int MatchTerms(string haystack, IEnumerable<string> terms, List<string> indicators, string label)
    {
        int count = 0;
        foreach (string term in terms)
        {
            if (!haystack.Contains(term, StringComparison.OrdinalIgnoreCase)) continue;
            count++;
            if (indicators.Count < 24) indicators.Add($"{label}: {term}");
        }
        return count;
    }
}
