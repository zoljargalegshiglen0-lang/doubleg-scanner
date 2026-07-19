using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using DoubleGScanner.Models;
using DoubleGScanner.Services;
using Microsoft.Win32;

namespace DoubleGScanner.Collectors;

public sealed class SystemProfileCollector : IScanCollector
{
    public string Name=>"System profile";
    public bool Supports(ScanMode mode)=>true;
    public Task<CollectorOutput> CollectAsync(ScanContext c,IProgress<ScanProgressUpdate>? p,CancellationToken t)
    {
        DateTime start=DateTime.UtcNow;
        p?.Report(new(){Percent=3,Module=Name,Message="Reading Windows security and scanner integrity..."});
        bool elevated=IsAdministrator();
        string? executable=Environment.ProcessPath;
        var evidence=new List<EvidenceRecord>
        {
            new()
            {
                Kind=EvidenceKind.System,Source=Name,Name="Windows profile",
                Detail=$"{Environment.OSVersion.VersionString}; 64-bit OS: {Environment.Is64BitOperatingSystem}",
                Metadata=new(StringComparer.OrdinalIgnoreCase)
                {
                    ["MachineName"]=Environment.MachineName,["UserName"]=Environment.UserName,
                    ["Elevated"]=elevated.ToString(),["TimeZone"]=TimeZoneInfo.Local.Id,
                    ["SecureBoot"]=ReadReg(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State","UEFISecureBootEnabled"),
                    ["MemoryIntegrity"]=ReadReg(@"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity","Enabled"),
                    ["ScannerVersion"]=Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "unknown",
                    ["ScannerHash"]=executable is null?"Unavailable":HashService.TrySha256(executable)??"Unavailable"
                }
            }
        };
        return Task.FromResult(new CollectorOutput{Module=Name,Status=CoverageStatus.Completed,
            Summary=elevated?"System profile collected with administrator access.":"System profile collected as standard user; protected artifacts may be unavailable.",
            Evidence=evidence,ItemsChecked=1,Duration=DateTime.UtcNow-start});
    }
    public static bool IsAdministrator()
    {
        try { using WindowsIdentity i=WindowsIdentity.GetCurrent(); return new WindowsPrincipal(i).IsInRole(WindowsBuiltInRole.Administrator); }
        catch { return false; }
    }
    private static string ReadReg(string path,string name)
    {
        try
        {
            using RegistryKey? k=Registry.LocalMachine.OpenSubKey(path);
            return k?.GetValue(name) switch { 1=>"Enabled",0=>"Disabled",_=>"Unavailable" };
        }
        catch { return "Unavailable"; }
    }
}

public sealed class ProcessCollector : IScanCollector
{
    public string Name=>"Running processes";
    public bool Supports(ScanMode mode)=>true;
    public async Task<CollectorOutput> CollectAsync(ScanContext c,IProgress<ScanProgressUpdate>? p,CancellationToken t)
    {
        DateTime start=DateTime.UtcNow; var list=new List<EvidenceRecord>();
        Process[] processes=Process.GetProcesses().OrderBy(x=>x.ProcessName,StringComparer.OrdinalIgnoreCase).ToArray();
        for(int i=0;i<processes.Length;i++)
        {
            t.ThrowIfCancellationRequested(); using Process proc=processes[i];
            string? path=null; DateTimeOffset? started=null; SignatureResult? sig=null; string? hash=null; string detail="";
            try { path=proc.MainModule?.FileName; } catch(Exception ex){ detail="Path unavailable: "+ex.GetType().Name; }
            try { started=proc.StartTime; } catch {}
            if(!string.IsNullOrWhiteSpace(path)&&File.Exists(path))
            {
                sig=SignatureVerifier.Verify(path); hash=await HashService.TrySha256Async(path,t);
            }
            list.Add(new(){Kind=EvidenceKind.Process,Source=Name,Name=proc.ProcessName,Path=path,HashSha256=hash,
                Publisher=sig?.Publisher,IsSignatureValid=sig?.IsValid,ProcessId=proc.Id,Timestamp=started,
                Detail=string.IsNullOrWhiteSpace(detail)?sig?.Status:detail});
            if(i%5==0||i==processes.Length-1) p?.Report(new(){Percent=8+(int)((i+1)/(double)Math.Max(1,processes.Length)*20),
                Module=Name,Message=$"Analyzing {proc.ProcessName}",ItemsChecked=list.Count});
        }
        return new(){Module=Name,Status=CoverageStatus.Completed,Summary=$"Collected metadata for {list.Count} running processes.",
            Evidence=list,ItemsChecked=list.Count,Duration=DateTime.UtcNow-start};
    }
}

public sealed class ModuleCollector : IScanCollector
{
    public string Name=>"CS2 loaded modules";
    public bool Supports(ScanMode mode)=>true;
    public async Task<CollectorOutput> CollectAsync(ScanContext c,IProgress<ScanProgressUpdate>? p,CancellationToken t)
    {
        DateTime start=DateTime.UtcNow; var list=new List<EvidenceRecord>(); bool partial=false;
        Process[] procs=Process.GetProcessesByName("cs2");
        foreach(Process proc in procs)
        {
            using(proc)
            {
                try
                {
                    int n=0;
                    foreach(ProcessModule m in proc.Modules)
                    {
                        t.ThrowIfCancellationRequested(); string? path=m.FileName; SignatureResult? sig=null; string? hash=null;
                        if(!string.IsNullOrWhiteSpace(path)&&File.Exists(path)){sig=SignatureVerifier.Verify(path);hash=await HashService.TrySha256Async(path,t);}
                        list.Add(new(){Kind=EvidenceKind.Module,Source=Name,Name=m.ModuleName,Path=path,HashSha256=hash,
                            Publisher=sig?.Publisher,IsSignatureValid=sig?.IsValid,ProcessId=proc.Id,Detail=sig?.Status,
                            Metadata=new(StringComparer.OrdinalIgnoreCase){["ProcessName"]="cs2.exe",["BaseAddress"]=m.BaseAddress.ToString("X"),["ModuleMemorySize"]=m.ModuleMemorySize.ToString()}});
                        if(++n%10==0)p?.Report(new(){Percent=31,Module=Name,Message=$"Inspecting CS2 module {m.ModuleName}",ItemsChecked=list.Count});
                    }
                }
                catch { partial=true; }
            }
        }
        string summary=procs.Length==0?"CS2 was not running; live loaded-module inspection was unavailable.":
            partial?$"Collected {list.Count} modules; some metadata was unavailable.":$"Collected {list.Count} modules loaded by CS2.";
        return new(){Module=Name,Status=procs.Length==0||partial?CoverageStatus.Partial:CoverageStatus.Completed,
            Summary=summary,Evidence=list,ItemsChecked=list.Count,Duration=DateTime.UtcNow-start};
    }
}

public sealed class NetworkCollector : IScanCollector
{
    public string Name=>"Live network activity";
    public bool Supports(ScanMode mode)=>true;
    public Task<CollectorOutput> CollectAsync(ScanContext c,IProgress<ScanProgressUpdate>? p,CancellationToken t)
    {
        DateTime start=DateTime.UtcNow; var list=new List<EvidenceRecord>();
        p?.Report(new(){Percent=70,Module=Name,Message="Reading current TCP connections and network counters..."});
        foreach(TcpRow row in GetRows())
        {
            t.ThrowIfCancellationRequested();
            list.Add(new(){Kind=EvidenceKind.Network,Source=Name,Name=ProcessName(row.Pid),ProcessId=row.Pid,
                Detail=$"{row.LocalAddress}:{row.LocalPort} -> {row.RemoteAddress}:{row.RemotePort}",
                Metadata=new(StringComparer.OrdinalIgnoreCase){["State"]=row.State,["RemoteEndpoint"]=$"{row.RemoteAddress}:{row.RemotePort}"}});
        }
        long received=0,sent=0;
        foreach(NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            try { var s=ni.GetIPv4Statistics();received+=s.BytesReceived;sent+=s.BytesSent; } catch {}
        }
        list.Add(new(){Kind=EvidenceKind.System,Source=Name,Name="System network counters",
            Detail="Cumulative interface counters; not historical per-application usage.",
            Metadata=new(StringComparer.OrdinalIgnoreCase){["BytesReceived"]=received.ToString(),["BytesSent"]=sent.ToString()}});
        return Task.FromResult(new CollectorOutput{Module=Name,Status=CoverageStatus.Completed,
            Summary=$"Collected {Math.Max(0,list.Count-1)} live TCP connections and system counters.",Evidence=list,ItemsChecked=list.Count,Duration=DateTime.UtcNow-start});
    }
    private static string ProcessName(int pid){try{using Process p=Process.GetProcessById(pid);return p.ProcessName;}catch{return "PID "+pid;}}
    private static IReadOnlyList<TcpRow> GetRows()
    {
        const int af=2; int size=0; GetExtendedTcpTable(IntPtr.Zero,ref size,true,af,TcpClass.OwnerPidAll,0);
        if(size<=0)return Array.Empty<TcpRow>(); IntPtr buffer=Marshal.AllocHGlobal(size);
        try
        {
            if(GetExtendedTcpTable(buffer,ref size,true,af,TcpClass.OwnerPidAll,0)!=0)return Array.Empty<TcpRow>();
            int count=Marshal.ReadInt32(buffer),rowSize=Marshal.SizeOf<MibRow>();IntPtr ptr=IntPtr.Add(buffer,4);var rows=new List<TcpRow>();
            for(int i=0;i<count;i++)
            {
                MibRow r=Marshal.PtrToStructure<MibRow>(ptr);
                rows.Add(new(new IPAddress(r.LocalAddr).ToString(),Port(r.LocalPort),new IPAddress(r.RemoteAddr).ToString(),Port(r.RemotePort),
                    r.Pid>int.MaxValue?0:(int)r.Pid,((TcpState)r.State).ToString())); ptr=IntPtr.Add(ptr,rowSize);
            }
            return rows;
        }
        finally{Marshal.FreeHGlobal(buffer);}
    }
    private static int Port(uint p)=>(int)(((p&0xFF)<<8)|((p&0xFF00)>>8));
    [DllImport("iphlpapi.dll")]private static extern uint GetExtendedTcpTable(IntPtr table,ref int size,bool order,int version,TcpClass cls,uint reserved);
    private enum TcpClass{OwnerPidAll=5}
    [StructLayout(LayoutKind.Sequential)]private struct MibRow{public uint State,LocalAddr,LocalPort,RemoteAddr,RemotePort,Pid;}
    private sealed record TcpRow(string LocalAddress,int LocalPort,string RemoteAddress,int RemotePort,int Pid,string State);
}
