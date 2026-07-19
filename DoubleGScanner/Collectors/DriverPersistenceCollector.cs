using DoubleGScanner.Models;
using DoubleGScanner.Services;
using Microsoft.Win32;

namespace DoubleGScanner.Collectors;

public sealed class DriverPersistenceCollector : IScanCollector
{
    public string Name=>"Drivers and startup persistence";
    public bool Supports(ScanMode mode)=>mode!=ScanMode.Quick;

    public async Task<CollectorOutput> CollectAsync(ScanContext c,IProgress<ScanProgressUpdate>? p,CancellationToken t)
    {
        DateTime start=DateTime.UtcNow;var list=new List<EvidenceRecord>();int checkedCount=0;bool partial=false;
        p?.Report(new(){Percent=74,Module=Name,Message="Checking registered kernel drivers and startup entries..."});
        try
        {
            using RegistryKey? services=Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if(services is not null)
            {
                foreach(string serviceName in services.GetSubKeyNames())
                {
                    t.ThrowIfCancellationRequested();using RegistryKey? key=services.OpenSubKey(serviceName);if(key is null)continue;
                    int type=key.GetValue("Type") is int i?i:0;if((type&1)==0&&(type&2)==0)continue;checkedCount++;
                    string raw=Convert.ToString(key.GetValue("ImagePath"))??"";string? path=ResolveDriverPath(raw);
                    SignatureResult? sig=null;string? hash=null;
                    if(!string.IsNullOrWhiteSpace(path)&&File.Exists(path)){sig=SignatureVerifier.Verify(path);hash=await HashService.TrySha256Async(path,t);}
                    list.Add(new(){Kind=EvidenceKind.FileArtifact,Source=Name,Name=serviceName,Path=path,HashSha256=hash,
                        Publisher=sig?.Publisher,IsSignatureValid=sig?.IsValid,Detail=sig?.Status??"Driver path unavailable",
                        Metadata=new(StringComparer.OrdinalIgnoreCase){["RecordType"]="Driver",["RawImagePath"]=raw,
                            ["Start"]=Convert.ToString(key.GetValue("Start"))??"Unavailable",["ServiceType"]=type.ToString(),
                            ["DisplayName"]=Convert.ToString(key.GetValue("DisplayName"))??serviceName}});
                }
            }
        }
        catch{partial=true;}

        foreach((RegistryKey root,string path,string scope) in new[]{
            (Registry.CurrentUser,@"Software\Microsoft\Windows\CurrentVersion\Run","Current user Run"),
            (Registry.CurrentUser,@"Software\Microsoft\Windows\CurrentVersion\RunOnce","Current user RunOnce"),
            (Registry.LocalMachine,@"Software\Microsoft\Windows\CurrentVersion\Run","All users Run"),
            (Registry.LocalMachine,@"Software\Microsoft\Windows\CurrentVersion\RunOnce","All users RunOnce")})
        {
            try
            {
                using RegistryKey? key=root.OpenSubKey(path);if(key is null)continue;
                foreach(string valueName in key.GetValueNames())
                {
                    checkedCount++;string command=Convert.ToString(key.GetValue(valueName))??"";
                    list.Add(new(){Kind=EvidenceKind.Execution,Source=Name,Name=valueName,Path=command,Detail="Windows startup registry entry.",
                        Metadata=new(StringComparer.OrdinalIgnoreCase){["RecordType"]="Startup",["Scope"]=scope}});
                }
            }
            catch{partial=true;}
        }

        foreach(string folder in new[]{Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)})
        {
            if(!Directory.Exists(folder))continue;
            try
            {
                foreach(string file in Directory.EnumerateFiles(folder))
                {
                    checkedCount++;list.Add(new(){Kind=EvidenceKind.Execution,Source=Name,Name=Path.GetFileName(file),Path=file,
                        Timestamp=File.GetLastWriteTime(file),Detail="Startup folder entry.",
                        Metadata=new(StringComparer.OrdinalIgnoreCase){["RecordType"]="StartupFolder"}});
                }
            }
            catch{partial=true;}
        }

        return new(){Module=Name,Status=partial?CoverageStatus.Partial:CoverageStatus.Completed,
            Summary=$"Checked {checkedCount:N0} registered driver and startup records.",Evidence=list,ItemsChecked=checkedCount,Duration=DateTime.UtcNow-start};
    }

    private static string? ResolveDriverPath(string raw)
    {
        if(string.IsNullOrWhiteSpace(raw))return null;string value=Environment.ExpandEnvironmentVariables(raw.Trim().Trim('"'));
        if(value.StartsWith(@"\SystemRoot\",StringComparison.OrdinalIgnoreCase))
            value=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),value[12..]);
        else if(value.StartsWith(@"System32\",StringComparison.OrdinalIgnoreCase))
            value=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),value);
        else if(value.StartsWith(@"\??\",StringComparison.OrdinalIgnoreCase))value=value[4..];
        int sys=value.IndexOf(".sys",StringComparison.OrdinalIgnoreCase);if(sys>=0)value=value[..(sys+4)];
        return value;
    }
}
