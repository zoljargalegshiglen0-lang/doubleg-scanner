using System.IO.Compression;
using System.Text;
using DoubleGScanner.Models;
using DoubleGScanner.Services;
using Microsoft.Win32;

namespace DoubleGScanner.Collectors;

public sealed class ExecutionHistoryCollector : IScanCollector
{
    public string Name=>"Execution history";
    public bool Supports(ScanMode mode)=>mode!=ScanMode.Quick;
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
        if(!Directory.Exists(folder))return 0;int limit=mode==ScanMode.Forensic?2000:700;
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
        string folder=Environment.GetFolderPath(Environment.SpecialFolder.Recent);if(!Directory.Exists(folder))return 0;
        FileInfo[] files=new DirectoryInfo(folder).EnumerateFiles("*").OrderByDescending(x=>x.LastWriteTimeUtc).Take(500).ToArray();
        foreach(FileInfo f in files)list.Add(new(){Kind=EvidenceKind.Execution,Source="Recent Items",Name=f.Name,Path=f.FullName,Timestamp=f.LastWriteTime,
            Detail="Recent Items shell artifact; shortcut target was not opened."});
        return files.Length;
    }
    private static string Rot13(string s)
    {
        var b=new StringBuilder(s.Length);foreach(char ch in s)
        {if(ch is>='a'and<='z')b.Append((char)('a'+(ch-'a'+13)%26));else if(ch is>='A'and<='Z')b.Append((char)('A'+(ch-'A'+13)%26));else b.Append(ch);}return b.ToString();
    }
}

public sealed class RecycleBinCollector : IScanCollector
{
    public string Name=>"Deleted-file traces";
    public bool Supports(ScanMode mode)=>mode!=ScanMode.Quick;
    public Task<CollectorOutput> CollectAsync(ScanContext c,IProgress<ScanProgressUpdate>? p,CancellationToken t)
    {
        DateTime start=DateTime.UtcNow;var list=new List<EvidenceRecord>();int checkedCount=0;bool partial=false;
        p?.Report(new(){Percent=61,Module=Name,Message="Reading Recycle Bin metadata without restoring files..."});
        foreach(DriveInfo drive in DriveInfo.GetDrives().Where(x=>x.IsReady&&x.DriveType==DriveType.Fixed))
        {
            string rb=Path.Combine(drive.RootDirectory.FullName,"$Recycle.Bin");if(!Directory.Exists(rb))continue;
            try
            {
                foreach(string file in Files(rb,"$I*"))
                {
                    t.ThrowIfCancellationRequested();checkedCount++;
                    if(Parse(file,out Deleted? d)&&d is not null)list.Add(new(){Kind=EvidenceKind.DeletedFile,Source=Name,
                        Name=Path.GetFileName(d.Path),Path=d.Path,Timestamp=d.Time,Detail="Recycle Bin metadata; content was not restored or opened.",
                        Metadata=new(StringComparer.OrdinalIgnoreCase){["OriginalSize"]=d.Size.ToString(),["MetadataFile"]=file,["CurrentStatus"]="Deleted trace"}});
                }
            }
            catch{partial=true;}
        }
        return Task.FromResult(new CollectorOutput{Module=Name,Status=partial?CoverageStatus.Partial:CoverageStatus.Completed,
            Summary=$"Checked {checkedCount:N0} Recycle Bin metadata records and parsed {list.Count:N0} deleted-file traces.",
            Evidence=list,ItemsChecked=checkedCount,Duration=DateTime.UtcNow-start});
    }
    private static bool Parse(string path,out Deleted? d)
    {
        d=null;try
        {
            byte[] data=File.ReadAllBytes(path);if(data.Length<24)return false;long ver=BitConverter.ToInt64(data,0),size=BitConverter.ToInt64(data,8),ft=BitConverter.ToInt64(data,16);
            DateTimeOffset? time=null;try{if(ft>0)time=DateTimeOffset.FromFileTime(ft);}catch{}
            string original;
            if(ver==2&&data.Length>=28){int chars=BitConverter.ToInt32(data,24);int bytes=Math.Min(Math.Max(chars*2,0),data.Length-28);original=Encoding.Unicode.GetString(data,28,bytes).TrimEnd('\0');}
            else original=Encoding.Unicode.GetString(data,24,data.Length-24).TrimEnd('\0');
            if(string.IsNullOrWhiteSpace(original))return false;d=new(original,size,time);return true;
        }catch{return false;}
    }
    private static IEnumerable<string> Files(string root,string pattern)
    {
        var stack=new Stack<string>();stack.Push(root);
        while(stack.Count>0){string cur=stack.Pop();string[] fs;try{fs=Directory.GetFiles(cur,pattern);}catch{fs=Array.Empty<string>();}
            foreach(string f in fs)yield return f;string[] ds;try{ds=Directory.GetDirectories(cur);}catch{ds=Array.Empty<string>();}foreach(string dir in ds)stack.Push(dir);}
    }
    private sealed record Deleted(string Path,long Size,DateTimeOffset? Time);
}

public sealed class FileArtifactCollector : IScanCollector
{
    public string Name=>"High-risk file locations";
    public bool Supports(ScanMode mode)=>mode!=ScanMode.Quick;
    private static readonly HashSet<string> Ext=new(StringComparer.OrdinalIgnoreCase){".exe",".dll",".sys",".com",".scr",".bat",".cmd",".ps1",".zip",".rar",".7z"};
    public async Task<CollectorOutput> CollectAsync(ScanContext c,IProgress<ScanProgressUpdate>? p,CancellationToken t)
    {
        DateTime start=DateTime.UtcNow;var list=new List<EvidenceRecord>();int checkedCount=0,max=c.Mode==ScanMode.Forensic?12000:5000,days=c.Mode==ScanMode.Forensic?180:60;
        DateTime cutoff=DateTime.UtcNow.AddDays(-days);string user=Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string[] roots={Path.Combine(user,"Downloads"),Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),Path.GetTempPath(),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Temp")};
        foreach(string root in roots.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if(!Directory.Exists(root))continue;
            foreach(string file in Files(root))
            {
                t.ThrowIfCancellationRequested();if(checkedCount>=max)break;string ext=Path.GetExtension(file);if(!Ext.Contains(ext))continue;
                FileInfo info;try{info=new(file);}catch{continue;}if(info.LastWriteTimeUtc<cutoff)continue;checkedCount++;
                string? hash=null;SignatureResult? sig=null;string detail="Metadata only";
                if(ext is ".exe"or".dll"or".sys"or".com"or".scr"){sig=SignatureVerifier.Verify(file);hash=await HashService.TrySha256Async(file,t);detail=sig.Status;}
                else if(ext.Equals(".zip",StringComparison.OrdinalIgnoreCase)){string[] entries=ZipNames(file,c.Rules).Take(12).ToArray();if(entries.Length>0)detail="Potentially relevant archive entries: "+string.Join(", ",entries);}
                bool relevant=RuleMatcher.IsKnownHash(hash,c.Rules)||RuleMatcher.ContainsHigh(file+" "+detail,c.Rules)||
                    (RuleMatcher.ContainsMedium(file+" "+detail,c.Rules)&&RuleMatcher.IsUserWritable(file));
                if(!relevant)continue;
                list.Add(new(){Kind=EvidenceKind.FileArtifact,Source=Name,Name=info.Name,Path=info.FullName,HashSha256=hash,
                    Publisher=sig?.Publisher,IsSignatureValid=sig?.IsValid,Timestamp=info.LastWriteTime,Detail=detail,
                    Metadata=new(StringComparer.OrdinalIgnoreCase){["FileSize"]=info.Length.ToString(),["Extension"]=ext,["Created"]=info.CreationTime.ToString("O")}});
                if(checkedCount%100==0)p?.Report(new(){Percent=80,Module=Name,Message=$"Checking recent executable/archive metadata in {root}",ItemsChecked=checkedCount});
            }
            if(checkedCount>=max)break;
        }
        return new(){Module=Name,Status=checkedCount>=max?CoverageStatus.Partial:CoverageStatus.Completed,
            Summary=$"Checked {checkedCount:N0} recent executable/archive files; retained {list.Count:N0} potentially relevant records.",
            Evidence=list,ItemsChecked=checkedCount,Duration=DateTime.UtcNow-start};
    }
    private static IEnumerable<string> Files(string root)
    {
        var stack=new Stack<string>();stack.Push(root);while(stack.Count>0){string cur=stack.Pop();string[] fs;try{fs=Directory.GetFiles(cur);}catch{fs=Array.Empty<string>();}
            foreach(string f in fs)yield return f;string[] ds;try{ds=Directory.GetDirectories(cur);}catch{ds=Array.Empty<string>();}
            foreach(string dir in ds){try{if((new DirectoryInfo(dir).Attributes&FileAttributes.ReparsePoint)==0)stack.Push(dir);}catch{}}}
    }
    private static IReadOnlyList<string> ZipNames(string path,RuleSet rules)
    {
        var matches=new List<string>();
        try
        {
            using ZipArchive a=ZipFile.OpenRead(path);
            foreach(ZipArchiveEntry e in a.Entries.Take(3000))
                if(RuleMatcher.ContainsHigh(e.FullName,rules)||RuleMatcher.ContainsMedium(e.FullName,rules))
                    matches.Add(e.FullName);
        }
        catch { }
        return matches;
    }
}
