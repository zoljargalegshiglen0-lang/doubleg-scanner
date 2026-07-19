using DoubleGScanner.Models;
using DoubleGScanner.Services;
using Microsoft.Data.Sqlite;

namespace DoubleGScanner.Collectors;

public sealed class BrowserCollector : IScanCollector
{
    public string Name=>"Browser activity";
    public bool Supports(ScanMode mode)=>mode!=ScanMode.Quick;

    public async Task<CollectorOutput> CollectAsync(ScanContext c,IProgress<ScanProgressUpdate>? p,CancellationToken t)
    {
        DateTime start=DateTime.UtcNow; var list=new List<EvidenceRecord>(); int checkedRows=0,profiles=0;bool partial=false;
        foreach(Profile profile in Discover())
        {
            t.ThrowIfCancellationRequested();profiles++;
            p?.Report(new(){Percent=38,Module=Name,Message=$"Checking {profile.Browser} - {profile.Name}",ItemsChecked=checkedRows});
            try
            {
                string copy=await CopyDb(profile.Path,c.TempDirectory,t);
                checkedRows+=profile.Firefox?await ReadFirefox(copy,profile,c.Rules,list,t):await ReadChromium(copy,profile,c.Rules,c.Mode,list,t);
            }
            catch { partial=true; }
        }
        return new(){Module=Name,Status=profiles==0?CoverageStatus.Unavailable:partial?CoverageStatus.Partial:CoverageStatus.Completed,
            Summary=profiles==0?"No supported browser database was found.":$"Checked {checkedRows:N0} local browser records across {profiles} profile(s); retained only potentially relevant entries.",
            Evidence=list,ItemsChecked=checkedRows,Duration=DateTime.UtcNow-start};
    }

    private static IEnumerable<Profile> Discover()
    {
        string local=Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string roaming=Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        foreach(var b in new[]{("Chrome",Path.Combine(local,"Google","Chrome","User Data")),
            ("Edge",Path.Combine(local,"Microsoft","Edge","User Data")),
            ("Brave",Path.Combine(local,"BraveSoftware","Brave-Browser","User Data"))})
        {
            if(!Directory.Exists(b.Item2))continue;
            foreach(string dir in SafeDirs(b.Item2))
            {
                string n=Path.GetFileName(dir);
                if(n.Equals("Default",StringComparison.OrdinalIgnoreCase)||n.StartsWith("Profile ",StringComparison.OrdinalIgnoreCase))
                {
                    string h=Path.Combine(dir,"History");if(File.Exists(h))yield return new(b.Item1,n,h,false);
                }
            }
        }
        foreach(var b in new[]{("Opera",Path.Combine(roaming,"Opera Software","Opera Stable","History")),
            ("Opera GX",Path.Combine(roaming,"Opera Software","Opera GX Stable","History"))})
            if(File.Exists(b.Item2))yield return new(b.Item1,"Default",b.Item2,false);
        string ff=Path.Combine(roaming,"Mozilla","Firefox","Profiles");
        if(Directory.Exists(ff))foreach(string dir in SafeDirs(ff))
        {
            string db=Path.Combine(dir,"places.sqlite");if(File.Exists(db))yield return new("Firefox",Path.GetFileName(dir),db,true);
        }
    }

    private static async Task<int> ReadChromium(string path,Profile profile,RuleSet rules,ScanMode mode,List<EvidenceRecord> list,CancellationToken t)
    {
        int count=0;await using var con=new SqliteConnection($"Data Source={path};Mode=ReadOnly");await con.OpenAsync(t);
        await using(var cmd=con.CreateCommand())
        {
            cmd.CommandText="SELECT url,title,last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 12000";
            await using var r=await cmd.ExecuteReaderAsync(t);
            while(await r.ReadAsync(t))
            {
                count++;string url=S(r,0),title=S(r,1);long raw=L(r,2);string all=url+" "+title;
                bool relevant=RuleMatcher.IsKnownDomain(url,rules)||RuleMatcher.ContainsHigh(all,rules)||
                    (RuleMatcher.ContainsMedium(all,rules)&&url.Contains("cs2",StringComparison.OrdinalIgnoreCase));
                if(!relevant)continue;
                list.Add(new(){Kind=EvidenceKind.Browser,Source="Browser activity",Name=string.IsNullOrWhiteSpace(title)?"Browser visit":title,
                    Url=url,Timestamp=ChromiumTime(raw),Detail="Potentially relevant local visit. No cookies, passwords, or sessions were read.",
                    Metadata=new(StringComparer.OrdinalIgnoreCase){["Browser"]=profile.Browser,["Profile"]=profile.Name,["RecordType"]="Visit"}});
            }
        }
        if(await TableExists(con,"downloads",t))
        {
            HashSet<string> cols=await Columns(con,"downloads",t);string C(string n)=>cols.Contains(n)?n:$"NULL AS {n}";
            await using var cmd=con.CreateCommand();
            cmd.CommandText=$"SELECT {C("current_path")},{C("target_path")},{C("start_time")},{C("tab_url")},{C("site_url")},{C("referrer")} FROM downloads ORDER BY start_time DESC LIMIT 4000";
            await using var r=await cmd.ExecuteReaderAsync(t);
            while(await r.ReadAsync(t))
            {
                count++;string current=S(r,0),target=S(r,1),tab=S(r,3),site=S(r,4),referrer=S(r,5);long raw=L(r,2);
                string selected=!string.IsNullOrWhiteSpace(target)?target:current;
                DateTimeOffset? timestamp=ChromiumTime(raw);
                int recentDays=mode==ScanMode.Forensic?365:120;
                bool recent=timestamp is not null&&timestamp.Value>=DateTimeOffset.Now.AddDays(-recentDays);
                bool executableOrArchive=RuleMatcher.IsExecutableOrArchive(selected);
                string all=string.Join(" ",current,target,tab,site,referrer);
                bool relevant=RuleMatcher.IsKnownDomain(tab,rules)||RuleMatcher.IsKnownDomain(site,rules)||RuleMatcher.ContainsHigh(all,rules)||
                    (RuleMatcher.ContainsMedium(all,rules)&&executableOrArchive)||(recent&&executableOrArchive);
                if(!relevant)continue;
                list.Add(new(){Kind=EvidenceKind.Browser,Source="Browser activity",
                    Name=Path.GetFileName(selected) is {Length:>0} n?n:"Browser download",Path=selected,
                    Url=!string.IsNullOrWhiteSpace(tab)?tab:!string.IsNullOrWhiteSpace(site)?site:referrer,
                    Timestamp=timestamp,Detail=RuleMatcher.ContainsHigh(all,rules)?"Potentially cheat-related local download record.":"Recent executable/archive download record retained for correlation.",
                    Metadata=new(StringComparer.OrdinalIgnoreCase){["Browser"]=profile.Browser,["Profile"]=profile.Name,["RecordType"]="Download",
                        ["FileExists"]=(!string.IsNullOrWhiteSpace(selected)&&File.Exists(selected)).ToString(),
                        ["RecentDownload"]=recent.ToString(),["ExecutableOrArchive"]=executableOrArchive.ToString(),
                        ["Extension"]=Path.GetExtension(selected)}});
            }
        }
        return count;
    }

    private static async Task<int> ReadFirefox(string path,Profile profile,RuleSet rules,List<EvidenceRecord> list,CancellationToken t)
    {
        int count=0;await using var con=new SqliteConnection($"Data Source={path};Mode=ReadOnly");await con.OpenAsync(t);
        await using var cmd=con.CreateCommand();cmd.CommandText="SELECT url,title,last_visit_date FROM moz_places WHERE last_visit_date IS NOT NULL ORDER BY last_visit_date DESC LIMIT 12000";
        await using var r=await cmd.ExecuteReaderAsync(t);
        while(await r.ReadAsync(t))
        {
            count++;string url=S(r,0),title=S(r,1);long raw=L(r,2);
            if(!RuleMatcher.IsKnownDomain(url,rules)&&!RuleMatcher.ContainsHigh(url+" "+title,rules))continue;
            list.Add(new(){Kind=EvidenceKind.Browser,Source="Browser activity",Name=string.IsNullOrWhiteSpace(title)?"Firefox visit":title,
                Url=url,Timestamp=raw>0?DateTimeOffset.FromUnixTimeMilliseconds(raw/1000):null,Detail="Potentially relevant Firefox history entry.",
                Metadata=new(StringComparer.OrdinalIgnoreCase){["Browser"]=profile.Browser,["Profile"]=profile.Name,["RecordType"]="Visit"}});
        }
        return count;
    }

    private static async Task<string> CopyDb(string source,string temp,CancellationToken t)
    {
        string dir=Path.Combine(temp,"browser-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(dir);
        string dest=Path.Combine(dir,Path.GetFileName(source));
        await using FileStream input=new(source,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete,1024*1024,true);
        await using FileStream output=new(dest,FileMode.CreateNew,FileAccess.Write,FileShare.None,1024*1024,true);
        await input.CopyToAsync(output,t);return dest;
    }
    private static DateTimeOffset? ChromiumTime(long micro)
    {if(micro<=0)return null;try{return new DateTimeOffset(1601,1,1,0,0,0,TimeSpan.Zero).AddTicks(micro*10);}catch{return null;}}
    private static async Task<bool> TableExists(SqliteConnection c,string table,CancellationToken t)
    {await using var cmd=c.CreateCommand();cmd.CommandText="SELECT 1 FROM sqlite_master WHERE type='table' AND name=$n LIMIT 1";cmd.Parameters.AddWithValue("$n",table);return await cmd.ExecuteScalarAsync(t)is not null;}
    private static async Task<HashSet<string>> Columns(SqliteConnection c,string table,CancellationToken t)
    {var set=new HashSet<string>(StringComparer.OrdinalIgnoreCase);await using var cmd=c.CreateCommand();cmd.CommandText=$"PRAGMA table_info([{table.Replace("]","]]",StringComparison.Ordinal)}])";
     await using var r=await cmd.ExecuteReaderAsync(t);while(await r.ReadAsync(t))if(!r.IsDBNull(1))set.Add(r.GetString(1));return set;}
    private static string S(SqliteDataReader r,int i)=>r.IsDBNull(i)?"":Convert.ToString(r.GetValue(i))??"";
    private static long L(SqliteDataReader r,int i)=>r.IsDBNull(i)?0:Convert.ToInt64(r.GetValue(i));
    private static IEnumerable<string> SafeDirs(string p){try{return Directory.EnumerateDirectories(p).ToArray();}catch{return Array.Empty<string>();}}
    private sealed record Profile(string Browser,string Name,string Path,bool Firefox);
}
