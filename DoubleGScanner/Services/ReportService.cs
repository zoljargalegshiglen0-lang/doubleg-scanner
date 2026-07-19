using System.Text.Json;
using DoubleGScanner.Models;
using MigraDoc.DocumentObjectModel;
using MigraDoc.DocumentObjectModel.Tables;
using MigraDoc.Rendering;

namespace DoubleGScanner.Services;

public sealed class ReportService
{
    public async Task<ReportBundle> CreateAsync(ScanResult result,CancellationToken token)
    {
        string dir=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),"DoubleG Scanner","Reports",result.ScanId);
        Directory.CreateDirectory(dir);
        string jsonPath=Path.Combine(dir,$"DoubleG-Scanner_Evidence_{result.ScanId}.json");
        string json=JsonSerializer.Serialize(result,new JsonSerializerOptions{WriteIndented=true});
        await File.WriteAllTextAsync(jsonPath,json,token);
        result.EvidenceJsonHash=HashService.TrySha256(jsonPath)??"Unavailable";

        string pdfPath=Path.Combine(dir,$"DoubleG-Scanner_Report_{result.ScanId}.pdf");
        var renderer=new PdfDocumentRenderer{Document=Build(result)};
        renderer.RenderDocument();renderer.PdfDocument.Save(pdfPath);
        string pdfHash=HashService.TrySha256(pdfPath)??"Unavailable";
        string hashPath=pdfPath+".sha256.txt";
        await File.WriteAllTextAsync(hashPath,$"{pdfHash}  {Path.GetFileName(pdfPath)}{Environment.NewLine}",token);
        return new(){PdfPath=pdfPath,JsonPath=jsonPath,PdfHashPath=hashPath};
    }

    private static Document Build(ScanResult r)
    {
        var d=new Document();d.Info.Title="DoubleG Scanner CS2 System Integrity Report";d.Info.Author="DoubleG Scanner";d.Info.Subject=r.ScanId;
        Style normal=d.Styles["Normal"]!;normal.Font.Name="Segoe UI";normal.Font.Size=8.5;normal.Font.Color=Color.FromHex("#263246");
        Style title=d.Styles.AddStyle("DGTitle","Normal");title.Font.Size=22;title.Font.Bold=true;title.Font.Color=Color.FromHex("#111827");
        Style heading=d.Styles.AddStyle("DGHeading","Normal");heading.Font.Size=12.5;heading.Font.Bold=true;heading.Font.Color=Color.FromHex("#111827");
        heading.ParagraphFormat.SpaceBefore=Unit.FromPoint(12);heading.ParagraphFormat.SpaceAfter=Unit.FromPoint(6);

        Section s=d.AddSection();s.PageSetup.PageFormat=PageFormat.A4;s.PageSetup.TopMargin=Unit.FromCentimeter(1.55);
        s.PageSetup.BottomMargin=Unit.FromCentimeter(1.55);s.PageSetup.LeftMargin=Unit.FromCentimeter(1.55);s.PageSetup.RightMargin=Unit.FromCentimeter(1.55);
        Cover(s,r);Summary(s,r);Coverage(s,r);Findings(s,r);Timeline(s,r);
        EvidenceTable(s,r,EvidenceKind.Browser,"RELEVANT BROWSER RECORDS",80);
        EvidenceTable(s,r,EvidenceKind.DeletedFile,"DELETED-FILE METADATA",80);
        EvidenceTable(s,r,EvidenceKind.Module,"CS2 MODULE EVIDENCE",160);
        EvidenceTable(s,r,EvidenceKind.Network,"LIVE NETWORK CONNECTIONS",120);
        Integrity(s,r);Limitations(s,r);
        Paragraph footer=s.Footers.Primary.AddParagraph();footer.Format.Alignment=ParagraphAlignment.Center;footer.Format.Font.Size=7;
        footer.Format.Font.Color=Color.FromHex("#7A8495");footer.AddText($"DoubleG Scanner {r.ScannerVersion} | {r.ScanId} | Local read-only report");
        return d;
    }

    private static void Cover(Section s,ScanResult r)
    {
        Paragraph brand=s.AddParagraph();brand.Style="DGTitle";brand.AddText("DOUBLEG SCANNER");
        Paragraph sub=s.AddParagraph("CS2 SYSTEM INTEGRITY REPORT");sub.Format.Font.Size=9;sub.Format.Font.Bold=true;sub.Format.Font.Color=Color.FromHex("#667085");
        sub.Format.SpaceAfter=Unit.FromPoint(14);

        Table banner=s.AddTable();banner.AddColumn(Unit.FromCentimeter(17));Row row=banner.AddRow();
        string bg=r.Verdict switch{ScanVerdict.Detected=>"#FFF0F3",ScanVerdict.Review=>"#FFF8E7",ScanVerdict.NotDetected=>"#EAFBF4",_=>"#F1F4F8"};
        string fg=r.Verdict switch{ScanVerdict.Detected=>"#B4233D",ScanVerdict.Review=>"#946200",ScanVerdict.NotDetected=>"#16704A",_=>"#4B5565"};
        row.Cells[0].Shading.Color=Color.FromHex(bg);row.Cells[0].Borders.Color=Color.FromHex(fg);row.Cells[0].Borders.Width=Unit.FromPoint(.9);
        row.Cells[0].Format.LeftIndent=Unit.FromPoint(12);row.Cells[0].Format.RightIndent=Unit.FromPoint(12);
        row.Cells[0].Format.SpaceBefore=Unit.FromPoint(12);row.Cells[0].Format.SpaceAfter=Unit.FromPoint(12);
        Paragraph vt=row.Cells[0].AddParagraph();vt.Format.Font.Size=17;vt.Format.Font.Bold=true;vt.Format.Font.Color=Color.FromHex(fg);vt.AddText(VerdictTitle(r.Verdict));
        Paragraph vd=row.Cells[0].AddParagraph();vd.Format.SpaceBefore=Unit.FromPoint(4);vd.AddText(VerdictText(r.Verdict));
        s.AddParagraph().Format.SpaceAfter=Unit.FromPoint(5);

        Table meta=s.AddTable();meta.Borders.Color=Color.FromHex("#DDE3EC");meta.Borders.Width=Unit.FromPoint(.55);
        meta.AddColumn(Unit.FromCentimeter(4.2));meta.AddColumn(Unit.FromCentimeter(12.8));
        Meta(meta,"Scan ID",r.ScanId);Meta(meta,"Scan mode",r.Mode.ToString());Meta(meta,"Completed",r.CompletedAt.ToString("yyyy-MM-dd HH:mm:ss zzz"));
        Meta(meta,"Risk score",$"{r.RiskScore} / 200");Meta(meta,"Findings",$"{r.CriticalCount} critical, {r.HighCount} high, {r.WarningCount} warning");
        Meta(meta,"Scanner / rules",$"{r.ScannerVersion} / {r.RuleDatabaseVersion}");Meta(meta,"Access",r.IsElevated?"Administrator":"Standard user");
    }

    private static void Summary(Section s,ScanResult r)
    {
        H(s,"EXECUTIVE SUMMARY");Paragraph p=s.AddParagraph();
        p.AddText(r.Verdict switch
        {
            ScanVerdict.Detected=>"At least one high-confidence indicator was identified by exact or strongly correlated evidence. Review every critical finding before taking action.",
            ScanVerdict.Review=>"The scan was not conclusive, but evidence requiring manual review was identified. A warning or high finding is not proof by itself.",
            ScanVerdict.NotDetected=>"No known high-confidence indicator was detected by the completed modules. This does not prove that cheating never occurred.",
            _=>"The scan did not produce a reliable complete verdict. Review the coverage table and rerun if appropriate."
        });
        Table t=s.AddTable();for(int i=0;i<4;i++)t.AddColumn(Unit.FromCentimeter(4.25));
        Row h=t.AddRow();h.Shading.Color=Color.FromHex("#151B28");h.Format.Font.Color=Colors.White;h.Format.Font.Bold=true;
        string[] names={"Evidence records","Findings","Modules complete","Risk score"};for(int i=0;i<4;i++)h.Cells[i].AddParagraph(names[i]);
        Row v=t.AddRow();v.Format.Font.Size=13;v.Format.Font.Bold=true;v.Cells[0].AddParagraph(r.Evidence.Count.ToString("N0"));
        v.Cells[1].AddParagraph(r.Findings.Count.ToString("N0"));v.Cells[2].AddParagraph(r.Coverage.Count(x=>x.Status==CoverageStatus.Completed).ToString());
        v.Cells[3].AddParagraph(r.RiskScore.ToString());Format(t,6,true);
    }

    private static void Coverage(Section s,ScanResult r)
    {
        H(s,"SCAN COVERAGE");Table t=s.AddTable();t.Borders.Color=Color.FromHex("#DDE3EC");t.Borders.Width=Unit.FromPoint(.45);
        t.AddColumn(Unit.FromCentimeter(4.1));t.AddColumn(Unit.FromCentimeter(2.2));t.AddColumn(Unit.FromCentimeter(2.2));t.AddColumn(Unit.FromCentimeter(8.5));
        Header(t,"Module","Status","Checked","Summary");
        foreach(ScanCoverage x in r.Coverage){Row row=t.AddRow();row.Cells[0].AddParagraph(x.Module);row.Cells[1].AddParagraph(x.Status.ToString());
            row.Cells[2].AddParagraph(x.ItemsChecked.ToString("N0"));row.Cells[3].AddParagraph(x.Summary);}
        Format(t,4,false);
    }

    private static void Findings(Section s,ScanResult r)
    {
        H(s,"FINDINGS");if(r.Findings.Count==0){s.AddParagraph("No warning, high, or critical findings were produced by the completed rules.");return;}
        int i=0;foreach(ScanFinding f in r.Findings.Take(80))
        {
            i++;Table t=s.AddTable();t.AddColumn(Unit.FromCentimeter(17));Row row=t.AddRow();
            string color=f.Severity switch{FindingSeverity.Critical=>"#C52847",FindingSeverity.High=>"#D85A30",FindingSeverity.Warning=>"#B57900",_=>"#4B647D"};
            Cell c=row.Cells[0];c.Borders.Color=Color.FromHex(color);c.Borders.Width=Unit.FromPoint(.8);c.Shading.Color=Color.FromHex("#FAFBFD");
            c.Format.LeftIndent=Unit.FromPoint(8);c.Format.RightIndent=Unit.FromPoint(8);c.Format.SpaceBefore=Unit.FromPoint(7);c.Format.SpaceAfter=Unit.FromPoint(7);
            Paragraph title=c.AddParagraph();title.Format.Font.Size=10.5;title.Format.Font.Bold=true;title.Format.Font.Color=Color.FromHex(color);
            title.AddText($"FINDING {i:00} - {f.Severity.ToString().ToUpperInvariant()} - {f.Title}");
            c.AddParagraph($"Rule: {f.RuleId} | Score: {f.Score} | Source: {f.EvidenceSource}");c.AddParagraph(f.Summary);
            if(!string.IsNullOrWhiteSpace(f.Path))c.AddParagraph("Artifact: "+f.Path);if(!string.IsNullOrWhiteSpace(f.HashSha256))c.AddParagraph("SHA-256: "+f.HashSha256);
            if(f.Timestamp is not null)c.AddParagraph("Time: "+f.Timestamp.Value.ToString("yyyy-MM-dd HH:mm:ss zzz"));
            if(f.Reasons.Count>0)c.AddParagraph("Reasons: "+string.Join("; ",f.Reasons));s.AddParagraph().Format.SpaceAfter=Unit.FromPoint(2);
        }
    }

    private static void Timeline(Section s,ScanResult r)
    {
        EvidenceRecord[] items=r.Evidence.Where(x=>x.Timestamp is not null&&(x.Kind==EvidenceKind.Browser||x.Kind==EvidenceKind.Execution||
            x.Kind==EvidenceKind.DeletedFile||x.Kind==EvidenceKind.Process)).OrderByDescending(x=>x.Timestamp).Take(120).ToArray();
        if(items.Length==0)return;H(s,"RECENT ACTIVITY TIMELINE");Table t=s.AddTable();t.Borders.Color=Color.FromHex("#E0E5ED");t.Borders.Width=Unit.FromPoint(.4);
        t.AddColumn(Unit.FromCentimeter(3.2));t.AddColumn(Unit.FromCentimeter(2.6));t.AddColumn(Unit.FromCentimeter(4));t.AddColumn(Unit.FromCentimeter(7.2));
        Header(t,"Time","Type","Name","Artifact / detail");foreach(EvidenceRecord x in items){Row row=t.AddRow();row.Cells[0].AddParagraph(x.Timestamp!.Value.ToString("yyyy-MM-dd HH:mm"));
            row.Cells[1].AddParagraph(x.Kind.ToString());row.Cells[2].AddParagraph(x.Name);row.Cells[3].AddParagraph(x.Path??x.Url??x.Detail??"");}Format(t,3.8,false);
    }

    private static void EvidenceTable(Section s,ScanResult r,EvidenceKind kind,string title,int limit)
    {
        EvidenceRecord[] items=r.Evidence.Where(x=>x.Kind==kind).Take(limit).ToArray();if(items.Length==0)return;H(s,title);
        Table t=s.AddTable();t.Borders.Color=Color.FromHex("#E0E5ED");t.Borders.Width=Unit.FromPoint(.4);
        t.AddColumn(Unit.FromCentimeter(3.3));t.AddColumn(Unit.FromCentimeter(4));t.AddColumn(Unit.FromCentimeter(9.7));Header(t,"Source","Name","Artifact / detail");
        foreach(EvidenceRecord x in items){Row row=t.AddRow();row.Cells[0].AddParagraph(x.Source);row.Cells[1].AddParagraph(x.Name);row.Cells[2].AddParagraph(x.Path??x.Url??x.Detail??"");}
        Format(t,3.8,false);
    }

    private static void Integrity(Section s,ScanResult r)
    {
        H(s,"REPORT AND SCANNER INTEGRITY");Table t=s.AddTable();t.Borders.Color=Color.FromHex("#DDE3EC");t.Borders.Width=Unit.FromPoint(.45);
        t.AddColumn(Unit.FromCentimeter(4.4));t.AddColumn(Unit.FromCentimeter(12.6));Meta(t,"Scanner binary SHA-256",r.ScannerBinaryHash);
        Meta(t,"Evidence JSON SHA-256",r.EvidenceJsonHash??"Unavailable");Meta(t,"Rule database",r.RuleDatabaseVersion);Meta(t,"Privacy mode","Local-only / read-only / no upload / no deletion");
    }
    private static void Limitations(Section s,ScanResult r)
    {
        H(s,"IMPORTANT INTERPRETATION AND LIMITATIONS");Paragraph p=s.AddParagraph();
        p.AddFormattedText("This report is evidence-based, not an automatic punishment decision. ",TextFormat.Bold);
        p.AddText("A naming match or browser entry is not proof. Exact hashes and independent correlation carry more weight. ");
        p.AddText("Not detected means completed modules found no known high-confidence indicator; it does not prove cheating never occurred. ");
        p.AddText("This build does not install a kernel driver, recover arbitrary private deleted content, or claim reliable detection of every DMA/kernel technique. ");
        p.AddText(r.PrivacyStatement);
    }

    private static void H(Section s,string text){Paragraph h=s.AddParagraph(text);h.Style="DGHeading";}
    private static void Meta(Table t,string name,string value){Row r=t.AddRow();r.Cells[0].Shading.Color=Color.FromHex("#F3F6FA");r.Cells[0].Format.Font.Bold=true;
        r.Cells[0].AddParagraph(name);r.Cells[1].AddParagraph(value);foreach(Cell c in r.Cells){c.VerticalAlignment=VerticalAlignment.Center;c.Format.LeftIndent=Unit.FromPoint(5);c.Format.SpaceBefore=Unit.FromPoint(4);c.Format.SpaceAfter=Unit.FromPoint(4);}}
    private static void Header(Table t,params string[] names){Row r=t.AddRow();r.Shading.Color=Color.FromHex("#151B28");r.Format.Font.Color=Colors.White;r.Format.Font.Bold=true;
        for(int i=0;i<names.Length;i++)r.Cells[i].AddParagraph(names[i]);}
    private static void Format(Table t,double pad,bool center){foreach(Row r in t.Rows)foreach(Cell c in r.Cells){c.VerticalAlignment=VerticalAlignment.Center;c.Format.SpaceBefore=Unit.FromPoint(pad);c.Format.SpaceAfter=Unit.FromPoint(pad);c.Format.LeftIndent=Unit.FromPoint(3);if(center)c.Format.Alignment=ParagraphAlignment.Center;}}
    private static string VerdictTitle(ScanVerdict v)=>v switch{ScanVerdict.Detected=>"CHEAT INDICATORS DETECTED",ScanVerdict.Review=>"MANUAL REVIEW REQUIRED",
        ScanVerdict.NotDetected=>"NO KNOWN INDICATOR DETECTED",ScanVerdict.Cancelled=>"SCAN CANCELLED",_=>"SCAN INCOMPLETE"};
    private static string VerdictText(ScanVerdict v)=>v switch{ScanVerdict.Detected=>"At least one high-confidence indicator was detected. Review evidence and context before action.",
        ScanVerdict.Review=>"The evidence is not conclusive, but knowledgeable manual review is required.",ScanVerdict.NotDetected=>"No known high-confidence indicator was detected by completed modules.",
        ScanVerdict.Cancelled=>"The user cancelled before a reliable result was produced.",_=>"Required modules could not be completed; no reliable verdict was produced."};
}
