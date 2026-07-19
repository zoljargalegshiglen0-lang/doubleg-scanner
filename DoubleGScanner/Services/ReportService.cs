using System.Text.Json;
using DoubleGScanner.Models;
using MigraDoc.DocumentObjectModel;
using MigraDoc.DocumentObjectModel.Tables;
using MigraDoc.Rendering;

namespace DoubleGScanner.Services;

public sealed class ReportService
{
    public async Task<ReportBundle> CreateAsync(ScanResult result, CancellationToken token)
    {
        string directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            "DoubleG Scanner", "Reports", result.ScanId);
        Directory.CreateDirectory(directory);

        string jsonPath = Path.Combine(directory, $"DoubleG-Scanner_Evidence_{result.ScanId}.json");
        string json = JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(jsonPath, json, token);
        result.EvidenceJsonHash = HashService.TrySha256(jsonPath) ?? "Unavailable";

        string pdfPath = Path.Combine(directory, $"DoubleG-Scanner_Report_{result.ScanId}.pdf");
        var renderer = new PdfDocumentRenderer { Document = Build(result) };
        renderer.RenderDocument();
        renderer.PdfDocument.Save(pdfPath);

        string pdfHash = HashService.TrySha256(pdfPath) ?? "Unavailable";
        string hashPath = pdfPath + ".sha256.txt";
        await File.WriteAllTextAsync(hashPath, $"{pdfHash}  {Path.GetFileName(pdfPath)}{Environment.NewLine}", token);
        return new ReportBundle { PdfPath = pdfPath, JsonPath = jsonPath, PdfHashPath = hashPath };
    }

    private static Document Build(ScanResult result)
    {
        var document = new Document();
        document.Info.Title = "DoubleG Scanner CS2 System Integrity Report";
        document.Info.Author = "DoubleG Team";
        document.Info.Subject = result.ScanId;

        Style normal = document.Styles["Normal"]!;
        normal.Font.Name = "Segoe UI";
        normal.Font.Size = 8.5;
        normal.Font.Color = Color.Parse("#2B2530");

        Style title = document.Styles.AddStyle("DGTitle", "Normal");
        title.Font.Size = 22;
        title.Font.Bold = true;
        title.Font.Color = Color.Parse("#B51620");

        Style heading = document.Styles.AddStyle("DGHeading", "Normal");
        heading.Font.Size = 12.5;
        heading.Font.Bold = true;
        heading.Font.Color = Color.Parse("#271416");
        heading.ParagraphFormat.SpaceBefore = Unit.FromPoint(12);
        heading.ParagraphFormat.SpaceAfter = Unit.FromPoint(6);

        Section section = document.AddSection();
        section.PageSetup.PageFormat = PageFormat.A4;
        section.PageSetup.TopMargin = Unit.FromCentimeter(1.5);
        section.PageSetup.BottomMargin = Unit.FromCentimeter(1.5);
        section.PageSetup.LeftMargin = Unit.FromCentimeter(1.5);
        section.PageSetup.RightMargin = Unit.FromCentimeter(1.5);

        Cover(section, result);
        Summary(section, result);
        Coverage(section, result);
        Findings(section, result);
        Timeline(section, result);
        EvidenceTable(section, result, EvidenceKind.KernelSecurity, "KERNEL SECURITY POSTURE", 20);
        EvidenceTable(section, result, EvidenceKind.KernelDriver, "LOADED KERNEL DRIVERS", 240);
        EvidenceTable(section, result, EvidenceKind.CodeIntegrity, "CODE INTEGRITY / DRIVER EVENTS", 180);
        EvidenceTable(section, result, EvidenceKind.Antivirus, "MICROSOFT DEFENDER DETECTIONS", 80);
        EvidenceTable(section, result, EvidenceKind.Browser, "RELEVANT BROWSER RECORDS", 80);
        EvidenceTable(section, result, EvidenceKind.DeletedFile, "RECYCLE BIN DELETED-FILE METADATA", 80);
        EvidenceTable(section, result, EvidenceKind.UsnJournal, "NTFS USN CHANGE / DELETION EVENTS", 120);
        EvidenceTable(section, result, EvidenceKind.NtfsMetadata, "NTFS MFT METADATA", 100);
        EvidenceTable(section, result, EvidenceKind.RawDeletedFile, "UNALLOCATED EXECUTABLE / ARCHIVE SIGNATURES", 100);
        EvidenceTable(section, result, EvidenceKind.Module, "CS2 MODULE EVIDENCE", 160);
        Integrity(section, result);
        Limitations(section, result);

        Paragraph footer = section.Footers.Primary.AddParagraph();
        footer.Format.Alignment = ParagraphAlignment.Center;
        footer.Format.Font.Size = 7;
        footer.Format.Font.Color = Color.Parse("#8A7470");
        footer.AddText($"DoubleG Scanner {result.ScannerVersion} | {result.ScanId} | Made by DoubleG Team");
        return document;
    }

    private static void Cover(Section section, ScanResult result)
    {
        Paragraph brand = section.AddParagraph();
        brand.Style = "DGTitle";
        brand.AddText("DOUBLEG SCANNER");

        Paragraph subtitle = section.AddParagraph("CS2 SYSTEM INTEGRITY REPORT");
        subtitle.Format.Font.Size = 9;
        subtitle.Format.Font.Bold = true;
        subtitle.Format.Font.Color = Color.Parse("#8A6F6B");
        subtitle.Format.SpaceAfter = Unit.FromPoint(14);

        Table banner = section.AddTable();
        banner.AddColumn(Unit.FromCentimeter(17));
        Row row = banner.AddRow();
        string background = result.Verdict switch
        {
            ScanVerdict.Detected => "#FFF0F3",
            ScanVerdict.Review => "#FFF8E7",
            ScanVerdict.NotDetected => "#EAFBF4",
            _ => "#F1F4F8"
        };
        string foreground = result.Verdict switch
        {
            ScanVerdict.Detected => "#B4233D",
            ScanVerdict.Review => "#946200",
            ScanVerdict.NotDetected => "#16704A",
            _ => "#4B5565"
        };
        row.Cells[0].Shading.Color = Color.Parse(background);
        row.Cells[0].Borders.Color = Color.Parse(foreground);
        row.Cells[0].Borders.Width = Unit.FromPoint(0.9);
        row.Cells[0].Format.LeftIndent = Unit.FromPoint(12);
        row.Cells[0].Format.RightIndent = Unit.FromPoint(12);
        row.Cells[0].Format.SpaceBefore = Unit.FromPoint(12);
        row.Cells[0].Format.SpaceAfter = Unit.FromPoint(12);

        Paragraph verdictTitle = row.Cells[0].AddParagraph();
        verdictTitle.Format.Font.Size = 17;
        verdictTitle.Format.Font.Bold = true;
        verdictTitle.Format.Font.Color = Color.Parse(foreground);
        verdictTitle.AddText(VerdictTitle(result.Verdict));

        Paragraph verdictText = row.Cells[0].AddParagraph();
        verdictText.Format.SpaceBefore = Unit.FromPoint(4);
        verdictText.AddText(VerdictText(result.Verdict));
        section.AddParagraph().Format.SpaceAfter = Unit.FromPoint(5);

        Table metadata = section.AddTable();
        metadata.Borders.Color = Color.Parse("#E5D8D6");
        metadata.Borders.Width = Unit.FromPoint(0.55);
        metadata.AddColumn(Unit.FromCentimeter(4.5));
        metadata.AddColumn(Unit.FromCentimeter(12.5));
        Meta(metadata, "Scan ID", result.ScanId);
        Meta(metadata, "Scan mode", result.Mode.ToString());
        Meta(metadata, "Completed", result.CompletedAt.ToString("yyyy-MM-dd HH:mm:ss zzz"));
        Meta(metadata, "Risk score", $"{result.RiskScore} / 200");
        Meta(metadata, "Findings", $"{result.CriticalCount} critical, {result.HighCount} high, {result.WarningCount} warning");
        Meta(metadata, "Scanner / rules", $"{result.ScannerVersion} / {result.RuleDatabaseVersion}");
        Meta(metadata, "Access", result.IsElevated ? "Administrator" : "Standard user");
    }

    private static void Summary(Section section, ScanResult result)
    {
        H(section, "EXECUTIVE SUMMARY");
        Paragraph paragraph = section.AddParagraph();
        paragraph.AddText(result.Verdict switch
        {
            ScanVerdict.Detected => "At least one high-confidence indicator was identified. Review every critical finding before taking action.",
            ScanVerdict.Review => "The scan was not conclusive, but evidence requiring manual review was identified.",
            ScanVerdict.NotDetected => "No known high-confidence indicator was detected by the completed modules.",
            _ => "The scan did not produce a reliable complete verdict."
        });

        Table table = section.AddTable();
        for (int i = 0; i < 4; i++) table.AddColumn(Unit.FromCentimeter(4.25));
        Row header = table.AddRow();
        header.Shading.Color = Color.Parse("#281416");
        header.Format.Font.Color = Colors.White;
        header.Format.Font.Bold = true;
        string[] names = { "Evidence", "Findings", "Modules", "Risk" };
        for (int i = 0; i < names.Length; i++) header.Cells[i].AddParagraph(names[i]);
        Row values = table.AddRow();
        values.Format.Font.Size = 13;
        values.Format.Font.Bold = true;
        values.Cells[0].AddParagraph(result.Evidence.Count.ToString("N0"));
        values.Cells[1].AddParagraph(result.Findings.Count.ToString("N0"));
        values.Cells[2].AddParagraph(result.Coverage.Count(x => x.Status == CoverageStatus.Completed).ToString());
        values.Cells[3].AddParagraph(result.RiskScore.ToString());
        Format(table, 6, true);
    }

    private static void Coverage(Section section, ScanResult result)
    {
        H(section, "SCAN COVERAGE");
        Table table = section.AddTable();
        table.Borders.Color = Color.Parse("#E5D8D6");
        table.Borders.Width = Unit.FromPoint(0.45);
        table.AddColumn(Unit.FromCentimeter(4.1));
        table.AddColumn(Unit.FromCentimeter(2.2));
        table.AddColumn(Unit.FromCentimeter(2.2));
        table.AddColumn(Unit.FromCentimeter(8.5));
        Header(table, "Module", "Status", "Checked", "Summary");
        foreach (ScanCoverage coverage in result.Coverage)
        {
            Row row = table.AddRow();
            row.Cells[0].AddParagraph(coverage.Module);
            row.Cells[1].AddParagraph(coverage.Status.ToString());
            row.Cells[2].AddParagraph(coverage.ItemsChecked.ToString("N0"));
            row.Cells[3].AddParagraph(coverage.Summary);
        }
        Format(table, 4, false);
    }

    private static void Findings(Section section, ScanResult result)
    {
        H(section, "FINDINGS");
        if (result.Findings.Count == 0)
        {
            section.AddParagraph("No warning, high, or critical findings were produced.");
            return;
        }

        int index = 0;
        foreach (ScanFinding finding in result.Findings.Take(80))
        {
            index++;
            Table table = section.AddTable();
            table.AddColumn(Unit.FromCentimeter(17));
            Row row = table.AddRow();
            string color = finding.Severity switch
            {
                FindingSeverity.Critical => "#C91F35",
                FindingSeverity.High => "#D44A32",
                FindingSeverity.Warning => "#A86C00",
                _ => "#69585A"
            };
            Cell cell = row.Cells[0];
            cell.Borders.Color = Color.Parse(color);
            cell.Borders.Width = Unit.FromPoint(0.8);
            cell.Shading.Color = Color.Parse("#FFFDFC");
            cell.Format.LeftIndent = Unit.FromPoint(8);
            cell.Format.RightIndent = Unit.FromPoint(8);
            cell.Format.SpaceBefore = Unit.FromPoint(7);
            cell.Format.SpaceAfter = Unit.FromPoint(7);

            Paragraph title = cell.AddParagraph();
            title.Format.Font.Size = 10.5;
            title.Format.Font.Bold = true;
            title.Format.Font.Color = Color.Parse(color);
            title.AddText($"FINDING {index:00} - {finding.Severity.ToString().ToUpperInvariant()} - {finding.Title}");

            cell.AddParagraph($"Rule: {finding.RuleId} | Score: {finding.Score} | Source: {finding.EvidenceSource}");
            cell.AddParagraph(finding.Summary);
            if (!string.IsNullOrWhiteSpace(finding.DetectedCheatName))
                Label(cell, "Detected cheat", finding.DetectedCheatName);
            if (!string.IsNullOrWhiteSpace(finding.CheatFamily))
                Label(cell, "Cheat family", finding.CheatFamily);
            if (!string.IsNullOrWhiteSpace(finding.DetectionMethod))
                Label(cell, "Detection method", finding.DetectionMethod);
            if (!string.IsNullOrWhiteSpace(finding.Path))
                Label(cell, "Artifact path", finding.Path);
            if (!string.IsNullOrWhiteSpace(finding.HashSha256))
                Label(cell, "SHA-256", finding.HashSha256);
            if (finding.Timestamp is not null)
                Label(cell, "Time", finding.Timestamp.Value.ToString("yyyy-MM-dd HH:mm:ss zzz"));
            if (finding.Reasons.Count > 0)
                Label(cell, "Reasons", string.Join("; ", finding.Reasons));
            section.AddParagraph().Format.SpaceAfter = Unit.FromPoint(2);
        }
    }

    private static void Timeline(Section section, ScanResult result)
    {
        EvidenceRecord[] items = result.Evidence
            .Where(x => x.Timestamp is not null && (x.Kind == EvidenceKind.Browser || x.Kind == EvidenceKind.Execution ||
                x.Kind == EvidenceKind.DeletedFile || x.Kind == EvidenceKind.UsnJournal || x.Kind == EvidenceKind.RawDeletedFile ||
                x.Kind == EvidenceKind.NtfsMetadata || x.Kind == EvidenceKind.CodeIntegrity ||
                x.Kind == EvidenceKind.KernelDriver || x.Kind == EvidenceKind.Process || x.Kind == EvidenceKind.Antivirus))
            .OrderByDescending(x => x.Timestamp)
            .Take(120)
            .ToArray();
        if (items.Length == 0) return;

        H(section, "RECENT ACTIVITY TIMELINE");
        Table table = section.AddTable();
        table.Borders.Color = Color.Parse("#E8DCDA");
        table.Borders.Width = Unit.FromPoint(0.4);
        table.AddColumn(Unit.FromCentimeter(3.2));
        table.AddColumn(Unit.FromCentimeter(2.6));
        table.AddColumn(Unit.FromCentimeter(4));
        table.AddColumn(Unit.FromCentimeter(7.2));
        Header(table, "Time", "Type", "Name", "Artifact / detail");
        foreach (EvidenceRecord item in items)
        {
            Row row = table.AddRow();
            row.Cells[0].AddParagraph(item.Timestamp!.Value.ToString("yyyy-MM-dd HH:mm"));
            row.Cells[1].AddParagraph(item.Kind.ToString());
            row.Cells[2].AddParagraph(item.Name);
            row.Cells[3].AddParagraph(item.Path ?? item.Url ?? item.Detail ?? "");
        }
        Format(table, 3.8, false);
    }

    private static void EvidenceTable(Section section, ScanResult result, EvidenceKind kind, string title, int limit)
    {
        EvidenceRecord[] items = result.Evidence.Where(x => x.Kind == kind).Take(limit).ToArray();
        if (items.Length == 0) return;
        H(section, title);
        Table table = section.AddTable();
        table.Borders.Color = Color.Parse("#E8DCDA");
        table.Borders.Width = Unit.FromPoint(0.4);
        table.AddColumn(Unit.FromCentimeter(3.3));
        table.AddColumn(Unit.FromCentimeter(4));
        table.AddColumn(Unit.FromCentimeter(9.7));
        Header(table, "Source", "Name", "Artifact / detail");
        foreach (EvidenceRecord item in items)
        {
            Row row = table.AddRow();
            row.Cells[0].AddParagraph(item.Source);
            row.Cells[1].AddParagraph(item.Name);
            row.Cells[2].AddParagraph(item.Path ?? item.Url ?? item.Detail ?? "");
        }
        Format(table, 3.8, false);
    }

    private static void Integrity(Section section, ScanResult result)
    {
        H(section, "REPORT INTEGRITY");
        Table table = section.AddTable();
        table.Borders.Color = Color.Parse("#E5D8D6");
        table.Borders.Width = Unit.FromPoint(0.45);
        table.AddColumn(Unit.FromCentimeter(4.6));
        table.AddColumn(Unit.FromCentimeter(12.4));
        Meta(table, "Scanner binary SHA-256", result.ScannerBinaryHash);
        Meta(table, "Evidence JSON SHA-256", result.EvidenceJsonHash ?? "Unavailable");
        Meta(table, "Rule database", result.RuleDatabaseVersion);
        Meta(table, "Privacy mode", "Local-only / read-only / no upload / no deletion");
    }

    private static void Limitations(Section section, ScanResult result)
    {
        H(section, "IMPORTANT INTERPRETATION");
        Paragraph english = section.AddParagraph();
        english.AddFormattedText("This report is evidence-based, not an automatic punishment decision. ", TextFormat.Bold);
        english.AddText("A name match or browser entry alone is not proof. Exact hashes, antivirus detections, technical indicators, and independent correlation carry more weight. ");
        english.AddText("Not detected does not prove that cheating never occurred. ");
        english.AddText(result.PrivacyStatement);

    }

    private static void H(Section section, string text)
    {
        Paragraph heading = section.AddParagraph(text);
        heading.Style = "DGHeading";
    }

    private static void Label(Cell cell, string label, string value)
    {
        Paragraph paragraph = cell.AddParagraph();
        paragraph.AddFormattedText(label + ": ", TextFormat.Bold);
        paragraph.AddText(value);
    }

    private static void Meta(Table table, string name, string value)
    {
        Row row = table.AddRow();
        row.Cells[0].Shading.Color = Color.Parse("#F8F2F0");
        row.Cells[0].Format.Font.Bold = true;
        row.Cells[0].AddParagraph(name);
        row.Cells[1].AddParagraph(value);
        foreach (Cell cell in row.Cells)
        {
            cell.VerticalAlignment = VerticalAlignment.Center;
            cell.Format.LeftIndent = Unit.FromPoint(5);
            cell.Format.SpaceBefore = Unit.FromPoint(4);
            cell.Format.SpaceAfter = Unit.FromPoint(4);
        }
    }

    private static void Header(Table table, params string[] names)
    {
        Row row = table.AddRow();
        row.Shading.Color = Color.Parse("#281416");
        row.Format.Font.Color = Colors.White;
        row.Format.Font.Bold = true;
        for (int i = 0; i < names.Length; i++) row.Cells[i].AddParagraph(names[i]);
    }

    private static void Format(Table table, double padding, bool center)
    {
        foreach (Row row in table.Rows)
        foreach (Cell cell in row.Cells)
        {
            cell.VerticalAlignment = VerticalAlignment.Center;
            cell.Format.SpaceBefore = Unit.FromPoint(padding);
            cell.Format.SpaceAfter = Unit.FromPoint(padding);
            cell.Format.LeftIndent = Unit.FromPoint(3);
            if (center) cell.Format.Alignment = ParagraphAlignment.Center;
        }
    }

    private static string VerdictTitle(ScanVerdict verdict) => verdict switch
    {
        ScanVerdict.Detected => "CHEAT INDICATORS DETECTED",
        ScanVerdict.Review => "MANUAL REVIEW REQUIRED",
        ScanVerdict.NotDetected => "NO KNOWN INDICATOR DETECTED",
        ScanVerdict.Cancelled => "SCAN CANCELLED",
        _ => "SCAN INCOMPLETE"
    };

    private static string VerdictText(ScanVerdict verdict) => verdict switch
    {
        ScanVerdict.Detected => "At least one high-confidence indicator was detected. Review the evidence before action.",
        ScanVerdict.Review => "The evidence is not conclusive, but manual review is required.",
        ScanVerdict.NotDetected => "No known high-confidence indicator was detected by completed modules.",
        ScanVerdict.Cancelled => "The scan was cancelled before a reliable result was produced.",
        _ => "Required modules could not be completed; no reliable verdict was produced."
    };
}
