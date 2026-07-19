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
        EvidenceTable(section, result, EvidenceKind.Antivirus, "MICROSOFT DEFENDER DETECTIONS / DEFENDER ИЛРҮҮЛЭЛТ", 80);
        EvidenceTable(section, result, EvidenceKind.Browser, "RELEVANT BROWSER RECORDS / BROWSER БҮРТГЭЛ", 80);
        EvidenceTable(section, result, EvidenceKind.DeletedFile, "DELETED-FILE METADATA / УСТГАСАН ФАЙЛЫН МӨР", 80);
        EvidenceTable(section, result, EvidenceKind.Module, "CS2 MODULE EVIDENCE / CS2 MODULE НОТОЛГОО", 160);
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

        Paragraph subtitle = section.AddParagraph("CS2 SYSTEM INTEGRITY REPORT / СИСТЕМИЙН ШАЛГАЛТЫН ТАЙЛАН");
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
        verdictText.AddLineBreak();
        verdictText.AddFormattedText(MongolianVerdictText(result.Verdict), TextFormat.Bold);
        section.AddParagraph().Format.SpaceAfter = Unit.FromPoint(5);

        Table metadata = section.AddTable();
        metadata.Borders.Color = Color.Parse("#E5D8D6");
        metadata.Borders.Width = Unit.FromPoint(0.55);
        metadata.AddColumn(Unit.FromCentimeter(4.5));
        metadata.AddColumn(Unit.FromCentimeter(12.5));
        Meta(metadata, "Scan ID / Шалгалтын ID", result.ScanId);
        Meta(metadata, "Scan mode / Горим", result.Mode.ToString());
        Meta(metadata, "Completed / Дууссан", result.CompletedAt.ToString("yyyy-MM-dd HH:mm:ss zzz"));
        Meta(metadata, "Risk score / Эрсдэлийн оноо", $"{result.RiskScore} / 200");
        Meta(metadata, "Findings / Илэрсэн зүйл", $"{result.CriticalCount} critical, {result.HighCount} high, {result.WarningCount} warning");
        Meta(metadata, "Scanner / rules", $"{result.ScannerVersion} / {result.RuleDatabaseVersion}");
        Meta(metadata, "Access / Эрх", result.IsElevated ? "Administrator" : "Standard user");
    }

    private static void Summary(Section section, ScanResult result)
    {
        H(section, "EXECUTIVE SUMMARY / ТОВЧ ДҮГНЭЛТ");
        Paragraph paragraph = section.AddParagraph();
        paragraph.AddText(result.Verdict switch
        {
            ScanVerdict.Detected => "At least one high-confidence indicator was identified. Review every critical finding before taking action.",
            ScanVerdict.Review => "The scan was not conclusive, but evidence requiring manual review was identified.",
            ScanVerdict.NotDetected => "No known high-confidence indicator was detected by the completed modules.",
            _ => "The scan did not produce a reliable complete verdict."
        });
        paragraph.AddLineBreak();
        paragraph.AddFormattedText(MongolianVerdictText(result.Verdict), TextFormat.Bold);

        Table table = section.AddTable();
        for (int i = 0; i < 4; i++) table.AddColumn(Unit.FromCentimeter(4.25));
        Row header = table.AddRow();
        header.Shading.Color = Color.Parse("#281416");
        header.Format.Font.Color = Colors.White;
        header.Format.Font.Bold = true;
        string[] names = { "Evidence / Нотолгоо", "Findings / Олдвор", "Modules / Модуль", "Risk / Эрсдэл" };
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
        H(section, "SCAN COVERAGE / ШАЛГАСАН ХЭСГҮҮД");
        Table table = section.AddTable();
        table.Borders.Color = Color.Parse("#E5D8D6");
        table.Borders.Width = Unit.FromPoint(0.45);
        table.AddColumn(Unit.FromCentimeter(4.1));
        table.AddColumn(Unit.FromCentimeter(2.2));
        table.AddColumn(Unit.FromCentimeter(2.2));
        table.AddColumn(Unit.FromCentimeter(8.5));
        Header(table, "Module / Модуль", "Status / Төлөв", "Checked / Тоо", "Summary / Тайлбар");
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
        H(section, "FINDINGS / ИЛЭРСЭН ЗҮЙЛС");
        if (result.Findings.Count == 0)
        {
            section.AddParagraph("No warning, high, or critical findings were produced. / Анхааруулах эсвэл өндөр эрсдэлтэй олдвор илрээгүй.");
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
                Label(cell, "Detected cheat / Илэрсэн cheat", finding.DetectedCheatName);
            if (!string.IsNullOrWhiteSpace(finding.CheatFamily))
                Label(cell, "Cheat family / Cheat төрөл", finding.CheatFamily);
            if (!string.IsNullOrWhiteSpace(finding.DetectionMethod))
                Label(cell, "Detection method / Илрүүлсэн арга", finding.DetectionMethod);
            if (!string.IsNullOrWhiteSpace(finding.Path))
                Label(cell, "Artifact path / Файлын зам", finding.Path);
            if (!string.IsNullOrWhiteSpace(finding.HashSha256))
                Label(cell, "SHA-256", finding.HashSha256);
            if (finding.Timestamp is not null)
                Label(cell, "Time / Хугацаа", finding.Timestamp.Value.ToString("yyyy-MM-dd HH:mm:ss zzz"));
            if (finding.Reasons.Count > 0)
                Label(cell, "Reasons / Шалтгаан", string.Join("; ", finding.Reasons));

            if (finding.RuleId.StartsWith("DGS-NAMED", StringComparison.OrdinalIgnoreCase))
            {
                Paragraph explanation = cell.AddParagraph();
                explanation.Format.SpaceBefore = Unit.FromPoint(4);
                explanation.AddFormattedText("Монгол тайлбар: ", TextFormat.Bold);
                explanation.AddText(finding.Severity == FindingSeverity.Critical
                    ? "Танигдсан cheat-ийн нэр файлын нэр эсвэл мөрөнд таарч, нэмэлт техникийн нотолгоотой давхцсан."
                    : "Cheat-ийн нэртэй төстэй мөр илэрсэн боловч зөвхөн нэрээр нь 100% батлах боломжгүй тул гараар нягтална.");
            }
            section.AddParagraph().Format.SpaceAfter = Unit.FromPoint(2);
        }
    }

    private static void Timeline(Section section, ScanResult result)
    {
        EvidenceRecord[] items = result.Evidence
            .Where(x => x.Timestamp is not null && (x.Kind == EvidenceKind.Browser || x.Kind == EvidenceKind.Execution ||
                x.Kind == EvidenceKind.DeletedFile || x.Kind == EvidenceKind.Process || x.Kind == EvidenceKind.Antivirus))
            .OrderByDescending(x => x.Timestamp)
            .Take(120)
            .ToArray();
        if (items.Length == 0) return;

        H(section, "RECENT ACTIVITY TIMELINE / СҮҮЛИЙН ҮЙЛДЛИЙН ДАРААЛАЛ");
        Table table = section.AddTable();
        table.Borders.Color = Color.Parse("#E8DCDA");
        table.Borders.Width = Unit.FromPoint(0.4);
        table.AddColumn(Unit.FromCentimeter(3.2));
        table.AddColumn(Unit.FromCentimeter(2.6));
        table.AddColumn(Unit.FromCentimeter(4));
        table.AddColumn(Unit.FromCentimeter(7.2));
        Header(table, "Time / Хугацаа", "Type / Төрөл", "Name / Нэр", "Artifact / detail");
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
        Header(table, "Source / Эх үүсвэр", "Name / Нэр", "Artifact / detail");
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
        H(section, "REPORT INTEGRITY / ТАЙЛАНГИЙН БҮРЭН БАЙДАЛ");
        Table table = section.AddTable();
        table.Borders.Color = Color.Parse("#E5D8D6");
        table.Borders.Width = Unit.FromPoint(0.45);
        table.AddColumn(Unit.FromCentimeter(4.6));
        table.AddColumn(Unit.FromCentimeter(12.4));
        Meta(table, "Scanner binary SHA-256", result.ScannerBinaryHash);
        Meta(table, "Evidence JSON SHA-256", result.EvidenceJsonHash ?? "Unavailable");
        Meta(table, "Rule database / Дүрмийн сан", result.RuleDatabaseVersion);
        Meta(table, "Privacy mode / Нууцлал", "Local-only / read-only / no upload / no deletion");
    }

    private static void Limitations(Section section, ScanResult result)
    {
        H(section, "IMPORTANT INTERPRETATION / ЧУХАЛ ТАЙЛБАР");
        Paragraph english = section.AddParagraph();
        english.AddFormattedText("This report is evidence-based, not an automatic punishment decision. ", TextFormat.Bold);
        english.AddText("A name match or browser entry alone is not proof. Exact hashes, antivirus detections, technical indicators, and independent correlation carry more weight. ");
        english.AddText("Not detected does not prove that cheating never occurred. ");
        english.AddText(result.PrivacyStatement);

        Paragraph mongolian = section.AddParagraph();
        mongolian.Format.SpaceBefore = Unit.FromPoint(6);
        mongolian.AddFormattedText("Монгол тайлбар: ", TextFormat.Bold);
        mongolian.AddText("“Илрээгүй” гэдэг нь 100% cheat байхгүйг батлахгүй. “Review” нь сэжигтэй олдворыг гараар нягтлах шаардлагатай гэсэн үг. ");
        mongolian.AddText("“Detected” нь exact hash, Defender илрүүлэлт, CS2 module эсвэл олон эх үүсвэрийн хүчтэй давхцсан нотолгоо илэрснийг заана. ");
        mongolian.AddText("DoubleG Scanner файл устгахгүй, quarantine хийхгүй, нууц үг болон cookie уншихгүй.");
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
        ScanVerdict.Detected => "CHEAT INDICATORS DETECTED / CHEAT ИЛЭРСЭН",
        ScanVerdict.Review => "MANUAL REVIEW REQUIRED / ГАРААР НЯГТАЛНА",
        ScanVerdict.NotDetected => "NO KNOWN INDICATOR DETECTED / ШУУД ИЛРЭЭГҮЙ",
        ScanVerdict.Cancelled => "SCAN CANCELLED / ШАЛГАЛТ ЦУЦЛАГДСАН",
        _ => "SCAN INCOMPLETE / ШАЛГАЛТ ДУТУУ"
    };

    private static string VerdictText(ScanVerdict verdict) => verdict switch
    {
        ScanVerdict.Detected => "At least one high-confidence indicator was detected. Review the evidence before action.",
        ScanVerdict.Review => "The evidence is not conclusive, but manual review is required.",
        ScanVerdict.NotDetected => "No known high-confidence indicator was detected by completed modules.",
        ScanVerdict.Cancelled => "The scan was cancelled before a reliable result was produced.",
        _ => "Required modules could not be completed; no reliable verdict was produced."
    };

    private static string MongolianVerdictText(ScanVerdict verdict) => verdict switch
    {
        ScanVerdict.Detected => "Хүчтэй нотолгоотой cheat шинж илэрсэн. Файлын нэр, зам, илрүүлсэн арга болон шалтгааныг доорх хэсгээс шалгана.",
        ScanVerdict.Review => "Сэжигтэй олдвор илэрсэн боловч дангаар нь cheat гэж батлах хангалтгүй. Гараар нягтлах шаардлагатай.",
        ScanVerdict.NotDetected => "Шалгаж дууссан модулиудаас танигдсан өндөр итгэлтэй cheat шинж шууд илрээгүй.",
        ScanVerdict.Cancelled => "Шалгалт дуусаагүй тул найдвартай үр дүн гараагүй.",
        _ => "Зарим чухал модуль дуусаагүй тул үр дүнг бүрэн гэж үзэхгүй."
    };
}
