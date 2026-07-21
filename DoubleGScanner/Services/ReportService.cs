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
        document.Info.Title = "DoubleG Scanner CS2 Forensic Report";
        document.Info.Author = "DoubleG Team";
        document.Info.Subject = result.ScanId;

        ConfigureStyles(document);

        Section section = document.AddSection();
        section.PageSetup.PageFormat = PageFormat.A4;
        section.PageSetup.TopMargin = Unit.FromCentimeter(1.3);
        section.PageSetup.BottomMargin = Unit.FromCentimeter(1.3);
        section.PageSetup.LeftMargin = Unit.FromCentimeter(1.4);
        section.PageSetup.RightMargin = Unit.FromCentimeter(1.4);

        Cover(section, result);
        DetectionSummary(section, result);
        ExecutiveSummary(section, result);
        CoverageOverview(section, result);
        ActivityArticles(section, result);
        SupportingReview(section, result);
        Integrity(section, result);
        Limitations(section, result);

        Paragraph footer = section.Footers.Primary.AddParagraph();
        footer.Format.Alignment = ParagraphAlignment.Center;
        footer.Format.Font.Size = 7;
        footer.Format.Font.Color = Color.Parse("#8A7470");
        footer.AddText($"DoubleG Scanner {result.ScannerVersion} | {result.ScanId} | Made by DoubleG Team");
        return document;
    }

    private static void ConfigureStyles(Document document)
    {
        Style normal = document.Styles["Normal"]!;
        normal.Font.Name = "Segoe UI";
        normal.Font.Size = 8.5;
        normal.Font.Color = Color.Parse("#2B2530");

        Style title = document.Styles.AddStyle("DGTitle", "Normal");
        title.Font.Size = 21;
        title.Font.Bold = true;
        title.Font.Color = Color.Parse("#A31224");

        Style heading = document.Styles.AddStyle("DGHeading", "Normal");
        heading.Font.Size = 12.5;
        heading.Font.Bold = true;
        heading.Font.Color = Color.Parse("#231416");
        heading.ParagraphFormat.SpaceBefore = Unit.FromPoint(11);
        heading.ParagraphFormat.SpaceAfter = Unit.FromPoint(5);

        Style small = document.Styles.AddStyle("DGSmall", "Normal");
        small.Font.Size = 7.5;
        small.Font.Color = Color.Parse("#736366");
    }

    private static void Cover(Section section, ScanResult result)
    {
        Table brandTable = section.AddTable();
        brandTable.AddColumn(Unit.FromCentimeter(2.4));
        brandTable.AddColumn(Unit.FromCentimeter(14.2));
        Row brandRow = brandTable.AddRow();
        brandRow.VerticalAlignment = VerticalAlignment.Center;

        string? logoPath = TryResolveLogoPath();
        if (!string.IsNullOrWhiteSpace(logoPath) && File.Exists(logoPath))
        {
            Paragraph logoParagraph = brandRow.Cells[0].AddParagraph();
            var image = logoParagraph.AddImage(logoPath);
            image.LockAspectRatio = true;
            image.Height = Unit.FromCentimeter(1.7);
        }

        Paragraph brand = brandRow.Cells[1].AddParagraph();
        brand.Style = "DGTitle";
        brand.AddText("DOUBLEG SCANNER");

        Paragraph subtitle = brandRow.Cells[1].AddParagraph("FORENSIC SCAN REPORT");
        subtitle.Format.Font.Size = 9;
        subtitle.Format.Font.Bold = true;
        subtitle.Format.Font.Color = Color.Parse("#8A6F6B");
        subtitle.Format.SpaceAfter = Unit.FromPoint(12);

        Table banner = section.AddTable();
        banner.AddColumn(Unit.FromCentimeter(16.8));
        Row row = banner.AddRow();
        string background = result.Verdict switch
        {
            ScanVerdict.Detected => "#FFF1F4",
            ScanVerdict.Review => "#FFF8E8",
            ScanVerdict.NotDetected => "#ECFAF3",
            _ => "#F4F5F7"
        };
        string foreground = result.Verdict switch
        {
            ScanVerdict.Detected => "#B61D34",
            ScanVerdict.Review => "#8B6400",
            ScanVerdict.NotDetected => "#13714B",
            _ => "#5D6572"
        };
        row.Cells[0].Shading.Color = Color.Parse(background);
        row.Cells[0].Borders.Color = Color.Parse(foreground);
        row.Cells[0].Borders.Width = Unit.FromPoint(0.9);
        row.Cells[0].Format.LeftIndent = Unit.FromPoint(11);
        row.Cells[0].Format.RightIndent = Unit.FromPoint(11);
        row.Cells[0].Format.SpaceBefore = Unit.FromPoint(10);
        row.Cells[0].Format.SpaceAfter = Unit.FromPoint(10);

        Paragraph verdictTitle = row.Cells[0].AddParagraph();
        verdictTitle.Format.Font.Size = 16.5;
        verdictTitle.Format.Font.Bold = true;
        verdictTitle.Format.Font.Color = Color.Parse(foreground);
        verdictTitle.AddText(VerdictTitle(result.Verdict));

        Paragraph verdictText = row.Cells[0].AddParagraph();
        verdictText.Format.SpaceBefore = Unit.FromPoint(3);
        verdictText.AddText(VerdictText(result.Verdict));
        section.AddParagraph().Format.SpaceAfter = Unit.FromPoint(4);

        Table metadata = section.AddTable();
        metadata.Borders.Color = Color.Parse("#E5D8D6");
        metadata.Borders.Width = Unit.FromPoint(0.55);
        metadata.AddColumn(Unit.FromCentimeter(4.5));
        metadata.AddColumn(Unit.FromCentimeter(12.3));
        Meta(metadata, "Scan ID", result.ScanId);
        Meta(metadata, "Scan mode", result.Mode.ToString());
        Meta(metadata, "Completed", result.CompletedAt.ToString("yyyy-MM-dd HH:mm:ss zzz"));
        Meta(metadata, "Risk score", $"{result.RiskScore} / 200");
        Meta(metadata, "Detected cheats", PrimaryCheatFindings(result).Length.ToString());
        Meta(metadata, "Review items", SupportingFindings(result).Length.ToString());
        Meta(metadata, "Scanner / rules", $"{result.ScannerVersion} / {result.RuleDatabaseVersion}");
        Meta(metadata, "Access", result.IsElevated ? "Administrator" : "Standard user");
    }

    private static void DetectionSummary(Section section, ScanResult result)
    {
        H(section, "CHEAT DETECTION SUMMARY");
        ScanFinding[] primary = PrimaryCheatFindings(result);
        if (primary.Length == 0)
        {
            Table ok = section.AddTable();
            ok.AddColumn(Unit.FromCentimeter(16.8));
            Row row = ok.AddRow();
            row.Cells[0].Shading.Color = Color.Parse("#F7FBF9");
            row.Cells[0].Borders.Color = Color.Parse("#A8D5BD");
            row.Cells[0].Borders.Width = Unit.FromPoint(0.8);
            Paragraph p = row.Cells[0].AddParagraph();
            p.Format.Font.Bold = true;
            p.Format.Font.Color = Color.Parse("#16704A");
            p.AddText("No confirmed cheat name is being highlighted in this report.");
            row.Cells[0].AddParagraph("Supporting traces, browser history, local files, kernel posture, and deleted-file artifacts are shown separately below as neutral review sections.");
            return;
        }

        int index = 0;
        foreach (ScanFinding finding in primary.Take(24))
        {
            index++;
            Table table = section.AddTable();
            table.AddColumn(Unit.FromCentimeter(16.8));
            Row row = table.AddRow();
            Cell cell = row.Cells[0];
            cell.Borders.Color = Color.Parse("#C91F35");
            cell.Borders.Width = Unit.FromPoint(1.0);
            cell.Shading.Color = Color.Parse("#FFF8FA");
            cell.Format.LeftIndent = Unit.FromPoint(8);
            cell.Format.RightIndent = Unit.FromPoint(8);
            cell.Format.SpaceBefore = Unit.FromPoint(7);
            cell.Format.SpaceAfter = Unit.FromPoint(7);

            Paragraph title = cell.AddParagraph();
            title.Format.Font.Size = 10.5;
            title.Format.Font.Bold = true;
            title.Format.Font.Color = Color.Parse("#C91F35");
            title.AddText($"DETECTION {index:00} - {finding.DetectedCheatName ?? finding.Title}");

            Paragraph pill = cell.AddParagraph();
            pill.Format.SpaceBefore = Unit.FromPoint(2);
            pill.AddFormattedText("Detected cheat: ", TextFormat.Bold);
            pill.Format.Font.Color = Color.Parse("#C91F35");
            pill.AddText(finding.DetectedCheatName ?? "Named detection");

            if (!string.IsNullOrWhiteSpace(finding.CheatFamily))
                Label(cell, "Family", finding.CheatFamily);
            if (!string.IsNullOrWhiteSpace(finding.DetectionMethod))
                Label(cell, "Detection method", finding.DetectionMethod);
            if (!string.IsNullOrWhiteSpace(finding.Path))
                Label(cell, "Artifact", finding.Path);
            if (!string.IsNullOrWhiteSpace(finding.HashSha256))
                Label(cell, "SHA-256", finding.HashSha256);
            if (finding.Timestamp is not null)
                Label(cell, "Time", finding.Timestamp.Value.ToString("yyyy-MM-dd HH:mm:ss zzz"));
            cell.AddParagraph(finding.Summary);
            if (finding.Reasons.Count > 0)
                Label(cell, "Combined evidence", string.Join("; ", finding.Reasons));
            section.AddParagraph().Format.SpaceAfter = Unit.FromPoint(1);
        }
    }

    private static void ExecutiveSummary(Section section, ScanResult result)
    {
        H(section, "EXECUTIVE SUMMARY");
        Paragraph paragraph = section.AddParagraph();
        paragraph.AddText(result.Verdict switch
        {
            ScanVerdict.Detected => "This report contains one or more high-confidence detections. The red detection cards above are the main items that should be reviewed first.",
            ScanVerdict.Review => "The scan did not produce a confirmed cheat detection, but it did collect supporting traces that may require manual review.",
            ScanVerdict.NotDetected => "No confirmed high-confidence cheat detection was produced by the completed modules. Neutral trace sections are still included for transparency.",
            _ => "The scan did not produce a reliable complete verdict. Review the coverage section before interpreting the report."
        });

        Table table = section.AddTable();
        for (int i = 0; i < 5; i++) table.AddColumn(Unit.FromCentimeter(3.36));
        Row header = table.AddRow();
        header.Shading.Color = Color.Parse("#281416");
        header.Format.Font.Color = Colors.White;
        header.Format.Font.Bold = true;
        string[] names = { "Evidence", "Detections", "Review", "Modules", "Risk" };
        for (int i = 0; i < names.Length; i++) header.Cells[i].AddParagraph(names[i]);
        Row values = table.AddRow();
        values.Format.Font.Size = 12;
        values.Format.Font.Bold = true;
        values.Cells[0].AddParagraph(result.Evidence.Count.ToString("N0"));
        values.Cells[1].AddParagraph(PrimaryCheatFindings(result).Length.ToString("N0"));
        values.Cells[2].AddParagraph(SupportingFindings(result).Length.ToString("N0"));
        values.Cells[3].AddParagraph(result.Coverage.Count(x => x.Status == CoverageStatus.Completed).ToString());
        values.Cells[4].AddParagraph(result.RiskScore.ToString());
        Format(table, 6, true);
    }

    private static void CoverageOverview(Section section, ScanResult result)
    {
        H(section, "SCAN COVERAGE");
        Table table = section.AddTable();
        table.Borders.Color = Color.Parse("#E5D8D6");
        table.Borders.Width = Unit.FromPoint(0.45);
        table.AddColumn(Unit.FromCentimeter(4.3));
        table.AddColumn(Unit.FromCentimeter(2.2));
        table.AddColumn(Unit.FromCentimeter(2.0));
        table.AddColumn(Unit.FromCentimeter(8.3));
        Header(table, "Module", "Status", "Checked", "Summary");
        foreach (ScanCoverage coverage in result.Coverage)
        {
            Row row = table.AddRow();
            row.Cells[0].AddParagraph(coverage.Module);
            row.Cells[1].AddParagraph(coverage.Status.ToString());
            row.Cells[2].AddParagraph(coverage.ItemsChecked.ToString("N0"));
            row.Cells[3].AddParagraph(coverage.Summary);
        }
        Format(table, 4.5, false);
    }

    private static void ActivityArticles(Section section, ScanResult result)
    {
        H(section, "ACTIVITY ARTICLES");
        section.AddParagraph("Each section below summarizes one part of the scan so that browser records, recent activity, kernel data, deleted-file traces, and local-file findings stay separated and easier to read.");

        AddArticle(section, result,
            "Browser History",
            "Downloaded files, visited sources, and browser-side traces.",
            new[] { EvidenceKind.Browser });

        AddArticle(section, result,
            "Last Activity",
            "Recent process, module, execution, and time-linked activity.",
            new[] { EvidenceKind.Process, EvidenceKind.Module, EvidenceKind.Execution });

        AddArticle(section, result,
            "Network / Data Usage",
            "Live network activity collected during the scan.",
            new[] { EvidenceKind.Network });

        AddArticle(section, result,
            "Local Files & Downloads",
            "Recent downloads, local executables, archives, and startup-related artifacts.",
            new[] { EvidenceKind.FileArtifact });

        AddArticle(section, result,
            "Kernel & Drivers",
            "Kernel posture, loaded drivers, and Windows driver-related events.",
            new[] { EvidenceKind.KernelSecurity, EvidenceKind.KernelDriver, EvidenceKind.CodeIntegrity });

        AddArticle(section, result,
            "Deleted Traces",
            "Recycle Bin metadata, NTFS journal/MFT data, and unallocated-space trace artifacts.",
            new[] { EvidenceKind.DeletedFile, EvidenceKind.NtfsMetadata, EvidenceKind.UsnJournal, EvidenceKind.RawDeletedFile });

        AddArticle(section, result,
            "Microsoft Defender",
            "Read-only no-remediation custom scan output.",
            new[] { EvidenceKind.Antivirus });
    }

    private static void AddArticle(Section section, ScanResult result, string title, string subtitle, EvidenceKind[] kinds)
    {
        EvidenceRecord[] evidence = result.Evidence.Where(x => kinds.Contains(x.Kind)).OrderByDescending(x => x.Timestamp).ToArray();
        ScanFinding[] relatedFindings = RelatedFindings(result.Findings, evidence).Take(10).ToArray();

        H(section, title.ToUpperInvariant());
        Table shell = section.AddTable();
        shell.AddColumn(Unit.FromCentimeter(16.8));
        Row row = shell.AddRow();
        Cell cell = row.Cells[0];
        cell.Borders.Color = Color.Parse("#DEC7C4");
        cell.Borders.Width = Unit.FromPoint(0.7);
        cell.Shading.Color = Color.Parse("#FFFCFB");
        cell.Format.LeftIndent = Unit.FromPoint(8);
        cell.Format.RightIndent = Unit.FromPoint(8);
        cell.Format.SpaceBefore = Unit.FromPoint(6);
        cell.Format.SpaceAfter = Unit.FromPoint(6);

        Paragraph lead = cell.AddParagraph();
        lead.Format.Font.Bold = true;
        lead.AddText(title);

        Paragraph subtitleParagraph = cell.AddParagraph(subtitle);
        subtitleParagraph.Style = "DGSmall";
        subtitleParagraph.Format.SpaceAfter = Unit.FromPoint(4);

        Paragraph counts = cell.AddParagraph();
        counts.AddFormattedText("Evidence: ", TextFormat.Bold);
        counts.AddText(evidence.Length.ToString("N0"));
        counts.AddFormattedText("  |  Related review items: ", TextFormat.Bold);
        counts.AddText(relatedFindings.Length.ToString("N0"));

        if (relatedFindings.Length > 0)
        {
            Paragraph findingHeader = cell.AddParagraph();
            findingHeader.Format.SpaceBefore = Unit.FromPoint(4);
            findingHeader.Format.Font.Bold = true;
            findingHeader.AddText("Key review notes");
            foreach (ScanFinding finding in relatedFindings)
            {
                Paragraph bullet = cell.AddParagraph();
                bullet.Format.LeftIndent = Unit.FromPoint(10);
                bullet.Format.FirstLineIndent = Unit.FromPoint(-7);
                bullet.AddText("• ");
                bullet.AddFormattedText(SanitizeSupportingTitle(finding), TextFormat.Bold);
                if (!string.IsNullOrWhiteSpace(finding.DetectedCheatName) && IsPrimaryCheatFinding(finding))
                {
                    bullet.AddText(" — ");
                    FormattedText red = bullet.AddFormattedText(finding.DetectedCheatName, TextFormat.Bold);
                    red.Color = Color.Parse("#C91F35");
                }
                bullet.AddText($". {finding.Summary}");
            }
        }
        else
        {
            cell.AddParagraph("No major review item was attached to this section.");
        }

        Paragraph evidenceHeader = cell.AddParagraph();
        evidenceHeader.Format.SpaceBefore = Unit.FromPoint(5);
        evidenceHeader.Format.Font.Bold = true;
        evidenceHeader.AddText("Evidence lines");

        Table table = cell.Elements.AddTable();
        table.Borders.Color = Color.Parse("#E8DCDA");
        table.Borders.Width = Unit.FromPoint(0.35);
        table.AddColumn(Unit.FromCentimeter(2.7));
        table.AddColumn(Unit.FromCentimeter(3.3));
        table.AddColumn(Unit.FromCentimeter(10.0));
        Header(table, "Time", "Item", "Detail");

        foreach (EvidenceRecord item in evidence.Take(12))
        {
            Row evidenceRow = table.AddRow();
            evidenceRow.Cells[0].AddParagraph(item.Timestamp?.ToString("yyyy-MM-dd HH:mm") ?? "-");
            evidenceRow.Cells[1].AddParagraph(item.Name);
            evidenceRow.Cells[2].AddParagraph(PrimaryDetail(item));
        }
        Format(table, 3.5, false);
    }

    private static void SupportingReview(Section section, ScanResult result)
    {
        ScanFinding[] supporting = SupportingFindings(result);
        H(section, "SUPPORTING REVIEW ITEMS");
        if (supporting.Length == 0)
        {
            section.AddParagraph("No separate supporting review item was generated.");
            return;
        }

        section.AddParagraph("These items are shown in a neutral format. They are supporting traces or technical review points and are intentionally separated from the red cheat-detection cards above.");

        foreach (ScanFinding finding in supporting.Take(24))
        {
            Table table = section.AddTable();
            table.AddColumn(Unit.FromCentimeter(16.8));
            Row row = table.AddRow();
            Cell cell = row.Cells[0];
            string color = finding.Severity switch
            {
                FindingSeverity.Critical => "#9D5964",
                FindingSeverity.High => "#A06C5C",
                FindingSeverity.Warning => "#8A7A54",
                _ => "#72727A"
            };
            cell.Borders.Color = Color.Parse(color);
            cell.Borders.Width = Unit.FromPoint(0.7);
            cell.Shading.Color = Color.Parse("#FFFCFB");
            cell.Format.LeftIndent = Unit.FromPoint(8);
            cell.Format.RightIndent = Unit.FromPoint(8);
            cell.Format.SpaceBefore = Unit.FromPoint(5);
            cell.Format.SpaceAfter = Unit.FromPoint(5);

            Paragraph title = cell.AddParagraph();
            title.Format.Font.Bold = true;
            title.Format.Font.Color = Color.Parse(color);
            title.AddText(SanitizeSupportingTitle(finding));

            cell.AddParagraph($"Severity: {finding.Severity} | Score: {finding.Score} | Source: {finding.EvidenceSource}");
            cell.AddParagraph(finding.Summary);
            if (!string.IsNullOrWhiteSpace(finding.Path))
                Label(cell, "Artifact", finding.Path);
            if (!string.IsNullOrWhiteSpace(finding.HashSha256))
                Label(cell, "SHA-256", finding.HashSha256);
            if (finding.Timestamp is not null)
                Label(cell, "Time", finding.Timestamp.Value.ToString("yyyy-MM-dd HH:mm:ss zzz"));
            if (finding.Reasons.Count > 0)
                Label(cell, "Notes", string.Join("; ", finding.Reasons));
        }
    }

    private static void Integrity(Section section, ScanResult result)
    {
        H(section, "REPORT INTEGRITY");
        Table table = section.AddTable();
        table.Borders.Color = Color.Parse("#E5D8D6");
        table.Borders.Width = Unit.FromPoint(0.45);
        table.AddColumn(Unit.FromCentimeter(4.6));
        table.AddColumn(Unit.FromCentimeter(12.2));
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
        english.AddText("Only the red detection cards are intended to highlight confirmed or strongly named detections. Other sections may contain browser history, installer traces, unsigned files, kernel posture, or deleted-file artifacts that require context and manual review. ");
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
        Cell nameCell = row.Cells[0]!;
        Cell valueCell = row.Cells[1]!;
        nameCell.Shading.Color = Color.Parse("#F8F2F0");
        nameCell.Format.Font.Bold = true;
        nameCell.AddParagraph(name);
        valueCell.AddParagraph(value);
        foreach (Cell? cell in row.Cells)
        {
            if (cell is null) continue;
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
        foreach (Row? row in table.Rows)
        {
            if (row is null) continue;
            foreach (Cell? cell in row.Cells)
            {
                if (cell is null) continue;
                cell.VerticalAlignment = VerticalAlignment.Center;
                cell.Format.SpaceBefore = Unit.FromPoint(padding);
                cell.Format.SpaceAfter = Unit.FromPoint(padding);
                cell.Format.LeftIndent = Unit.FromPoint(3);
                if (center) cell.Format.Alignment = ParagraphAlignment.Center;
            }
        }
    }

    private static string VerdictTitle(ScanVerdict verdict) => verdict switch
    {
        ScanVerdict.Detected => "CHEAT DETECTION FOUND",
        ScanVerdict.Review => "MANUAL REVIEW REQUIRED",
        ScanVerdict.NotDetected => "NO CONFIRMED DETECTION FOUND",
        ScanVerdict.Cancelled => "SCAN CANCELLED",
        _ => "SCAN INCOMPLETE"
    };

    private static string VerdictText(ScanVerdict verdict) => verdict switch
    {
        ScanVerdict.Detected => "One or more high-confidence detections were highlighted. Review the red detection cards first.",
        ScanVerdict.Review => "No confirmed detection was highlighted, but supporting evidence requires manual review.",
        ScanVerdict.NotDetected => "No confirmed high-confidence detection was highlighted by completed modules.",
        ScanVerdict.Cancelled => "The scan was cancelled before a reliable result was produced.",
        _ => "Required modules could not be completed, so no reliable complete verdict was produced."
    };

    private static string? TryResolveLogoPath()
    {
        string[] candidates =
        {
            Path.Combine(AppContext.BaseDirectory, "Assets", "DoubleGLogo.png"),
            Path.Combine(AppContext.BaseDirectory, "DoubleGLogo.png"),
            Path.Combine(Environment.CurrentDirectory, "Assets", "DoubleGLogo.png")
        };

        return candidates.FirstOrDefault(File.Exists);
    }

    private static ScanFinding[] PrimaryCheatFindings(
        ScanResult result) =>
        result.Findings
            .Where(IsPrimaryCheatFinding)
            .GroupBy(
                item => NormalizeReportKey(
                    item.DetectedCheatName ??
                    item.Title),
                StringComparer.OrdinalIgnoreCase)
            .Select(group =>
                group
                    .OrderByDescending(item =>
                        item.Score)
                    .ThenByDescending(item =>
                        item.Timestamp)
                    .First())
            .OrderByDescending(item =>
                item.Score)
            .ThenByDescending(item =>
                item.Timestamp)
            .ToArray();

    private static ScanFinding[] SupportingFindings(
        ScanResult result) =>
        result.Findings
            .Where(item =>
                !IsPrimaryCheatFinding(item))
            .GroupBy(
                item =>
                    !string.IsNullOrWhiteSpace(
                        item.DetectedCheatName)
                        ? $"named:{NormalizeReportKey(item.DetectedCheatName)}"
                        : item.RuleId.StartsWith(
                            "DGS-KERNEL-",
                            StringComparison.OrdinalIgnoreCase)
                            ? $"kernel:{item.RuleId}"
                            : $"other:{item.RuleId}|{NormalizeReportKey(item.Path ?? item.Title)}",
                StringComparer.OrdinalIgnoreCase)
            .Select(group =>
                group
                    .OrderByDescending(item =>
                        item.Score)
                    .ThenByDescending(item =>
                        item.Timestamp)
                    .First())
            .OrderByDescending(item =>
                item.Score)
            .ThenByDescending(item =>
                item.Timestamp)
            .ToArray();

    private static bool IsPrimaryCheatFinding(ScanFinding finding)
    {
        if (string.IsNullOrWhiteSpace(finding.DetectedCheatName))
            return false;

        if (finding.RuleId.Equals("DGS-DEFENDER-001", StringComparison.OrdinalIgnoreCase))
            return true;

        if (finding.RuleId.Equals("DGS-HASH-001", StringComparison.OrdinalIgnoreCase) ||
            finding.RuleId.Equals("DGS-HASH-LEGACY", StringComparison.OrdinalIgnoreCase))
            return true;

        if (finding.RuleId.StartsWith("DGS-NAMED-CORR", StringComparison.OrdinalIgnoreCase) ||
            finding.RuleId.StartsWith("DGS-NAMED-MODULE", StringComparison.OrdinalIgnoreCase) ||
            finding.RuleId.StartsWith("DGS-NAMED-PROCESS", StringComparison.OrdinalIgnoreCase) ||
            finding.RuleId.StartsWith("DGS-NAMED-DOWNLOAD", StringComparison.OrdinalIgnoreCase) ||
            finding.RuleId.StartsWith("DGS-NAMED-BROWSER", StringComparison.OrdinalIgnoreCase) ||
            finding.RuleId.StartsWith("DGS-NAMED-RAW-DELETED", StringComparison.OrdinalIgnoreCase))
            return true;

        return finding.Score >= 80;
    }

    private static ScanFinding[] RelatedFindings(IReadOnlyList<ScanFinding> findings, IReadOnlyList<EvidenceRecord> evidence)
    {
        if (evidence.Count == 0)
            return Array.Empty<ScanFinding>();

        HashSet<string> sources = evidence
            .Select(x => x.Source)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        HashSet<string> paths = evidence
            .Select(x => x.Path ?? x.Url)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Cast<string>()
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        return findings
            .Where(x =>
                sources.Contains(x.EvidenceSource) ||
                (!string.IsNullOrWhiteSpace(x.Path) && paths.Contains(x.Path)))
            .OrderByDescending(x => IsPrimaryCheatFinding(x))
            .ThenByDescending(x => x.Score)
            .ThenByDescending(x => x.Timestamp)
            .ToArray();
    }

    private static string NormalizeReportKey(
        string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return "";

        string normalized =
            new string(
                value
                    .ToLowerInvariant()
                    .Where(char.IsLetterOrDigit)
                    .ToArray());

        return string.IsNullOrWhiteSpace(normalized)
            ? value.Trim().ToLowerInvariant()
            : normalized;
    }

    private static string SanitizeSupportingTitle(ScanFinding finding)
    {
        if (IsPrimaryCheatFinding(finding))
            return finding.Title;

        return finding.Title
            .Replace("cheat-like", "suspicious", StringComparison.OrdinalIgnoreCase)
            .Replace("cheat-related", "suspicious", StringComparison.OrdinalIgnoreCase)
            .Replace("cheat-family", "named", StringComparison.OrdinalIgnoreCase)
            .Replace("Detected cheat", "Detected indicator", StringComparison.OrdinalIgnoreCase)
            .Replace("Named cheat", "Named artifact", StringComparison.OrdinalIgnoreCase)
            .Replace("cheat", "indicator", StringComparison.OrdinalIgnoreCase);
    }

    private static string PrimaryDetail(EvidenceRecord item)
    {
        string detail = item.Path ?? item.Url ?? item.Detail ?? "";
        if (string.IsNullOrWhiteSpace(detail))
            detail = item.Metadata.Count > 0
                ? string.Join(" | ", item.Metadata.Take(3).Select(x => $"{x.Key}: {x.Value}"))
                : "No additional detail";

        if (detail.Length > 180)
            detail = detail[..177] + "...";

        return detail;
    }
}
