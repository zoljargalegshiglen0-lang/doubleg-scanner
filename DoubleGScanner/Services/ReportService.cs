using System.Text.Json;
using DoubleGScanner.Models;
using MigraDoc.DocumentObjectModel;
using MigraDoc.DocumentObjectModel.Tables;
using MigraDoc.Rendering;

namespace DoubleGScanner.Services;

public sealed class ReportService
{
    private const double ContentWidthCm = 18.2;

    private const string Navy = "#171717";
    private const string Navy2 = "#242424";
    private const string Ink = "#171717";
    private const string Muted = "#71717A";
    private const string Line = "#D6D3D1";
    private const string Soft = "#F2F0EC";
    private const string Purple = "#2762D9";
    private const string PurpleSoft = "#E9F0FF";
    private const string Cyan = "#1E8E5A";
    private const string CyanSoft = "#E8F5EE";
    private const string Red = "#E1261C";
    private const string RedDark = "#9F1712";
    private const string RedSoft = "#FDE9E7";
    private const string Amber = "#D99B17";
    private const string Orange = "#F97316";
    private const string AmberSoft = "#FFF5D8";
    private const string Green = "#1E8E5A";
    private const string GreenSoft = "#E8F5EE";

    public async Task<ReportBundle> CreateAsync(ScanResult result, CancellationToken token)
    {
        string directory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            "DoubleG Scanner",
            "Reports",
            result.ScanId);
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
        await File.WriteAllTextAsync(
            hashPath,
            $"{pdfHash}  {Path.GetFileName(pdfPath)}{Environment.NewLine}",
            token);

        return new ReportBundle
        {
            PdfPath = pdfPath,
            JsonPath = jsonPath,
            PdfHashPath = hashPath
        };
    }

    private static Document Build(ScanResult result)
    {
        var document = new Document();
        document.Info.Title = "DoubleG Scanner - Integrity Case Report";
        document.Info.Author = "xanny";
        document.Info.Subject = result.ScanId;
        document.Info.Keywords = "DoubleG Scanner, CS2, forensic, integrity, evidence";

        ConfigureStyles(document);

        Section section = document.AddSection();
        section.PageSetup.PageFormat = PageFormat.A4;
        section.PageSetup.TopMargin = Unit.FromCentimeter(1.05);
        section.PageSetup.BottomMargin = Unit.FromCentimeter(1.45);
        section.PageSetup.LeftMargin = Unit.FromCentimeter(1.4);
        section.PageSetup.RightMargin = Unit.FromCentimeter(1.4);
        section.PageSetup.FooterDistance = Unit.FromCentimeter(0.55);

        AddFooter(section, result);

        AddCaseHeader(section, result, "CASE FILE", result.ScanId);
        AddCaseOverview(section, result);
        AddIdentityStripOriginal(section, result);
        AddEvidenceProfileOriginal(section, result);
        AddKeyObservationsOriginal(section, result);
        AddDecisionRuleOriginal(section);

        section.AddPageBreak();
        AddCaseHeader(section, result, "EVIDENCE LEDGER", $"{AllReportFindings(result).Length:N0} findings");
        AddFindingsLedgerOriginal(section, result);

        section.AddPageBreak();
        AddCaseHeader(section, result, "COVERAGE & TRUST MAP", $"{result.Coverage.Count:N0} modules");
        AddCoverageTrustMap(section, result);
        AddDmaCorrelationGate(section, result);
        AddOriginalIntegrity(section, result);

        if (result.Evidence.Count > 0)
        {
            section.AddPageBreak();
            AddCaseHeader(section, result, "EVIDENCE APPENDIX", $"{result.Evidence.Count:N0} records");
            AddEvidenceReview(section, result);
            AddInterpretation(section, result);
        }

        return document;
    }

    private static void ConfigureStyles(Document document)
    {
        Style normal = document.Styles["Normal"]!;
        normal.Font.Name = "Segoe UI";
        normal.Font.Size = 8.1;
        normal.Font.Color = C(Ink);
        normal.ParagraphFormat.SpaceAfter = Unit.FromPoint(2);

        Style title = document.Styles.AddStyle("DGBrand", "Normal");
        title.Font.Name = "Segoe UI Semibold";
        title.Font.Size = 15.5;
        title.Font.Bold = true;
        title.Font.Color = C(Ink);

        Style heading = document.Styles.AddStyle("DGSection", "Normal");
        heading.Font.Name = "Segoe UI Semibold";
        heading.Font.Size = 11.2;
        heading.Font.Bold = true;
        heading.Font.Color = C(Ink);
        heading.ParagraphFormat.SpaceBefore = Unit.FromPoint(9);
        heading.ParagraphFormat.SpaceAfter = Unit.FromPoint(4.5);

        Style small = document.Styles.AddStyle("DGSmall", "Normal");
        small.Font.Size = 7;
        small.Font.Color = C(Muted);

        Style mono = document.Styles.AddStyle("DGMono", "Normal");
        mono.Font.Name = "Consolas";
        mono.Font.Size = 6.7;
        mono.Font.Color = C(Muted);
    }

    private static void AddFooter(Section section, ScanResult result)
    {
        Paragraph footer = section.Footers.Primary.AddParagraph();
        footer.Format.Alignment = ParagraphAlignment.Left;
        footer.Format.Borders.Top.Color = C(Line);
        footer.Format.Borders.Top.Width = Unit.FromPoint(0.45);
        footer.Format.SpaceBefore = Unit.FromPoint(4);
        footer.Format.Font.Name = "Segoe UI";
        footer.Format.Font.Size = 6.4;
        footer.Format.Font.Color = C(Muted);

        FormattedText brand = footer.AddFormattedText("DOUBLEG FORENSIC REPORT", TextFormat.Bold);
        brand.Color = C(Ink);
        footer.AddText("   ");
        FormattedText author = footer.AddFormattedText("by xanny", TextFormat.Bold);
        author.Color = C(Red);
        footer.AddText($"   |   {result.ScannerVersion}   |   {result.ScanId}   |   page ");
        footer.AddPageField();
        footer.AddText(" / ");
        footer.AddNumPagesField();
    }

    private static void AddCaseHeader(Section section, ScanResult result, string overline, string rightValue)
    {
        Table table = section.AddTable();
        table.AddColumn(Unit.FromCentimeter(0.22));
        table.AddColumn(Unit.FromCentimeter(1.35));
        table.AddColumn(Unit.FromCentimeter(10.45));
        table.AddColumn(Unit.FromCentimeter(6.18));

        Row row = table.AddRow();
        row.VerticalAlignment = VerticalAlignment.Center;
        row.Cells[0].Shading.Color = C(Red);

        string? logoPath = TryResolveLogoPath();
        if (!string.IsNullOrWhiteSpace(logoPath) && File.Exists(logoPath))
        {
            Paragraph logo = row.Cells[1].AddParagraph();
            logo.Format.Alignment = ParagraphAlignment.Center;
            var image = logo.AddImage(logoPath);
            image.LockAspectRatio = true;
            image.Height = Unit.FromCentimeter(0.88);
        }

        Paragraph brand = row.Cells[2].AddParagraph();
        brand.Style = "DGBrand";
        brand.AddText("DOUBLEG");
        Paragraph sub = row.Cells[2].AddParagraph("INTEGRITY LAB");
        sub.Format.Font.Size = 6.1;
        sub.Format.Font.Bold = true;
        sub.Format.Font.Color = C(Red);
        sub.Format.SpaceBefore = Unit.FromPoint(-1);

        Paragraph right = row.Cells[3].AddParagraph(overline.ToUpperInvariant());
        right.Format.Alignment = ParagraphAlignment.Right;
        right.Format.Font.Size = 6.0;
        right.Format.Font.Bold = true;
        right.Format.Font.Color = C(Muted);
        Paragraph rightLine = row.Cells[3].AddParagraph(Trim(rightValue, 60));
        rightLine.Format.Alignment = ParagraphAlignment.Right;
        rightLine.Format.Font.Size = 8.2;
        rightLine.Format.Font.Bold = true;
        rightLine.Format.Font.Color = C(Ink);

        foreach (Cell? cell in row.Cells)
        {
            if (cell is null) continue;
            cell.Format.LeftIndent = Unit.FromPoint(4);
            cell.Format.RightIndent = Unit.FromPoint(4);
            cell.Format.SpaceBefore = Unit.FromPoint(4);
            cell.Format.SpaceAfter = Unit.FromPoint(4);
        }

        Table line = section.AddTable();
        line.AddColumn(Unit.FromCentimeter(ContentWidthCm));
        Row lineRow = line.AddRow();
        lineRow.Height = Unit.FromPoint(1.3);
        lineRow.Cells[0].Shading.Color = C(Line);
        section.AddParagraph().Format.SpaceAfter = Unit.FromPoint(5);
    }

    private static void AddCaseOverview(Section section, ScanResult result)
    {
        Table table = section.AddTable();
        table.AddColumn(Unit.FromCentimeter(11.15));
        table.AddColumn(Unit.FromCentimeter(7.05));
        Row row = table.AddRow();
        row.VerticalAlignment = VerticalAlignment.Top;

        Paragraph first = row.Cells[0].AddParagraph("INTEGRITY");
        first.Format.Font.Name = "Segoe UI Semibold";
        first.Format.Font.Size = 26;
        first.Format.Font.Bold = true;
        first.Format.Font.Color = C(Ink);
        first.Format.SpaceBefore = Unit.FromPoint(8);

        Paragraph second = row.Cells[0].AddParagraph("CASE REPORT");
        second.Format.Font.Name = "Segoe UI Semibold";
        second.Format.Font.Size = 26;
        second.Format.Font.Bold = true;
        second.Format.Font.Color = C(Red);
        second.Format.SpaceBefore = Unit.FromPoint(-3);

        Paragraph description = row.Cells[0].AddParagraph(
            "A structured review of runtime, file, persistence, kernel and hardware evidence collected from the scanned system.");
        description.Format.Font.Size = 8.0;
        description.Format.Font.Color = C(Muted);
        description.Format.SpaceBefore = Unit.FromPoint(7);
        description.Format.RightIndent = Unit.FromPoint(18);

        Table verdict = row.Cells[1].Elements.AddTable();
        verdict.AddColumn(Unit.FromCentimeter(6.45));
        Row box = verdict.AddRow();
        box.Cells[0].Shading.Color = C(Ink);
        box.Cells[0].Borders.Color = C(Ink);
        box.Cells[0].Borders.Width = Unit.FromPoint(0.4);

        Paragraph over = box.Cells[0].AddParagraph("ASSESSMENT");
        over.Format.Font.Size = 6.0;
        over.Format.Font.Bold = true;
        over.Format.Font.Color = C("#B7B7BC");

        Paragraph verdictTitle = box.Cells[0].AddParagraph(VerdictTitle(result.Verdict));
        verdictTitle.Format.Font.Name = "Segoe UI Semibold";
        verdictTitle.Format.Font.Size = 16.5;
        verdictTitle.Format.Font.Bold = true;
        verdictTitle.Format.Font.Color = C(result.Verdict == ScanVerdict.NotDetected ? Green : Red);
        verdictTitle.Format.SpaceBefore = Unit.FromPoint(8);

        Paragraph riskLabel = box.Cells[0].AddParagraph("RISK INDEX");
        riskLabel.Format.Font.Size = 5.8;
        riskLabel.Format.Font.Bold = true;
        riskLabel.Format.Font.Color = C("#B7B7BC");
        riskLabel.Format.SpaceBefore = Unit.FromPoint(13);

        Paragraph risk = box.Cells[0].AddParagraph(result.RiskScore.ToString("N0"));
        risk.Format.Alignment = ParagraphAlignment.Right;
        risk.Format.Font.Name = "Segoe UI Semibold";
        risk.Format.Font.Size = 24;
        risk.Format.Font.Bold = true;
        risk.Format.Font.Color = Colors.White;
        risk.Format.SpaceBefore = Unit.FromPoint(-12);

        box.Cells[0].Format.LeftIndent = Unit.FromPoint(12);
        box.Cells[0].Format.RightIndent = Unit.FromPoint(12);
        box.Cells[0].Format.SpaceBefore = Unit.FromPoint(10);
        box.Cells[0].Format.SpaceAfter = Unit.FromPoint(10);
    }

    private static void AddIdentityStripOriginal(Section section, ScanResult result)
    {
        section.AddParagraph().Format.SpaceAfter = Unit.FromPoint(4);
        Table table = section.AddTable();
        for (int index = 0; index < 4; index++)
            table.AddColumn(Unit.FromCentimeter(ContentWidthCm / 4));

        (string Label, string Value)[] values =
        {
            ("MACHINE", result.MachineName),
            ("WINDOWS USER", result.WindowsUser),
            ("MODE", result.Mode.ToString().ToUpperInvariant()),
            ("DURATION", DurationText(result.CompletedAt - result.StartedAt))
        };

        Row row = table.AddRow();
        for (int index = 0; index < values.Length; index++)
        {
            row.Cells[index].Shading.Color = C("#E8E5DF");
            Paragraph label = row.Cells[index].AddParagraph(values[index].Label);
            label.Format.Font.Size = 5.8;
            label.Format.Font.Bold = true;
            label.Format.Font.Color = C(Muted);
            Paragraph value = row.Cells[index].AddParagraph(Trim(values[index].Value, 35));
            value.Format.Font.Size = 8.0;
            value.Format.Font.Bold = true;
            value.Format.Font.Color = C(Ink);
            value.Format.SpaceBefore = Unit.FromPoint(3);
            row.Cells[index].Borders.Right.Color = C("#C8C4BD");
            row.Cells[index].Borders.Right.Width = index == values.Length - 1 ? Unit.FromPoint(0) : Unit.FromPoint(0.45);
            row.Cells[index].Format.LeftIndent = Unit.FromPoint(8);
            row.Cells[index].Format.RightIndent = Unit.FromPoint(8);
            row.Cells[index].Format.SpaceBefore = Unit.FromPoint(6);
            row.Cells[index].Format.SpaceAfter = Unit.FromPoint(6);
        }
    }

    private static void AddEvidenceProfileOriginal(Section section, ScanResult result)
    {
        H(section, "EVIDENCE PROFILE");
        ScanFinding[] primary = PrimaryCheatFindings(result);
        ScanFinding[] supporting = SupportingFindings(result);
        int correlated = result.Findings.Count(x => x.Reasons.Count >= 2);
        int completed = result.Coverage.Count(x => x.Status == CoverageStatus.Completed);

        (string Label, string Value, string Detail, string Accent)[] items =
        {
            ("DIRECT", primary.Length.ToString("N0"), "Direct cheat artifacts", Red),
            ("CORRELATED", correlated.ToString("N0"), "Multi-source matches", Orange),
            ("REVIEW", supporting.Length.ToString("N0"), "Context required", Amber),
            ("MODULES OK", completed.ToString("N0"), "Completed coverage", Green)
        };

        Table outer = section.AddTable();
        double width = ContentWidthCm / items.Length;
        foreach (var _ in items)
            outer.AddColumn(Unit.FromCentimeter(width));
        Row row = outer.AddRow();

        for (int index = 0; index < items.Length; index++)
        {
            Table card = row.Cells[index].Elements.AddTable();
            card.AddColumn(Unit.FromCentimeter(0.2));
            card.AddColumn(Unit.FromCentimeter(width - 0.33));
            Row cardRow = card.AddRow();
            cardRow.Cells[0].Shading.Color = C(items[index].Accent);
            cardRow.Cells[1].Shading.Color = Colors.White;
            cardRow.Cells[1].Borders.Color = C(Line);
            cardRow.Cells[1].Borders.Width = Unit.FromPoint(0.5);

            Paragraph label = cardRow.Cells[1].AddParagraph(items[index].Label);
            label.Format.Font.Size = 5.8;
            label.Format.Font.Bold = true;
            label.Format.Font.Color = C(items[index].Accent);
            Paragraph value = cardRow.Cells[1].AddParagraph(items[index].Value);
            value.Format.Font.Name = "Segoe UI Semibold";
            value.Format.Font.Size = 17;
            value.Format.Font.Bold = true;
            value.Format.Font.Color = C(Ink);
            value.Format.SpaceBefore = Unit.FromPoint(4);
            Paragraph detail = cardRow.Cells[1].AddParagraph(items[index].Detail);
            detail.Format.Font.Size = 5.8;
            detail.Format.Font.Color = C(Muted);
            detail.Format.SpaceBefore = Unit.FromPoint(3);

            cardRow.Cells[1].Format.LeftIndent = Unit.FromPoint(7);
            cardRow.Cells[1].Format.RightIndent = Unit.FromPoint(5);
            cardRow.Cells[1].Format.SpaceBefore = Unit.FromPoint(6);
            cardRow.Cells[1].Format.SpaceAfter = Unit.FromPoint(6);
        }
    }

    private static void AddKeyObservationsOriginal(Section section, ScanResult result)
    {
        H(section, "KEY OBSERVATIONS");
        ScanFinding[] observations = AllReportFindings(result)
            .OrderByDescending(IsPrimaryCheatFinding)
            .ThenByDescending(x => x.Score)
            .Take(3)
            .ToArray();

        if (observations.Length == 0)
        {
            AddNoticeCard(section, "No reportable observation was generated.", Green, GreenSoft);
            return;
        }

        for (int index = 0; index < observations.Length; index++)
        {
            ScanFinding finding = observations[index];
            string accent = CategoryAccent(FindingCategory(finding));
            Table table = section.AddTable();
            table.AddColumn(Unit.FromCentimeter(1.25));
            table.AddColumn(Unit.FromCentimeter(16.95));
            Row row = table.AddRow();
            row.VerticalAlignment = VerticalAlignment.Center;
            row.Cells[0].Shading.Color = C(accent);
            Paragraph number = row.Cells[0].AddParagraph((index + 1).ToString("00"));
            number.Format.Alignment = ParagraphAlignment.Center;
            number.Format.Font.Size = 7.0;
            number.Format.Font.Bold = true;
            number.Format.Font.Color = Colors.White;

            Paragraph title = row.Cells[1].AddParagraph(IsPrimaryCheatFinding(finding)
                ? finding.DetectedCheatName ?? finding.Title
                : SanitizeSupportingTitle(finding));
            title.Format.Font.Size = 8.4;
            title.Format.Font.Bold = true;
            title.Format.Font.Color = C(Ink);
            Paragraph summary = row.Cells[1].AddParagraph(Trim(finding.Summary, 230));
            summary.Format.Font.Size = 6.8;
            summary.Format.Font.Color = C(Muted);
            summary.Format.SpaceBefore = Unit.FromPoint(2);

            row.Cells[1].Format.LeftIndent = Unit.FromPoint(7);
            row.Cells[1].Format.RightIndent = Unit.FromPoint(5);
            row.Cells[1].Format.SpaceBefore = Unit.FromPoint(4);
            row.Cells[1].Format.SpaceAfter = Unit.FromPoint(4);
            section.AddParagraph().Format.SpaceAfter = Unit.FromPoint(0);
        }
    }

    private static void AddDecisionRuleOriginal(Section section)
    {
        section.AddParagraph().Format.SpaceAfter = Unit.FromPoint(3);
        Table table = section.AddTable();
        table.AddColumn(Unit.FromCentimeter(ContentWidthCm));
        Row row = table.AddRow();
        row.Cells[0].Shading.Color = C(RedSoft);
        row.Cells[0].Borders.Color = C("#F4B8B4");
        row.Cells[0].Borders.Width = Unit.FromPoint(0.55);
        Paragraph label = row.Cells[0].AddParagraph("DECISION RULE");
        label.Format.Font.Size = 5.8;
        label.Format.Font.Bold = true;
        label.Format.Font.Color = C(Red);
        Paragraph body = row.Cells[0].AddParagraph(
            "No single neutral signal - including a second monitor, unsigned file, overlay or browser trace - is treated as proof. The final verdict is based on direct artifacts and cross-source correlation.");
        body.Format.Font.Size = 7.0;
        body.Format.Font.Color = C(RedDark);
        body.Format.SpaceBefore = Unit.FromPoint(4);
        row.Cells[0].Format.LeftIndent = Unit.FromPoint(9);
        row.Cells[0].Format.RightIndent = Unit.FromPoint(9);
        row.Cells[0].Format.SpaceBefore = Unit.FromPoint(7);
        row.Cells[0].Format.SpaceAfter = Unit.FromPoint(7);
    }

    private static void AddFindingsLedgerOriginal(Section section, ScanResult result)
    {
        Paragraph intro = section.AddParagraph("Each card shows the evidence source, weight and review priority.");
        intro.Format.Font.Size = 8.0;
        intro.Format.Font.Color = C(Muted);
        intro.Format.SpaceAfter = Unit.FromPoint(7);

        ScanFinding[] findings = AllReportFindings(result);
        if (findings.Length == 0)
        {
            AddNoticeCard(section, "No confirmed or supporting finding was produced.", Green, GreenSoft);
            return;
        }

        int index = 0;
        foreach (ScanFinding finding in findings
                     .OrderByDescending(IsPrimaryCheatFinding)
                     .ThenByDescending(x => x.Score)
                     .ThenByDescending(x => x.Timestamp))
        {
            index++;
            string category = FindingCategory(finding);
            string accent = CategoryAccent(category);
            string severity = SeverityShort(finding.Severity);

            Table card = section.AddTable();
            card.AddColumn(Unit.FromCentimeter(1.45));
            card.AddColumn(Unit.FromCentimeter(13.75));
            card.AddColumn(Unit.FromCentimeter(3.0));
            Row row = card.AddRow();
            row.VerticalAlignment = VerticalAlignment.Top;
            card.Borders.Color = C(Line);
            card.Borders.Width = Unit.FromPoint(0.5);

            row.Cells[0].Shading.Color = C(accent);
            Paragraph number = row.Cells[0].AddParagraph(index.ToString("00"));
            number.Format.Alignment = ParagraphAlignment.Center;
            number.Format.Font.Size = 8.5;
            number.Format.Font.Bold = true;
            number.Format.Font.Color = Colors.White;
            number.Format.SpaceBefore = Unit.FromPoint(8);

            row.Cells[1].Shading.Color = Colors.White;
            Paragraph categoryLine = row.Cells[1].AddParagraph(category.ToUpperInvariant());
            categoryLine.Format.Font.Size = 5.7;
            categoryLine.Format.Font.Bold = true;
            categoryLine.Format.Font.Color = C(accent);
            Paragraph title = row.Cells[1].AddParagraph(IsPrimaryCheatFinding(finding)
                ? finding.DetectedCheatName ?? finding.Title
                : SanitizeSupportingTitle(finding));
            title.Format.Font.Size = 9.0;
            title.Format.Font.Bold = true;
            title.Format.Font.Color = C(Ink);
            title.Format.SpaceBefore = Unit.FromPoint(2);
            Paragraph summary = row.Cells[1].AddParagraph(Trim(finding.Summary, 300));
            summary.Format.Font.Size = 6.9;
            summary.Format.Font.Color = C(Muted);
            summary.Format.SpaceBefore = Unit.FromPoint(4);
            if (!string.IsNullOrWhiteSpace(finding.Path))
            {
                Paragraph path = row.Cells[1].AddParagraph(Trim(finding.Path, 150));
                path.Style = "DGMono";
                path.Format.SpaceBefore = Unit.FromPoint(2);
            }
            if (finding.Reasons.Count > 0)
            {
                Paragraph reasons = row.Cells[1].AddParagraph();
                reasons.Format.Font.Size = 6.5;
                reasons.Format.Font.Color = C(Muted);
                reasons.AddFormattedText("Correlation: ", TextFormat.Bold);
                reasons.AddText(Trim(string.Join("; ", finding.Reasons), 220));
            }

            Table bar = row.Cells[1].Elements.AddTable();
            const int segments = 10;
            for (int segment = 0; segment < segments; segment++)
                bar.AddColumn(Unit.FromCentimeter(1.04));
            Row barRow = bar.AddRow();
            int filled = Math.Max(1, Math.Min(segments, (int)Math.Ceiling(Math.Min(100, finding.Score) / 10.0)));
            for (int segment = 0; segment < segments; segment++)
            {
                barRow.Cells[segment].Shading.Color = C(segment < filled ? accent : "#E1DED8");
                barRow.Cells[segment].Format.SpaceBefore = Unit.FromPoint(1.2);
                barRow.Cells[segment].Format.SpaceAfter = Unit.FromPoint(1.2);
                barRow.Cells[segment].Format.RightIndent = Unit.FromPoint(0.5);
            }

            row.Cells[2].Shading.Color = Colors.White;
            Paragraph severityLine = row.Cells[2].AddParagraph(severity);
            severityLine.Format.Alignment = ParagraphAlignment.Right;
            severityLine.Format.Font.Size = 5.8;
            severityLine.Format.Font.Bold = true;
            severityLine.Format.Font.Color = C(accent);
            Paragraph score = row.Cells[2].AddParagraph(finding.Score.ToString("N0"));
            score.Format.Alignment = ParagraphAlignment.Right;
            score.Format.Font.Name = "Segoe UI Semibold";
            score.Format.Font.Size = 17;
            score.Format.Font.Bold = true;
            score.Format.Font.Color = C(accent);
            score.Format.SpaceBefore = Unit.FromPoint(2);
            Paragraph source = row.Cells[2].AddParagraph(Trim(finding.EvidenceSource, 45));
            source.Format.Alignment = ParagraphAlignment.Right;
            source.Format.Font.Size = 5.8;
            source.Format.Font.Color = C(Muted);
            source.Format.SpaceBefore = Unit.FromPoint(7);

            foreach (Cell? cell in row.Cells)
            {
                if (cell is null) continue;
                cell.Format.LeftIndent = Unit.FromPoint(6);
                cell.Format.RightIndent = Unit.FromPoint(6);
                cell.Format.SpaceBefore = Unit.FromPoint(6);
                cell.Format.SpaceAfter = Unit.FromPoint(6);
            }
            section.AddParagraph().Format.SpaceAfter = Unit.FromPoint(2);
        }
    }

    private static void AddCoverageTrustMap(Section section, ScanResult result)
    {
        Paragraph intro = section.AddParagraph("Coverage is displayed as independent modules rather than a single pass/fail line.");
        intro.Format.Font.Size = 8.0;
        intro.Format.Font.Color = C(Muted);
        intro.Format.SpaceAfter = Unit.FromPoint(7);

        Table outer = section.AddTable();
        outer.AddColumn(Unit.FromCentimeter(9.0));
        outer.AddColumn(Unit.FromCentimeter(9.2));

        for (int index = 0; index < result.Coverage.Count; index += 2)
        {
            Row row = outer.AddRow();
            for (int column = 0; column < 2; column++)
            {
                int itemIndex = index + column;
                if (itemIndex >= result.Coverage.Count)
                    continue;

                ScanCoverage coverage = result.Coverage[itemIndex];
                string accent = CoverageColor(coverage.Status);
                Table card = row.Cells[column].Elements.AddTable();
                card.AddColumn(Unit.FromCentimeter(1.3));
                card.AddColumn(Unit.FromCentimeter(column == 0 ? 7.45 : 7.65));
                Row cardRow = card.AddRow();
                card.Borders.Color = C(Line);
                card.Borders.Width = Unit.FromPoint(0.5);
                cardRow.Cells[0].Shading.Color = C(accent);
                cardRow.Cells[1].Shading.Color = Colors.White;

                Paragraph number = cardRow.Cells[0].AddParagraph((itemIndex + 1).ToString("00"));
                number.Format.Alignment = ParagraphAlignment.Center;
                number.Format.Font.Size = 7.0;
                number.Format.Font.Bold = true;
                number.Format.Font.Color = Colors.White;
                number.Format.SpaceBefore = Unit.FromPoint(7);

                Paragraph status = cardRow.Cells[1].AddParagraph(coverage.Status.ToString().ToUpperInvariant());
                status.Format.Font.Size = 5.7;
                status.Format.Font.Bold = true;
                status.Format.Font.Color = C(accent);
                Paragraph title = cardRow.Cells[1].AddParagraph(coverage.Module.ToUpperInvariant());
                title.Format.Font.Size = 8.2;
                title.Format.Font.Bold = true;
                title.Format.Font.Color = C(Ink);
                title.Format.SpaceBefore = Unit.FromPoint(2);
                Paragraph checkedLine = cardRow.Cells[1].AddParagraph($"{coverage.ItemsChecked:N0} checked   |   {DurationText(coverage.Duration)}");
                checkedLine.Format.Font.Size = 5.8;
                checkedLine.Format.Font.Color = C(Muted);
                checkedLine.Format.SpaceBefore = Unit.FromPoint(2);
                Paragraph summary = cardRow.Cells[1].AddParagraph(Trim(coverage.Summary, 150));
                summary.Format.Font.Size = 6.5;
                summary.Format.Font.Color = C(Muted);
                summary.Format.SpaceBefore = Unit.FromPoint(4);

                cardRow.Cells[1].Borders.Bottom.Color = C(accent);
                cardRow.Cells[1].Borders.Bottom.Width = Unit.FromPoint(2.4);
                foreach (Cell? cell in cardRow.Cells)
                {
                    if (cell is null) continue;
                    cell.Format.LeftIndent = Unit.FromPoint(6);
                    cell.Format.RightIndent = Unit.FromPoint(6);
                    cell.Format.SpaceBefore = Unit.FromPoint(5);
                    cell.Format.SpaceAfter = Unit.FromPoint(5);
                }
            }
            row.Cells[0].Format.RightIndent = Unit.FromPoint(3);
            row.Cells[1].Format.LeftIndent = Unit.FromPoint(3);
            outer.AddRow().Height = Unit.FromPoint(4);
        }
    }

    private static void AddDmaCorrelationGate(Section section, ScanResult result)
    {
        H(section, "DMA CORRELATION GATE");
        Table table = section.AddTable();
        table.AddColumn(Unit.FromCentimeter(10.2));
        table.AddColumn(Unit.FromCentimeter(8.0));
        Row row = table.AddRow();
        row.Cells[0].Shading.Color = C(Ink);
        row.Cells[1].Shading.Color = C(Ink);

        Paragraph title = row.Cells[0].AddParagraph("Hardware alone is not a conviction.");
        title.Format.Font.Name = "Segoe UI Semibold";
        title.Format.Font.Size = 13.5;
        title.Format.Font.Bold = true;
        title.Format.Font.Color = Colors.White;
        Paragraph body = row.Cells[0].AddParagraph(
            "DMA is escalated only when device metadata overlaps with known software, service, task, driver or execution evidence.");
        body.Format.Font.Size = 6.9;
        body.Format.Font.Color = C("#C7C7CC");
        body.Format.SpaceBefore = Unit.FromPoint(6);

        Table gate = row.Cells[1].Elements.AddTable();
        gate.AddColumn(Unit.FromCentimeter(2.45));
        gate.AddColumn(Unit.FromCentimeter(0.55));
        gate.AddColumn(Unit.FromCentimeter(2.45));
        gate.AddColumn(Unit.FromCentimeter(0.55));
        gate.AddColumn(Unit.FromCentimeter(2.0));
        Row gateRow = gate.AddRow();
        AddGateStep(gateRow.Cells[0], "1", "DEVICE", "PnP / PCIe", Red);
        gateRow.Cells[1].AddParagraph(">").Format.Alignment = ParagraphAlignment.Center;
        gateRow.Cells[1].Format.Font.Color = C("#78787E");
        gateRow.Cells[1].VerticalAlignment = VerticalAlignment.Center;
        AddGateStep(gateRow.Cells[2], "2", "SOFTWARE", "Driver / service", Red);
        gateRow.Cells[3].AddParagraph(">").Format.Alignment = ParagraphAlignment.Center;
        gateRow.Cells[3].Format.Font.Color = C("#78787E");
        gateRow.Cells[3].VerticalAlignment = VerticalAlignment.Center;
        AddGateStep(gateRow.Cells[4], "3", "CORRELATE", "High confidence", Green);

        foreach (Cell? cell in row.Cells)
        {
            if (cell is null) continue;
            cell.Format.LeftIndent = Unit.FromPoint(10);
            cell.Format.RightIndent = Unit.FromPoint(10);
            cell.Format.SpaceBefore = Unit.FromPoint(9);
            cell.Format.SpaceAfter = Unit.FromPoint(9);
        }

        bool dmaFinding = result.Findings.Any(x => FindingCategory(x) == "Hardware / DMA" && x.Score >= 50);
        Paragraph status = section.AddParagraph(dmaFinding
            ? "Result: correlated DMA evidence requires manual review."
            : "Result: no high-confidence hardware-plus-software DMA correlation was confirmed.");
        status.Format.Font.Size = 6.7;
        status.Format.Font.Bold = true;
        status.Format.Font.Color = C(dmaFinding ? Red : Green);
        status.Format.SpaceBefore = Unit.FromPoint(4);
    }

    private static void AddGateStep(Cell cell, string number, string title, string detail, string accent)
    {
        cell.Shading.Color = C(accent);
        Paragraph n = cell.AddParagraph(number);
        n.Format.Alignment = ParagraphAlignment.Center;
        n.Format.Font.Size = 8.0;
        n.Format.Font.Bold = true;
        n.Format.Font.Color = Colors.White;
        Paragraph t = cell.AddParagraph(title);
        t.Format.Alignment = ParagraphAlignment.Center;
        t.Format.Font.Size = 5.4;
        t.Format.Font.Bold = true;
        t.Format.Font.Color = Colors.White;
        Paragraph d = cell.AddParagraph(detail);
        d.Format.Alignment = ParagraphAlignment.Center;
        d.Format.Font.Size = 4.8;
        d.Format.Font.Color = Colors.White;
        cell.Format.LeftIndent = Unit.FromPoint(3);
        cell.Format.RightIndent = Unit.FromPoint(3);
        cell.Format.SpaceBefore = Unit.FromPoint(5);
        cell.Format.SpaceAfter = Unit.FromPoint(5);
    }

    private static void AddOriginalIntegrity(Section section, ScanResult result)
    {
        H(section, "REPORT INTEGRITY");
        (string Label, string Value)[] values =
        {
            ("SCANNER HASH", Trim(result.ScannerBinaryHash, 24)),
            ("EVIDENCE HASH", Trim(result.EvidenceJsonHash ?? "Unavailable", 24)),
            ("RULE DATABASE", result.RuleDatabaseVersion),
            ("PRIVACY", Trim(result.PrivacyStatement, 45))
        };

        Table table = section.AddTable();
        for (int index = 0; index < values.Length; index++)
            table.AddColumn(Unit.FromCentimeter(ContentWidthCm / values.Length));
        Row row = table.AddRow();
        for (int index = 0; index < values.Length; index++)
        {
            row.Cells[index].Shading.Color = Colors.White;
            row.Cells[index].Borders.Color = C(Line);
            row.Cells[index].Borders.Width = Unit.FromPoint(0.45);
            Paragraph label = row.Cells[index].AddParagraph(values[index].Label);
            label.Format.Font.Size = 5.5;
            label.Format.Font.Bold = true;
            label.Format.Font.Color = C(Muted);
            Paragraph value = row.Cells[index].AddParagraph(values[index].Value);
            value.Format.Font.Size = 6.7;
            value.Format.Font.Bold = true;
            value.Format.Font.Color = C(Ink);
            value.Format.SpaceBefore = Unit.FromPoint(6);
            row.Cells[index].Format.LeftIndent = Unit.FromPoint(7);
            row.Cells[index].Format.RightIndent = Unit.FromPoint(7);
            row.Cells[index].Format.SpaceBefore = Unit.FromPoint(7);
            row.Cells[index].Format.SpaceAfter = Unit.FromPoint(7);
        }
    }

    private static void AddBrandHeader(Section section, ScanResult result)
    {
        Table table = section.AddTable();
        table.AddColumn(Unit.FromCentimeter(1.65));
        table.AddColumn(Unit.FromCentimeter(10.7));
        table.AddColumn(Unit.FromCentimeter(5.85));

        Row row = table.AddRow();
        row.Shading.Color = C(Navy);
        row.VerticalAlignment = VerticalAlignment.Center;
        row.Height = Unit.FromCentimeter(2.05);

        string? logoPath = TryResolveLogoPath();
        if (!string.IsNullOrWhiteSpace(logoPath) && File.Exists(logoPath))
        {
            Paragraph logo = row.Cells[0].AddParagraph();
            logo.Format.Alignment = ParagraphAlignment.Center;
            var image = logo.AddImage(logoPath);
            image.LockAspectRatio = true;
            image.Height = Unit.FromCentimeter(1.2);
        }

        Paragraph brand = row.Cells[1].AddParagraph();
        brand.Style = "DGBrand";
        brand.AddText("DOUBLEG SCANNER");

        Paragraph subtitle = row.Cells[1].AddParagraph("CS2 INTEGRITY & CHEAT DETECTION REPORT");
        subtitle.Format.Font.Size = 7.5;
        subtitle.Format.Font.Color = C("#AAB6CF");
        subtitle.Format.SpaceBefore = Unit.FromPoint(-1);

        Paragraph meta = row.Cells[2].AddParagraph();
        meta.Style = "DGMono";
        meta.Format.Alignment = ParagraphAlignment.Right;
        meta.Format.Font.Color = C("#C7D2E8");
        meta.AddText(result.CompletedAt.ToString("yyyy-MM-dd  HH:mm:ss zzz"));
        meta.AddLineBreak();
        meta.AddText($"{result.MachineName}  |  {result.ScannerVersion}");
        meta.AddLineBreak();
        FormattedText mode = meta.AddFormattedText(result.Mode.ToString().ToUpperInvariant(), TextFormat.Bold);
        mode.Color = C("#A78BFA");

        foreach (Cell? cell in row.Cells)
        {
            if (cell is null) continue;
            cell.Format.LeftIndent = Unit.FromPoint(6);
            cell.Format.RightIndent = Unit.FromPoint(6);
            cell.Format.SpaceBefore = Unit.FromPoint(4);
            cell.Format.SpaceAfter = Unit.FromPoint(4);
        }

        Table accent = section.AddTable();
        accent.AddColumn(Unit.FromCentimeter(ContentWidthCm));
        Row accentRow = accent.AddRow();
        accentRow.Height = Unit.FromPoint(2.2);
        accentRow.Cells[0].Shading.Color = C(Purple);
        section.AddParagraph().Format.SpaceAfter = Unit.FromPoint(1);
    }

    private static void AddHero(Section section, ScanResult result)
    {
        string riskColor = RiskColor(result);
        string riskSoft = RiskSoftColor(result);
        ScanFinding[] primary = PrimaryCheatFindings(result);
        ScanFinding[] supporting = SupportingFindings(result);

        Table table = section.AddTable();
        table.AddColumn(Unit.FromCentimeter(0.22));
        table.AddColumn(Unit.FromCentimeter(4.0));
        table.AddColumn(Unit.FromCentimeter(9.2));
        table.AddColumn(Unit.FromCentimeter(4.78));
        Row row = table.AddRow();
        row.VerticalAlignment = VerticalAlignment.Center;

        row.Cells[0].Shading.Color = C(riskColor);
        for (int index = 1; index < 4; index++)
            row.Cells[index].Shading.Color = C(Navy);

        Paragraph score = row.Cells[1].AddParagraph(result.RiskScore.ToString("N0"));
        score.Format.Alignment = ParagraphAlignment.Center;
        score.Format.Font.Name = "Segoe UI Semibold";
        score.Format.Font.Size = 27;
        score.Format.Font.Bold = true;
        score.Format.Font.Color = Colors.White;
        score.Format.SpaceBefore = Unit.FromPoint(12);

        Paragraph scoreLabel = row.Cells[1].AddParagraph("RISK SCORE");
        scoreLabel.Format.Alignment = ParagraphAlignment.Center;
        scoreLabel.Format.Font.Size = 6.8;
        scoreLabel.Format.Font.Bold = true;
        scoreLabel.Format.Font.Color = C("#8E9AB5");
        scoreLabel.Format.SpaceAfter = Unit.FromPoint(12);

        Paragraph risk = row.Cells[2].AddParagraph(RiskBand(result));
        risk.Format.Font.Size = 7.4;
        risk.Format.Font.Bold = true;
        risk.Format.Font.Color = C(riskColor);
        risk.Format.SpaceBefore = Unit.FromPoint(8);

        Paragraph verdict = row.Cells[2].AddParagraph(VerdictTitle(result.Verdict));
        verdict.Format.Font.Name = "Segoe UI Semibold";
        verdict.Format.Font.Size = 17.5;
        verdict.Format.Font.Bold = true;
        verdict.Format.Font.Color = Colors.White;
        verdict.Format.SpaceBefore = Unit.FromPoint(2);

        Paragraph summary = row.Cells[2].AddParagraph(VerdictText(result.Verdict));
        summary.Format.Font.Size = 7.7;
        summary.Format.Font.Color = C("#AAB6CF");
        summary.Format.SpaceBefore = Unit.FromPoint(3);
        summary.Format.SpaceAfter = Unit.FromPoint(5);

        Table countTable = row.Cells[3].Elements.AddTable();
        countTable.AddColumn(Unit.FromCentimeter(2.3));
        countTable.AddColumn(Unit.FromCentimeter(2.3));
        Row labels = countTable.AddRow();
        labels.Cells[0].AddParagraph("DETECTIONS");
        labels.Cells[1].AddParagraph("SUPPORTING");
        labels.Format.Font.Size = 6.2;
        labels.Format.Font.Bold = true;
        labels.Format.Font.Color = C("#AAB6CF");
        labels.Format.Alignment = ParagraphAlignment.Center;

        Row values = countTable.AddRow();
        values.Cells[0].AddParagraph(primary.Length.ToString("N0"));
        values.Cells[1].AddParagraph(supporting.Length.ToString("N0"));
        values.Format.Font.Name = "Segoe UI Semibold";
        values.Format.Font.Size = 20;
        values.Format.Font.Bold = true;
        values.Format.Font.Color = Colors.White;
        values.Format.Alignment = ParagraphAlignment.Center;

        Row pill = countTable.AddRow();
        pill.Cells[0].MergeRight = 1;
        pill.Cells[0].Shading.Color = C(riskSoft);
        Paragraph pillText = pill.Cells[0].AddParagraph(result.Verdict == ScanVerdict.NotDetected
            ? "SCAN COMPLETED"
            : "MANUAL REVIEW");
        pillText.Format.Alignment = ParagraphAlignment.Center;
        pillText.Format.Font.Size = 6.7;
        pillText.Format.Font.Bold = true;
        pillText.Format.Font.Color = C(result.Verdict == ScanVerdict.NotDetected ? Green : RedDark);

        foreach (Cell? cell in row.Cells)
        {
            if (cell is null) continue;
            cell.Format.LeftIndent = Unit.FromPoint(5);
            cell.Format.RightIndent = Unit.FromPoint(5);
            cell.Format.SpaceBefore = Unit.FromPoint(5);
            cell.Format.SpaceAfter = Unit.FromPoint(5);
        }

        table.Borders.Color = C(Navy);
        table.Borders.Width = Unit.FromPoint(0.4);
        section.AddParagraph().Format.SpaceAfter = Unit.FromPoint(1);
    }

    private static void AddMetricGrid(Section section, ScanResult result)
    {
        int completed = result.Coverage.Count(x => x.Status == CoverageStatus.Completed);
        long checkedItems = result.Coverage.Sum(x => (long)x.ItemsChecked);
        TimeSpan duration = result.CompletedAt - result.StartedAt;

        (string Label, string Value, string? Accent)[] metrics =
        {
            ("EVIDENCE", result.Evidence.Count.ToString("N0"), null),
            ("DETECTIONS", PrimaryCheatFindings(result).Length.ToString("N0"), Red),
            ("REVIEW", SupportingFindings(result).Length.ToString("N0"), Amber),
            ("MODULES", $"{completed}/{result.Coverage.Count}", null),
            ("CHECKED", checkedItems.ToString("N0"), null),
            ("DURATION", DurationText(duration), null)
        };

        Table outer = section.AddTable();
        double width = ContentWidthCm / metrics.Length;
        foreach (var _ in metrics)
            outer.AddColumn(Unit.FromCentimeter(width));

        Row row = outer.AddRow();
        for (int index = 0; index < metrics.Length; index++)
        {
            Table card = row.Cells[index].Elements.AddTable();
            card.AddColumn(Unit.FromCentimeter(width - 0.12));
            Row cardRow = card.AddRow();
            cardRow.Cells[0].Shading.Color = Colors.White;
            cardRow.Cells[0].Borders.Color = C(Line);
            cardRow.Cells[0].Borders.Width = Unit.FromPoint(0.55);

            Paragraph label = cardRow.Cells[0].AddParagraph(metrics[index].Label);
            label.Format.Font.Size = 6.2;
            label.Format.Font.Bold = true;
            label.Format.Font.Color = C(Muted);

            Paragraph value = cardRow.Cells[0].AddParagraph(metrics[index].Value);
            value.Format.Font.Name = "Segoe UI Semibold";
            value.Format.Font.Size = 11.7;
            value.Format.Font.Bold = true;
            value.Format.Font.Color = C(metrics[index].Accent ?? Ink);
            value.Format.SpaceBefore = Unit.FromPoint(2);

            cardRow.Cells[0].Format.LeftIndent = Unit.FromPoint(5);
            cardRow.Cells[0].Format.RightIndent = Unit.FromPoint(4);
            cardRow.Cells[0].Format.SpaceBefore = Unit.FromPoint(5);
            cardRow.Cells[0].Format.SpaceAfter = Unit.FromPoint(5);
        }

        foreach (Cell? cell in row.Cells)
        {
            if (cell is null) continue;
            cell.Format.RightIndent = Unit.FromPoint(2);
        }

        section.AddParagraph().Format.SpaceAfter = Unit.FromPoint(1);
    }

    private static void AddSystemStrip(Section section, ScanResult result)
    {
        Table table = section.AddTable();
        for (int index = 0; index < 4; index++)
            table.AddColumn(Unit.FromCentimeter(ContentWidthCm / 4));

        Row labels = table.AddRow();
        string[] names = { "MACHINE", "WINDOWS USER", "ACCESS", "SCAN MODE" };
        for (int index = 0; index < names.Length; index++)
        {
            labels.Cells[index].AddParagraph(names[index]);
            labels.Cells[index].Shading.Color = C(Soft);
        }
        labels.Format.Font.Size = 6.2;
        labels.Format.Font.Bold = true;
        labels.Format.Font.Color = C(Muted);

        Row values = table.AddRow();
        string[] data =
        {
            result.MachineName,
            result.WindowsUser,
            result.IsElevated ? "Administrator" : "Standard user",
            result.Mode.ToString()
        };
        for (int index = 0; index < data.Length; index++)
        {
            Paragraph value = values.Cells[index].AddParagraph(data[index]);
            value.Format.Font.Size = 8.1;
            value.Format.Font.Bold = index == 0 || index == 2;
            values.Cells[index].Shading.Color = C(Soft);
        }

        table.Borders.Color = C(Line);
        table.Borders.Width = Unit.FromPoint(0.45);
        foreach (Row? row in table.Rows)
        {
            if (row is null) continue;
            foreach (Cell? cell in row.Cells)
            {
                if (cell is null) continue;
                cell.Format.LeftIndent = Unit.FromPoint(5);
                cell.Format.RightIndent = Unit.FromPoint(5);
                cell.Format.SpaceBefore = Unit.FromPoint(3.5);
                cell.Format.SpaceAfter = Unit.FromPoint(3.5);
            }
        }
    }

    private static void AddCategoryBreakdown(Section section, ScanResult result)
    {
        H(section, "BREAKDOWN BY CATEGORY");

        ScanFinding[] findings = AllReportFindings(result);
        if (findings.Length == 0)
        {
            AddNoticeCard(section, "No reportable category count was generated.", Green, GreenSoft);
            return;
        }

        var groups = findings
            .GroupBy(x => FindingCategory(x))
            .Select(x => new { Category = x.Key, Count = x.Count() })
            .OrderBy(x => CategoryOrder(x.Category))
            .ThenByDescending(x => x.Count)
            .ToArray();
        int maximum = Math.Max(1, groups.Max(x => x.Count));

        Table table = section.AddTable();
        table.AddColumn(Unit.FromCentimeter(4.75));
        table.AddColumn(Unit.FromCentimeter(1.0));
        table.AddColumn(Unit.FromCentimeter(12.45));

        foreach (var group in groups)
        {
            Row row = table.AddRow();
            Paragraph label = row.Cells[0].AddParagraph(group.Category.ToUpperInvariant());
            label.Format.Font.Size = 6.8;
            label.Format.Font.Bold = true;
            label.Format.Font.Color = C(Ink);

            Paragraph count = row.Cells[1].AddParagraph(group.Count.ToString());
            count.Format.Alignment = ParagraphAlignment.Right;
            count.Format.Font.Size = 7;
            count.Format.Font.Bold = true;
            count.Format.Font.Color = C(Muted);

            Table bar = row.Cells[2].Elements.AddTable();
            const int segments = 20;
            for (int index = 0; index < segments; index++)
                bar.AddColumn(Unit.FromCentimeter(0.47));
            Row barRow = bar.AddRow();
            int filled = Math.Max(1, (int)Math.Ceiling(group.Count / (double)maximum * segments));
            string accent = CategoryAccent(group.Category);
            for (int index = 0; index < segments; index++)
            {
                barRow.Cells[index].Shading.Color = C(index < filled ? accent : "#E8EDF5");
                barRow.Cells[index].Format.SpaceBefore = Unit.FromPoint(1.8);
                barRow.Cells[index].Format.SpaceAfter = Unit.FromPoint(1.8);
                barRow.Cells[index].Format.RightIndent = Unit.FromPoint(0.6);
            }

            foreach (Cell? cell in row.Cells)
            {
                if (cell is null) continue;
                cell.VerticalAlignment = VerticalAlignment.Center;
                cell.Format.SpaceBefore = Unit.FromPoint(2.2);
                cell.Format.SpaceAfter = Unit.FromPoint(2.2);
            }
        }
    }

    private static void AddFindings(Section section, ScanResult result)
    {
        H(section, "FINDINGS");
        ScanFinding[] findings = AllReportFindings(result);
        if (findings.Length == 0)
        {
            AddNoticeCard(
                section,
                "No confirmed or supporting finding was produced by the completed modules.",
                Green,
                GreenSoft);
            return;
        }

        foreach (IGrouping<string, ScanFinding> group in findings
                     .GroupBy(FindingCategory)
                     .OrderBy(x => CategoryOrder(x.Key)))
        {
            AddFindingGroupHeader(section, group.Key, group.Count(), CategoryAccent(group.Key));
            foreach (ScanFinding finding in group
                         .OrderByDescending(IsPrimaryCheatFinding)
                         .ThenByDescending(x => x.Score)
                         .ThenByDescending(x => x.Timestamp)
                         .Take(30))
            {
                AddFindingCard(section, finding, CategoryAccent(group.Key));
            }

            if (group.Count() > 30)
            {
                Paragraph more = section.AddParagraph($"{group.Count() - 30:N0} additional item(s) are available in the evidence JSON.");
                more.Style = "DGSmall";
                more.Format.SpaceAfter = Unit.FromPoint(4);
            }
        }
    }

    private static void AddFindingGroupHeader(Section section, string category, int count, string accent)
    {
        Table table = section.AddTable();
        table.AddColumn(Unit.FromCentimeter(0.22));
        table.AddColumn(Unit.FromCentimeter(15.6));
        table.AddColumn(Unit.FromCentimeter(2.38));
        Row row = table.AddRow();
        row.Height = Unit.FromCentimeter(0.78);
        row.VerticalAlignment = VerticalAlignment.Center;
        row.Cells[0].Shading.Color = C(accent);
        row.Cells[1].Shading.Color = C(Navy2);
        row.Cells[2].Shading.Color = C(accent);

        Paragraph title = row.Cells[1].AddParagraph(category.ToUpperInvariant());
        title.Format.Font.Size = 7.3;
        title.Format.Font.Bold = true;
        title.Format.Font.Color = Colors.White;

        Paragraph badge = row.Cells[2].AddParagraph(count.ToString("N0"));
        badge.Format.Alignment = ParagraphAlignment.Center;
        badge.Format.Font.Size = 7.5;
        badge.Format.Font.Bold = true;
        badge.Format.Font.Color = Colors.White;

        row.Cells[1].Format.LeftIndent = Unit.FromPoint(6);
        section.AddParagraph().Format.SpaceAfter = Unit.FromPoint(0);
    }

    private static void AddFindingCard(Section section, ScanFinding finding, string accent)
    {
        string severityColor = SeverityColor(finding.Severity);
        Table table = section.AddTable();
        table.AddColumn(Unit.FromCentimeter(1.62));
        table.AddColumn(Unit.FromCentimeter(12.55));
        table.AddColumn(Unit.FromCentimeter(4.03));
        Row row = table.AddRow();
        row.VerticalAlignment = VerticalAlignment.Center;

        row.Cells[0].Shading.Color = C(severityColor);
        Paragraph severity = row.Cells[0].AddParagraph(SeverityShort(finding.Severity));
        severity.Format.Alignment = ParagraphAlignment.Center;
        severity.Format.Font.Size = 6.8;
        severity.Format.Font.Bold = true;
        severity.Format.Font.Color = Colors.White;

        row.Cells[1].Shading.Color = Colors.White;
        Paragraph title = row.Cells[1].AddParagraph();
        title.Format.Font.Size = 8.2;
        title.Format.Font.Bold = true;
        title.Format.Font.Color = C(Ink);
        title.AddText(IsPrimaryCheatFinding(finding)
            ? finding.DetectedCheatName ?? finding.Title
            : SanitizeSupportingTitle(finding));

        Paragraph details = row.Cells[1].AddParagraph();
        details.Format.Font.Size = 6.9;
        details.Format.Font.Color = C(Muted);
        if (!string.IsNullOrWhiteSpace(finding.Path))
        {
            details.AddText(Trim(finding.Path, 150));
            details.AddLineBreak();
        }
        details.AddText(Trim(finding.Summary, 240));

        if (finding.Reasons.Count > 0)
        {
            Paragraph reasons = row.Cells[1].AddParagraph();
            reasons.Format.Font.Size = 6.6;
            reasons.Format.Font.Color = C(Muted);
            reasons.AddFormattedText("Correlation: ", TextFormat.Bold);
            reasons.AddText(Trim(string.Join("; ", finding.Reasons), 220));
        }

        row.Cells[2].Shading.Color = Colors.White;
        Paragraph score = row.Cells[2].AddParagraph($"score {finding.Score:N0}");
        score.Format.Alignment = ParagraphAlignment.Right;
        score.Format.Font.Size = 7;
        score.Format.Font.Bold = true;
        score.Format.Font.Color = C(accent);

        Paragraph source = row.Cells[2].AddParagraph(Trim(finding.EvidenceSource, 58));
        source.Format.Alignment = ParagraphAlignment.Right;
        source.Format.Font.Size = 6.3;
        source.Format.Font.Color = C(Muted);

        if (finding.Timestamp is not null)
        {
            Paragraph time = row.Cells[2].AddParagraph(finding.Timestamp.Value.ToString("yyyy-MM-dd HH:mm"));
            time.Format.Alignment = ParagraphAlignment.Right;
            time.Format.Font.Size = 6.1;
            time.Format.Font.Color = C(Muted);
        }

        table.Borders.Color = C(Line);
        table.Borders.Width = Unit.FromPoint(0.42);
        foreach (Cell? cell in row.Cells)
        {
            if (cell is null) continue;
            cell.Format.LeftIndent = Unit.FromPoint(5);
            cell.Format.RightIndent = Unit.FromPoint(5);
            cell.Format.SpaceBefore = Unit.FromPoint(4.5);
            cell.Format.SpaceAfter = Unit.FromPoint(4.5);
        }
    }

    private static void AddCoverage(Section section, ScanResult result)
    {
        H(section, "SCAN COVERAGE");
        Table table = section.AddTable();
        table.AddColumn(Unit.FromCentimeter(4.0));
        table.AddColumn(Unit.FromCentimeter(2.15));
        table.AddColumn(Unit.FromCentimeter(2.0));
        table.AddColumn(Unit.FromCentimeter(1.75));
        table.AddColumn(Unit.FromCentimeter(8.3));
        AddHeader(table, "MODULE", "STATUS", "CHECKED", "TIME", "SUMMARY");

        int rowIndex = 0;
        foreach (ScanCoverage coverage in result.Coverage)
        {
            Row row = table.AddRow();
            row.Shading.Color = C(rowIndex++ % 2 == 0 ? "#FFFFFF" : Soft);
            row.Cells[0].AddParagraph(coverage.Module);

            Paragraph status = row.Cells[1].AddParagraph(coverage.Status.ToString().ToUpperInvariant());
            status.Format.Font.Bold = true;
            status.Format.Font.Color = C(CoverageColor(coverage.Status));

            row.Cells[2].AddParagraph(coverage.ItemsChecked.ToString("N0"));
            row.Cells[3].AddParagraph(DurationText(coverage.Duration));
            row.Cells[4].AddParagraph(coverage.Summary);
        }

        table.Borders.Color = C(Line);
        table.Borders.Width = Unit.FromPoint(0.42);
        FormatTable(table, 3.7);
    }

    private static void AddEvidenceReview(Section section, ScanResult result)
    {
        H(section, "EVIDENCE REVIEW");
        Paragraph intro = section.AddParagraph(
            "Runtime, persistence, kernel, DMA, browser, file, deleted-trace, network, and Defender evidence are separated below. A single neutral trace is not treated as proof by itself.");
        intro.Format.Font.Size = 7.4;
        intro.Format.Font.Color = C(Muted);

        AddEvidenceArticle(section, result,
            "RUNTIME & INJECTION",
            Purple,
            new[] { EvidenceKind.Process, EvidenceKind.ProcessHandle, EvidenceKind.Module, EvidenceKind.Overlay, EvidenceKind.MemoryRegion });

        AddEvidenceArticle(section, result,
            "PERSISTENCE",
            Amber,
            new[] { EvidenceKind.Persistence });

        AddEvidenceArticle(section, result,
            "KERNEL & DMA",
            Cyan,
            new[] { EvidenceKind.KernelSecurity, EvidenceKind.KernelDriver, EvidenceKind.CodeIntegrity, EvidenceKind.DmaDevice });

        AddEvidenceArticle(section, result,
            "BROWSER & EXECUTION",
            Purple,
            new[] { EvidenceKind.Browser, EvidenceKind.Execution });

        AddEvidenceArticle(section, result,
            "FILES & DELETED TRACES",
            Red,
            new[] { EvidenceKind.FileArtifact, EvidenceKind.DeletedFile, EvidenceKind.NtfsMetadata, EvidenceKind.UsnJournal, EvidenceKind.RawDeletedFile });

        AddEvidenceArticle(section, result,
            "NETWORK & DEFENDER",
            Green,
            new[] { EvidenceKind.Network, EvidenceKind.Antivirus });
    }

    private static void AddEvidenceArticle(
        Section section,
        ScanResult result,
        string title,
        string accent,
        IReadOnlyCollection<EvidenceKind> kinds)
    {
        EvidenceRecord[] evidence = result.Evidence
            .Where(x => kinds.Contains(x.Kind))
            .OrderByDescending(x => x.Timestamp)
            .ToArray();
        if (evidence.Length == 0)
            return;

        Table heading = section.AddTable();
        heading.AddColumn(Unit.FromCentimeter(0.2));
        heading.AddColumn(Unit.FromCentimeter(15.2));
        heading.AddColumn(Unit.FromCentimeter(2.8));
        Row headingRow = heading.AddRow();
        headingRow.Cells[0].Shading.Color = C(accent);
        headingRow.Cells[1].Shading.Color = C(Navy2);
        headingRow.Cells[2].Shading.Color = C(Navy2);
        Paragraph headingText = headingRow.Cells[1].AddParagraph(title);
        headingText.Format.Font.Size = 7.1;
        headingText.Format.Font.Bold = true;
        headingText.Format.Font.Color = Colors.White;
        Paragraph count = headingRow.Cells[2].AddParagraph($"{evidence.Length:N0} evidence");
        count.Format.Alignment = ParagraphAlignment.Right;
        count.Format.Font.Size = 6.6;
        count.Format.Font.Color = C("#C7D2E8");
        headingRow.Cells[1].Format.LeftIndent = Unit.FromPoint(5);
        headingRow.Cells[2].Format.RightIndent = Unit.FromPoint(5);
        headingRow.Cells[1].Format.SpaceBefore = Unit.FromPoint(3.5);
        headingRow.Cells[1].Format.SpaceAfter = Unit.FromPoint(3.5);
        headingRow.Cells[2].Format.SpaceBefore = Unit.FromPoint(3.5);
        headingRow.Cells[2].Format.SpaceAfter = Unit.FromPoint(3.5);

        Table table = section.AddTable();
        table.AddColumn(Unit.FromCentimeter(2.65));
        table.AddColumn(Unit.FromCentimeter(3.55));
        table.AddColumn(Unit.FromCentimeter(12.0));
        AddHeader(table, "TIME", "ITEM", "DETAIL");

        int index = 0;
        foreach (EvidenceRecord item in evidence.Take(12))
        {
            Row row = table.AddRow();
            row.Shading.Color = C(index++ % 2 == 0 ? "#FFFFFF" : Soft);
            row.Cells[0].AddParagraph(item.Timestamp?.ToString("yyyy-MM-dd HH:mm") ?? "-");
            row.Cells[1].AddParagraph(Trim(item.Name, 55));
            row.Cells[2].AddParagraph(PrimaryDetail(item));
        }

        table.Borders.Color = C(Line);
        table.Borders.Width = Unit.FromPoint(0.35);
        FormatTable(table, 3.2);

        if (evidence.Length > 12)
        {
            Paragraph more = section.AddParagraph($"{evidence.Length - 12:N0} additional evidence line(s) are available in the evidence JSON.");
            more.Style = "DGSmall";
        }
    }

    private static void AddIntegrity(Section section, ScanResult result)
    {
        H(section, "REPORT INTEGRITY");
        Table table = section.AddTable();
        table.AddColumn(Unit.FromCentimeter(4.85));
        table.AddColumn(Unit.FromCentimeter(13.35));
        AddIntegrityRow(table, "SCANNER BINARY SHA-256", result.ScannerBinaryHash);
        AddIntegrityRow(table, "EVIDENCE JSON SHA-256", result.EvidenceJsonHash ?? "Unavailable");
        AddIntegrityRow(table, "RULE DATABASE", result.RuleDatabaseVersion);
        AddIntegrityRow(table, "PRIVACY MODE", "Local-only / read-only / no upload / no deletion");
        table.Borders.Color = C(Line);
        table.Borders.Width = Unit.FromPoint(0.42);
    }

    private static void AddIntegrityRow(Table table, string label, string value)
    {
        Row row = table.AddRow();
        row.Cells[0].Shading.Color = C(PurpleSoft);
        row.Cells[1].Shading.Color = Colors.White;

        Paragraph name = row.Cells[0].AddParagraph(label);
        name.Format.Font.Size = 6.4;
        name.Format.Font.Bold = true;
        name.Format.Font.Color = C(Muted);

        Paragraph data = row.Cells[1].AddParagraph(value);
        data.Format.Font.Name = value.Length > 50 ? "Consolas" : "Segoe UI";
        data.Format.Font.Size = value.Length > 50 ? 6.5 : 7.7;
        data.Format.Font.Color = C(Ink);

        foreach (Cell? cell in row.Cells)
        {
            if (cell is null) continue;
            cell.Format.LeftIndent = Unit.FromPoint(6);
            cell.Format.RightIndent = Unit.FromPoint(6);
            cell.Format.SpaceBefore = Unit.FromPoint(4.2);
            cell.Format.SpaceAfter = Unit.FromPoint(4.2);
        }
    }

    private static void AddInterpretation(Section section, ScanResult result)
    {
        H(section, "IMPORTANT INTERPRETATION");
        Table table = section.AddTable();
        table.AddColumn(Unit.FromCentimeter(ContentWidthCm));
        Row row = table.AddRow();
        row.Cells[0].Shading.Color = C(AmberSoft);
        row.Cells[0].Borders.Color = C(Amber);
        row.Cells[0].Borders.Width = Unit.FromPoint(0.75);

        Paragraph paragraph = row.Cells[0].AddParagraph();
        paragraph.Format.Font.Size = 7.5;
        paragraph.AddFormattedText("This report is evidence-based and is not an automatic punishment decision. ", TextFormat.Bold);
        paragraph.AddText("A hardware item, multi-monitor setup, overlay, unsigned file, browser record, or single process-access trace alone is not proof of cheating. High-confidence correlations and supporting evidence should be reviewed together. ");
        paragraph.AddText("Not detected does not prove that cheating never occurred. ");
        paragraph.AddText(result.PrivacyStatement);

        row.Cells[0].Format.LeftIndent = Unit.FromPoint(8);
        row.Cells[0].Format.RightIndent = Unit.FromPoint(8);
        row.Cells[0].Format.SpaceBefore = Unit.FromPoint(7);
        row.Cells[0].Format.SpaceAfter = Unit.FromPoint(7);
    }

    private static void H(Section section, string text)
    {
        Paragraph heading = section.AddParagraph(text);
        heading.Style = "DGSection";
    }

    private static void AddHeader(Table table, params string[] names)
    {
        Row row = table.AddRow();
        row.Shading.Color = C(Navy2);
        row.Format.Font.Size = 6.8;
        row.Format.Font.Bold = true;
        row.Format.Font.Color = Colors.White;
        for (int index = 0; index < names.Length; index++)
            row.Cells[index].AddParagraph(names[index]);
    }

    private static void FormatTable(Table table, double padding)
    {
        foreach (Row? row in table.Rows)
        {
            if (row is null) continue;
            foreach (Cell? cell in row.Cells)
            {
                if (cell is null) continue;
                cell.VerticalAlignment = VerticalAlignment.Center;
                cell.Format.LeftIndent = Unit.FromPoint(4);
                cell.Format.RightIndent = Unit.FromPoint(4);
                cell.Format.SpaceBefore = Unit.FromPoint(padding);
                cell.Format.SpaceAfter = Unit.FromPoint(padding);
                cell.Format.Font.Size = Unit.FromPoint(6.9);
            }
        }
    }

    private static void AddNoticeCard(Section section, string message, string accent, string background)
    {
        Table table = section.AddTable();
        table.AddColumn(Unit.FromCentimeter(ContentWidthCm));
        Row row = table.AddRow();
        row.Cells[0].Shading.Color = C(background);
        row.Cells[0].Borders.Color = C(accent);
        row.Cells[0].Borders.Width = Unit.FromPoint(0.7);
        Paragraph paragraph = row.Cells[0].AddParagraph(message);
        paragraph.Format.Font.Size = 8;
        paragraph.Format.Font.Bold = true;
        paragraph.Format.Font.Color = C(accent);
        row.Cells[0].Format.LeftIndent = Unit.FromPoint(8);
        row.Cells[0].Format.RightIndent = Unit.FromPoint(8);
        row.Cells[0].Format.SpaceBefore = Unit.FromPoint(6);
        row.Cells[0].Format.SpaceAfter = Unit.FromPoint(6);
    }

    private static string VerdictTitle(ScanVerdict verdict) => verdict switch
    {
        ScanVerdict.Detected => "THREATS DETECTED",
        ScanVerdict.Review => "MANUAL REVIEW REQUIRED",
        ScanVerdict.NotDetected => "NO CONFIRMED DETECTION",
        ScanVerdict.Cancelled => "SCAN CANCELLED",
        _ => "SCAN INCOMPLETE"
    };

    private static string VerdictText(ScanVerdict verdict) => verdict switch
    {
        ScanVerdict.Detected => "One or more high-confidence detections were highlighted. Review named detections and correlated runtime evidence first.",
        ScanVerdict.Review => "No confirmed detection was produced, but one or more supporting traces require manual review.",
        ScanVerdict.NotDetected => "No confirmed high-confidence detection was highlighted by the completed modules.",
        ScanVerdict.Cancelled => "The scan was cancelled before a reliable result was produced.",
        _ => "Required modules could not be completed, so the result must be interpreted with caution."
    };

    private static string RiskBand(ScanResult result)
    {
        if (result.Verdict == ScanVerdict.NotDetected && result.RiskScore < 50)
            return "LOW RISK";
        if (result.RiskScore >= 200 || result.CriticalCount > 0)
            return "CRITICAL RISK";
        if (result.RiskScore >= 100 || result.Verdict == ScanVerdict.Detected)
            return "HIGH RISK";
        return "REVIEW";
    }

    private static string RiskColor(ScanResult result) => RiskBand(result) switch
    {
        "LOW RISK" => Green,
        "REVIEW" => Amber,
        "HIGH RISK" => Red,
        _ => "#DC2626"
    };

    private static string RiskSoftColor(ScanResult result) => RiskBand(result) switch
    {
        "LOW RISK" => GreenSoft,
        "REVIEW" => AmberSoft,
        _ => RedSoft
    };

    private static string SeverityColor(FindingSeverity severity) => severity switch
    {
        FindingSeverity.Critical => "#B91C1C",
        FindingSeverity.High => Red,
        FindingSeverity.Warning => Amber,
        _ => Cyan
    };

    private static string SeverityShort(FindingSeverity severity) => severity switch
    {
        FindingSeverity.Critical => "CRIT",
        FindingSeverity.High => "HIGH",
        FindingSeverity.Warning => "MED",
        _ => "INFO"
    };

    private static string CoverageColor(CoverageStatus status) => status switch
    {
        CoverageStatus.Completed => Green,
        CoverageStatus.Partial => Amber,
        CoverageStatus.Unavailable => Red,
        CoverageStatus.Failed => RedDark,
        _ => Muted
    };

    private static string FindingCategory(ScanFinding finding)
    {
        string text = string.Join(" ", new[]
        {
            finding.RuleId,
            finding.Title,
            finding.Summary,
            finding.EvidenceSource,
            finding.Path,
            finding.DetectionMethod,
            finding.CheatFamily
        }.Where(x => !string.IsNullOrWhiteSpace(x))).ToLowerInvariant();

        if (text.Contains("dma") || text.Contains("pcie") || text.Contains("fpga") || text.Contains("leechcore"))
            return "Hardware / DMA";
        if (text.Contains("discord"))
            return "Discord / Online Traces";
        if (text.Contains("overlay"))
            return "Overlay Windows";
        if (text.Contains("processhandle") || text.Contains("process handle") || text.Contains("vm_write") ||
            text.Contains("create_thread") || text.Contains("inject") || text.Contains("executable memory") ||
            text.Contains("memory region") || text.Contains("thread start"))
            return "Runtime / Injection";
        if (text.Contains("scheduled task") || text.Contains("service") || text.Contains("startup") ||
            text.Contains("persistence") || text.Contains("autorun"))
            return "Persistence";
        if (text.Contains("kernel") || text.Contains("driver") || text.Contains("code integrity") ||
            text.Contains("test-signing") || text.Contains("vulnerable driver"))
            return "Kernel / Drivers";
        if (text.Contains("defender") || text.Contains("antivirus"))
            return "Microsoft Defender";
        if (text.Contains("deleted") || text.Contains("recycle") || text.Contains("mft") ||
            text.Contains("usn") || text.Contains("unallocated"))
            return "Deleted Traces";
        if (text.Contains("browser") || text.Contains("download history") || text.Contains("visited"))
            return "Browser / Downloads";
        if (text.Contains("network") || text.Contains("tcp") || text.Contains("domain") || text.Contains("remote ip"))
            return "Network";
        if (text.Contains("file") || text.Contains("archive") || text.Contains("hash") ||
            text.Contains("filename") || text.Contains("static string"))
            return "Cheat Files";
        if (IsPrimaryCheatFinding(finding))
            return "Cheat Detections";
        return "Other Review";
    }

    private static int CategoryOrder(string category) => category switch
    {
        "Cheat Detections" => 0,
        "Cheat Files" => 1,
        "Runtime / Injection" => 2,
        "Overlay Windows" => 3,
        "Persistence" => 4,
        "Kernel / Drivers" => 5,
        "Hardware / DMA" => 6,
        "Discord / Online Traces" => 7,
        "Browser / Downloads" => 8,
        "Deleted Traces" => 9,
        "Microsoft Defender" => 10,
        "Network" => 11,
        _ => 99
    };

    private static string CategoryAccent(string category) => category switch
    {
        "Cheat Detections" => Red,
        "Cheat Files" => "#F97316",
        "Runtime / Injection" => Purple,
        "Overlay Windows" => "#8B5CF6",
        "Persistence" => Amber,
        "Kernel / Drivers" => Cyan,
        "Hardware / DMA" => "#DB2777",
        "Discord / Online Traces" => Purple,
        "Browser / Downloads" => "#2563EB",
        "Deleted Traces" => "#B45309",
        "Microsoft Defender" => Green,
        "Network" => "#0F766E",
        _ => Muted
    };

    private static string DurationText(TimeSpan duration)
    {
        if (duration < TimeSpan.Zero)
            duration = TimeSpan.Zero;
        if (duration.TotalHours >= 1)
            return $"{(int)duration.TotalHours:00}:{duration.Minutes:00}:{duration.Seconds:00}";
        return $"{duration.Minutes:00}:{duration.Seconds:00}";
    }

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

    private static ScanFinding[] AllReportFindings(ScanResult result)
    {
        return PrimaryCheatFindings(result)
            .Concat(SupportingFindings(result))
            .GroupBy(
                x => $"{x.RuleId}|{NormalizeReportKey(x.Path ?? x.DetectedCheatName ?? x.Title)}",
                StringComparer.OrdinalIgnoreCase)
            .Select(x => x
                .OrderByDescending(IsPrimaryCheatFinding)
                .ThenByDescending(y => y.Score)
                .ThenByDescending(y => y.Timestamp)
                .First())
            .OrderByDescending(IsPrimaryCheatFinding)
            .ThenByDescending(x => x.Score)
            .ThenByDescending(x => x.Timestamp)
            .ToArray();
    }

    private static ScanFinding[] PrimaryCheatFindings(ScanResult result) =>
        result.Findings
            .Where(IsPrimaryCheatFinding)
            .GroupBy(
                item => NormalizeReportKey(item.DetectedCheatName ?? item.Title),
                StringComparer.OrdinalIgnoreCase)
            .Select(group => group
                .OrderByDescending(item => item.Score)
                .ThenByDescending(item => item.Timestamp)
                .First())
            .OrderByDescending(item => item.Score)
            .ThenByDescending(item => item.Timestamp)
            .ToArray();

    private static ScanFinding[] SupportingFindings(ScanResult result) =>
        result.Findings
            .Where(item => !IsPrimaryCheatFinding(item))
            .GroupBy(
                item => !string.IsNullOrWhiteSpace(item.DetectedCheatName)
                    ? $"named:{NormalizeReportKey(item.DetectedCheatName)}"
                    : item.RuleId.StartsWith("DGS-KERNEL-", StringComparison.OrdinalIgnoreCase)
                        ? $"kernel:{item.RuleId}"
                        : $"other:{item.RuleId}|{NormalizeReportKey(item.Path ?? item.Title)}",
                StringComparer.OrdinalIgnoreCase)
            .Select(group => group
                .OrderByDescending(item => item.Score)
                .ThenByDescending(item => item.Timestamp)
                .First())
            .OrderByDescending(item => item.Score)
            .ThenByDescending(item => item.Timestamp)
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

    private static string NormalizeReportKey(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return "";
        string normalized = new string(value
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
        {
            detail = item.Metadata.Count > 0
                ? string.Join(" | ", item.Metadata.Take(3).Select(x => $"{x.Key}: {x.Value}"))
                : "No additional detail";
        }
        return Trim(detail, 210);
    }

    private static string Trim(string? value, int maximum)
    {
        if (string.IsNullOrWhiteSpace(value))
            return "-";
        string clean = value.Replace('\r', ' ').Replace('\n', ' ').Trim();
        return clean.Length <= maximum ? clean : clean[..Math.Max(1, maximum - 3)] + "...";
    }

    private static Color C(string hex) => Color.Parse(hex);
}
