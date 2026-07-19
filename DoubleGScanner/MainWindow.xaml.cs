using System.Diagnostics;
using System.Windows;
using System.Windows.Media;
using DoubleGScanner.Models;
using DoubleGScanner.Services;

namespace DoubleGScanner;

public partial class MainWindow : Window
{
    private readonly ScanCoordinator coordinator=new();
    private readonly ReportService reports=new();
    private CancellationTokenSource? cancellation;
    private ReportBundle? lastReport;

    public MainWindow(){InitializeComponent();}

    private async void StartScanButton_Click(object sender,RoutedEventArgs e)
    {
        if(ConsentCheckBox.IsChecked!=true)return;
        cancellation=new();SetScanning(true);ResetUi();
        ScanMode mode=ForensicMode.IsChecked==true?ScanMode.Forensic:FullMode.IsChecked==true?ScanMode.Full:ScanMode.Quick;
        var progress=new Progress<ScanProgressUpdate>(u=>
        {
            int percent=Math.Clamp(u.Percent,0,100);ScanProgress.Value=percent;ProgressText.Text=$"{percent}%";
            LiveModuleText.Text=u.Module;LiveStatusText.Text=u.Message;ItemsCheckedText.Text=$"Items checked: {u.ItemsChecked:N0}";
            if(u.Findings>0)FindingCountText.Text=u.Findings.ToString("N0");
        });
        try
        {
            StatusTitle.Text="System analysis in progress";StatusDescription.Text="Keep the app open. Nothing is uploaded, deleted, or modified.";
            ScanResult result=await coordinator.RunAsync(mode,progress,cancellation.Token);
            lastReport=await reports.CreateAsync(result,cancellation.Token);ShowResult(result);
        }
        catch(OperationCanceledException){ShowCancelled();}
        catch(Exception ex)
        {
            StatusTitle.Text="Scan incomplete";StatusDescription.Text="The scanner stopped safely and did not modify files.";
            VerdictText.Text="INCOMPLETE";VerdictText.Foreground=(Brush)FindResource("WarningBrush");VerdictDetail.Text=ex.Message;
        }
        finally{SetScanning(false);cancellation?.Dispose();cancellation=null;}
    }

    private void ShowResult(ScanResult r)
    {
        ScanProgress.Value=100;ProgressText.Text="100%";EvidenceCountText.Text=r.Evidence.Count.ToString("N0");
        FindingCountText.Text=r.Findings.Count.ToString("N0");ModuleCountText.Text=r.Coverage.Count(x=>x.Status==CoverageStatus.Completed).ToString();
        RiskScoreText.Text=r.RiskScore.ToString();FindingsGrid.ItemsSource=r.Findings;CoverageGrid.ItemsSource=r.Coverage;
        (string title,string detail,string brush)=r.Verdict switch
        {
            ScanVerdict.Detected=>("DETECTED","High-confidence indicators were found. Review the PDF evidence before action.","DangerBrush"),
            ScanVerdict.Review=>("REVIEW","The result is not conclusive. Manual review is required.","WarningBrush"),
            ScanVerdict.NotDetected=>("NOT DETECTED","No known high-confidence indicator was identified by completed modules.","SuccessBrush"),
            ScanVerdict.Incomplete=>("INCOMPLETE","One or more required modules could not be completed.","WarningBrush"),
            _=>("CANCELLED","No reliable result was produced.","TextSecondaryBrush")
        };
        StatusTitle.Text="Scan completed";StatusDescription.Text=$"{r.Mode} scan finished. Local PDF and JSON evidence were generated.";
        VerdictText.Text=title;VerdictText.Foreground=(Brush)FindResource(brush);VerdictDetail.Text=detail;
        LiveModuleText.Text="Report generated";LiveStatusText.Text=lastReport?.PdfPath??"Report unavailable";
        ItemsCheckedText.Text=$"Evidence records: {r.Evidence.Count:N0}";OpenReportButton.IsEnabled=lastReport is not null;OpenFolderButton.IsEnabled=lastReport is not null;
    }
    private void ShowCancelled()
    {
        StatusTitle.Text="Scan cancelled";StatusDescription.Text="The scan stopped safely. No reliable verdict was produced.";
        VerdictText.Text="CANCELLED";VerdictText.Foreground=(Brush)FindResource("TextSecondaryBrush");
        VerdictDetail.Text="Run a complete scan to produce a valid result.";LiveModuleText.Text="Cancelled";LiveStatusText.Text="No files were modified or uploaded.";
    }
    private void ResetUi()
    {
        lastReport=null;OpenReportButton.IsEnabled=false;OpenFolderButton.IsEnabled=false;FindingsGrid.ItemsSource=null;CoverageGrid.ItemsSource=null;
        EvidenceCountText.Text="0";FindingCountText.Text="0";ModuleCountText.Text="0";RiskScoreText.Text="0";
        VerdictText.Text="SCANNING";VerdictText.Foreground=(Brush)FindResource("TextPrimaryBrush");VerdictDetail.Text="Correlating independent evidence sources.";
        ScanProgress.Value=0;ProgressText.Text="0%";
    }
    private void SetScanning(bool scanning)
    {
        StartScanButton.IsEnabled=!scanning&&ConsentCheckBox.IsChecked==true;CancelButton.IsEnabled=scanning;
        QuickMode.IsEnabled=!scanning;FullMode.IsEnabled=!scanning;ForensicMode.IsEnabled=!scanning;ConsentCheckBox.IsEnabled=!scanning;
    }
    private void CancelButton_Click(object sender,RoutedEventArgs e)=>cancellation?.Cancel();
    private void ConsentCheckBox_Changed(object sender,RoutedEventArgs e){if(cancellation is null)StartScanButton.IsEnabled=ConsentCheckBox.IsChecked==true;}
    private void OpenReportButton_Click(object sender,RoutedEventArgs e)
    {
        if(lastReport is null||!File.Exists(lastReport.PdfPath))return;
        Process.Start(new ProcessStartInfo(lastReport.PdfPath){UseShellExecute=true});
    }
    private void OpenFolderButton_Click(object sender,RoutedEventArgs e)
    {
        string? dir=lastReport is null?null:Path.GetDirectoryName(lastReport.PdfPath);if(dir is null||!Directory.Exists(dir))return;
        Process.Start(new ProcessStartInfo("explorer.exe",dir){UseShellExecute=true});
    }
}
