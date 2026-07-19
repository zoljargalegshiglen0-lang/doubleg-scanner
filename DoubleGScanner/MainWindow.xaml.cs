using System.Diagnostics;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using DoubleGScanner.Collectors;
using DoubleGScanner.Models;
using DoubleGScanner.Services;

namespace DoubleGScanner;

public partial class MainWindow : Window
{
    private readonly ScanCoordinator coordinator = new();
    private readonly ReportService reports = new();
    private CancellationTokenSource? cancellation;
    private ReportBundle? lastReport;
    private bool navigationReady;

    public MainWindow()
    {
        InitializeComponent();

        string version = GetDisplayVersion();
        VersionText.Text = $"v{version}";
        TitleVersionText.Text = $"v{version}";
        Title = $"DoubleG Scanner v{version}";
        CurrentTimeText.Text = DateTime.Now.ToString("HH:mm  •  dd MMM yyyy");

        MainTabs.SelectedIndex = 0;
        navigationReady = true;
        NavOverviewButton.IsChecked = true;
    }

    private static string GetDisplayVersion()
    {
        Assembly assembly = Assembly.GetExecutingAssembly();

        string? informational = assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion;

        if (!string.IsNullOrWhiteSpace(informational))
            return informational.Split('+')[0];

        Version? version = assembly.GetName().Version;
        return version is null
            ? "dev"
            : $"{version.Major}.{version.Minor}.{Math.Max(version.Build, 0)}";
    }

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.OriginalSource is DependencyObject source &&
            FindVisualParent<Button>(source) is not null)
            return;

        if (e.ClickCount == 2)
        {
            ToggleMaximize();
            return;
        }

        if (e.LeftButton == MouseButtonState.Pressed)
            DragMove();
    }

    private static T? FindVisualParent<T>(DependencyObject child)
        where T : DependencyObject
    {
        DependencyObject? current = child;

        while (current is not null)
        {
            if (current is T match)
                return match;

            current = VisualTreeHelper.GetParent(current);
        }

        return null;
    }

    private void ToggleMaximize()
    {
        WindowState = WindowState == WindowState.Maximized
            ? WindowState.Normal
            : WindowState.Maximized;
    }

    private void Minimize_Click(object sender, RoutedEventArgs e) =>
        WindowState = WindowState.Minimized;

    private void Maximize_Click(object sender, RoutedEventArgs e) =>
        ToggleMaximize();

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
    private void Exit_Click(object sender, RoutedEventArgs e) => Close();

    private void NavOverview_Checked(object sender, RoutedEventArgs e)
    {
        if (!navigationReady)
            return;

        MainTabs.SelectedIndex = 0;
    }

    private void NavFindings_Checked(object sender, RoutedEventArgs e)
    {
        if (!navigationReady)
            return;

        MainTabs.SelectedIndex = 1;
    }

    private void NavCoverage_Checked(object sender, RoutedEventArgs e)
    {
        if (!navigationReady)
            return;

        MainTabs.SelectedIndex = 2;
    }

    private async void StartScanButton_Click(object sender, RoutedEventArgs e)
    {
        if (ConsentCheckBox.IsChecked != true)
            return;

        ScanMode mode = ForensicMode.IsChecked == true
            ? ScanMode.Forensic
            : FullMode.IsChecked == true
                ? ScanMode.Full
                : ScanMode.Quick;

        if (mode != ScanMode.Quick &&
            !SystemProfileCollector.IsAdministrator())
        {
            string modeName = mode == ScanMode.Forensic
                ? "Forensic Scan"
                : "Full Scan";

            string requirements = mode == ScanMode.Forensic
                ? "NTFS MFT, USN Journal, unallocated-space signatures, and Kernel & Driver Integrity"
                : "NTFS MFT, USN Journal, and unallocated-space signatures";

            MessageBoxResult choice = MessageBox.Show(
                $"{modeName} requires administrator access for {requirements}.\n\nRestart DoubleG Scanner as administrator now?",
                "DoubleG Scanner — Administrator Required",
                MessageBoxButton.YesNo,
                MessageBoxImage.Information);

            if (choice == MessageBoxResult.Yes)
            {
                try
                {
                    string? executable = Environment.ProcessPath;
                    if (!string.IsNullOrWhiteSpace(executable))
                    {
                        Process.Start(new ProcessStartInfo(executable)
                        {
                            UseShellExecute = true,
                            Verb = "runas"
                        });

                        Application.Current.Shutdown();
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show(
                        "Administrator restart was not completed.\n\n" + ex.Message,
                        "DoubleG Scanner",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning);
                }
            }

            return;
        }

        cancellation = new CancellationTokenSource();
        SetScanning(true);
        ResetUi();

        var progress = new Progress<ScanProgressUpdate>(update =>
        {
            int percent = Math.Clamp(update.Percent, 0, 100);
            ScanProgress.Value = percent;
            ProgressText.Text = $"{percent}%";
            LiveModuleText.Text = update.Module;
            LiveStatusText.Text = update.Message;
            ItemsCheckedText.Text = $"Items checked: {update.ItemsChecked:N0}";

            if (update.Findings > 0)
                FindingCountText.Text = update.Findings.ToString("N0");
        });

        try
        {
            StatusTitle.Text = "Integrity analysis in progress";
            StatusDescription.Text =
                "Keep DoubleG Scanner open while local collectors finish.";

            ScanResult result = await coordinator.RunAsync(
                mode,
                progress,
                cancellation.Token);

            lastReport = await reports.CreateAsync(
                result,
                cancellation.Token);

            ShowResult(result);
        }
        catch (OperationCanceledException)
        {
            ShowCancelled();
        }
        catch (Exception ex)
        {
            StatusTitle.Text = "Scan incomplete";
            StatusDescription.Text =
                "The scanner stopped safely and did not modify files.";
            VerdictText.Text = "INCOMPLETE";
            VerdictText.Foreground = (Brush)FindResource("WarningBrush");
            VerdictDetail.Text = ex.Message;
        }
        finally
        {
            SetScanning(false);
            cancellation?.Dispose();
            cancellation = null;
        }
    }

    private void ShowResult(ScanResult result)
    {
        ScanProgress.Value = 100;
        ProgressText.Text = "100%";
        EvidenceCountText.Text = result.Evidence.Count.ToString("N0");
        FindingCountText.Text = result.Findings.Count.ToString("N0");
        ModuleCountText.Text = result.Coverage
            .Count(item => item.Status == CoverageStatus.Completed)
            .ToString();
        RiskScoreText.Text = result.RiskScore.ToString();

        FindingsGrid.ItemsSource = result.Findings;
        CoverageGrid.ItemsSource = result.Coverage;

        (string title, string detail, string brush) = result.Verdict switch
        {
            ScanVerdict.Detected => (
                "DETECTED",
                "High-confidence cheat indicators were found. Review the PDF evidence.",
                "DangerBrush"),
            ScanVerdict.Review => (
                "REVIEW",
                "Suspicious evidence requires manual verification.",
                "WarningBrush"),
            ScanVerdict.NotDetected => (
                "NOT DETECTED",
                "No known high-confidence indicator was identified.",
                "SuccessBrush"),
            ScanVerdict.Incomplete => (
                "INCOMPLETE",
                "One or more required modules could not be completed.",
                "WarningBrush"),
            _ => (
                "CANCELLED",
                "No reliable result was produced.",
                "TextSecondaryBrush")
        };

        StatusTitle.Text = "Scan completed";
        StatusDescription.Text =
            $"{result.Mode} scan completed. PDF and JSON evidence were generated locally.";

        VerdictText.Text = title;
        VerdictText.Foreground = (Brush)FindResource(brush);
        VerdictDetail.Text = detail;

        LiveModuleText.Text = "Report generated";
        LiveStatusText.Text = lastReport?.PdfPath ?? "Report unavailable";
        ItemsCheckedText.Text =
            $"Evidence records: {result.Evidence.Count:N0}";

        OpenReportButton.IsEnabled = lastReport is not null;
        OpenFolderButton.IsEnabled = lastReport is not null;

        MainTabs.SelectedIndex = 0;
        NavOverviewButton.IsChecked = true;
    }

    private void ShowCancelled()
    {
        StatusTitle.Text = "Scan cancelled";
        StatusDescription.Text = "The session ended safely.";
        VerdictText.Text = "CANCELLED";
        VerdictText.Foreground =
            (Brush)FindResource("TextSecondaryBrush");
        VerdictDetail.Text =
            "Run a complete scan to produce a valid result.";
        LiveModuleText.Text = "Cancelled";
        LiveStatusText.Text =
            "No files were modified or uploaded.";
    }

    private void ResetUi()
    {
        lastReport = null;
        OpenReportButton.IsEnabled = false;
        OpenFolderButton.IsEnabled = false;
        FindingsGrid.ItemsSource = null;
        CoverageGrid.ItemsSource = null;
        EvidenceCountText.Text = "0";
        FindingCountText.Text = "0";
        ModuleCountText.Text = "0";
        RiskScoreText.Text = "0";
        VerdictText.Text = "SCANNING";
        VerdictText.Foreground =
            (Brush)FindResource("TextPrimaryBrush");
        VerdictDetail.Text =
            "Correlating independent evidence sources.";
        ScanProgress.Value = 0;
        ProgressText.Text = "0%";
    }

    private void SetScanning(bool scanning)
    {
        StartScanButton.IsEnabled =
            !scanning && ConsentCheckBox.IsChecked == true;

        CancelButton.IsEnabled = scanning;
        QuickMode.IsEnabled = !scanning;
        FullMode.IsEnabled = !scanning;
        ForensicMode.IsEnabled = !scanning;
        ConsentCheckBox.IsEnabled = !scanning;
    }

    private void CancelButton_Click(object sender, RoutedEventArgs e) =>
        cancellation?.Cancel();

    private void ConsentCheckBox_Changed(
        object sender,
        RoutedEventArgs e)
    {
        if (cancellation is null)
            StartScanButton.IsEnabled =
                ConsentCheckBox.IsChecked == true;
    }

    private void OpenReportButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        if (lastReport is null ||
            !File.Exists(lastReport.PdfPath))
            return;

        Process.Start(new ProcessStartInfo(lastReport.PdfPath)
        {
            UseShellExecute = true
        });
    }

    private void OpenFolderButton_Click(
        object sender,
        RoutedEventArgs e)
    {
        string? directory = lastReport is null
            ? null
            : Path.GetDirectoryName(lastReport.PdfPath);

        if (directory is null ||
            !Directory.Exists(directory))
            return;

        Process.Start(new ProcessStartInfo(
            "explorer.exe",
            directory)
        {
            UseShellExecute = true
        });
    }
}
