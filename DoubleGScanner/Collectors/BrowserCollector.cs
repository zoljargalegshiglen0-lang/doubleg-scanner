using DoubleGScanner.Models;
using DoubleGScanner.Services;
using Microsoft.Data.Sqlite;

namespace DoubleGScanner.Collectors;

public sealed class BrowserCollector : IScanCollector
{
    public string Name => "Browser activity";
    public bool Supports(ScanMode mode) => true;

    public async Task<CollectorOutput> CollectAsync(
        ScanContext context,
        IProgress<ScanProgressUpdate>? progress,
        CancellationToken token)
    {
        DateTime started = DateTime.UtcNow;
        var evidence = new List<EvidenceRecord>();
        int checkedRows = 0;
        int profiles = 0;
        bool partial = false;

        foreach (Profile profile in Discover())
        {
            token.ThrowIfCancellationRequested();
            profiles++;

            progress?.Report(new ScanProgressUpdate
            {
                Percent = context.Mode == ScanMode.Quick ? 38 : 42,
                Module = Name,
                Message = $"Checking visits and downloads in {profile.Browser} — {profile.Name}",
                ItemsChecked = checkedRows
            });

            try
            {
                string copy = await CopyDb(
                    profile.Path,
                    context.TempDirectory,
                    token);

                checkedRows += profile.Firefox
                    ? await ReadFirefox(
                        copy,
                        profile,
                        context.Rules,
                        context.Mode,
                        evidence,
                        token)
                    : await ReadChromium(
                        copy,
                        profile,
                        context.Rules,
                        context.Mode,
                        evidence,
                        token);
            }
            catch
            {
                partial = true;
            }
        }

        return new CollectorOutput
        {
            Module = Name,
            Status = profiles == 0
                ? CoverageStatus.Unavailable
                : partial
                    ? CoverageStatus.Partial
                    : CoverageStatus.Completed,
            Summary = profiles == 0
                ? "No supported browser history database was found."
                : $"Checked {checkedRows:N0} local browser records across {profiles} profile(s) and retained {evidence.Count:N0} relevant visit/download records. Quick Scan includes recent executable/archive downloads even when the local file has been deleted.",
            Evidence = evidence,
            ItemsChecked = checkedRows,
            Duration = DateTime.UtcNow - started
        };
    }

    private static IEnumerable<Profile> Discover()
    {
        string local = Environment.GetFolderPath(
            Environment.SpecialFolder.LocalApplicationData);
        string roaming = Environment.GetFolderPath(
            Environment.SpecialFolder.ApplicationData);

        foreach ((string browser, string root) in new[]
        {
            ("Chrome", Path.Combine(local, "Google", "Chrome", "User Data")),
            ("Edge", Path.Combine(local, "Microsoft", "Edge", "User Data")),
            ("Brave", Path.Combine(local, "BraveSoftware", "Brave-Browser", "User Data"))
        })
        {
            if (!Directory.Exists(root))
                continue;

            foreach (string directory in SafeDirs(root))
            {
                string profileName = Path.GetFileName(directory);
                if (!profileName.Equals(
                        "Default",
                        StringComparison.OrdinalIgnoreCase) &&
                    !profileName.StartsWith(
                        "Profile ",
                        StringComparison.OrdinalIgnoreCase))
                    continue;

                string history = Path.Combine(directory, "History");
                if (File.Exists(history))
                    yield return new Profile(
                        browser,
                        profileName,
                        history,
                        false);
            }
        }

        foreach ((string browser, string history) in new[]
        {
            ("Opera", Path.Combine(roaming, "Opera Software", "Opera Stable", "History")),
            ("Opera GX", Path.Combine(roaming, "Opera Software", "Opera GX Stable", "History"))
        })
        {
            if (File.Exists(history))
                yield return new Profile(
                    browser,
                    "Default",
                    history,
                    false);
        }

        string firefoxRoot = Path.Combine(
            roaming,
            "Mozilla",
            "Firefox",
            "Profiles");

        if (!Directory.Exists(firefoxRoot))
            yield break;

        foreach (string directory in SafeDirs(firefoxRoot))
        {
            string database = Path.Combine(
                directory,
                "places.sqlite");

            if (File.Exists(database))
                yield return new Profile(
                    "Firefox",
                    Path.GetFileName(directory),
                    database,
                    true);
        }
    }

    private static async Task<int> ReadChromium(
        string path,
        Profile profile,
        RuleSet rules,
        ScanMode mode,
        List<EvidenceRecord> evidence,
        CancellationToken token)
    {
        int checkedRows = 0;
        int visitLimit = 12_000;
        int downloadLimit = 4_000;
        int recentDays = mode == ScanMode.Quick
            ? 120
            : 365;

        await using var connection =
            new SqliteConnection($"Data Source={path};Mode=ReadOnly");
        await connection.OpenAsync(token);

        await using (SqliteCommand command =
                     connection.CreateCommand())
        {
            command.CommandText =
                $"SELECT url,title,last_visit_time " +
                $"FROM urls ORDER BY last_visit_time DESC LIMIT {visitLimit}";

            await using SqliteDataReader reader =
                await command.ExecuteReaderAsync(token);

            while (await reader.ReadAsync(token))
            {
                checkedRows++;

                string url = StringValue(reader, 0);
                string title = StringValue(reader, 1);
                long raw = LongValue(reader, 2);
                string combined = url + " " + title;

                bool relevant =
                    RuleMatcher.IsKnownDomain(url, rules) ||
                    RuleMatcher.FindKnownCheatName(
                        combined,
                        rules) is not null ||
                    RuleMatcher.ContainsHigh(
                        combined,
                        rules) ||
                    (RuleMatcher.ContainsMedium(
                         combined,
                         rules) &&
                     url.Contains(
                         "cs2",
                         StringComparison.OrdinalIgnoreCase));

                if (!relevant)
                    continue;

                evidence.Add(new EvidenceRecord
                {
                    Kind = EvidenceKind.Browser,
                    Source = "Browser activity",
                    Name = string.IsNullOrWhiteSpace(title)
                        ? "Browser visit"
                        : title,
                    Url = url,
                    Timestamp = ChromiumTime(raw),
                    Detail =
                        "Potentially relevant local visit. No cookies, passwords, or sessions were read.",
                    Metadata =
                        new Dictionary<string, string>(
                            StringComparer.OrdinalIgnoreCase)
                        {
                            ["Browser"] = profile.Browser,
                            ["Profile"] = profile.Name,
                            ["RecordType"] = "Visit"
                        }
                });
            }
        }

        if (!await TableExists(
                connection,
                "downloads",
                token))
            return checkedRows;

        HashSet<string> columns =
            await Columns(
                connection,
                "downloads",
                token);

        string Column(string name) =>
            columns.Contains(name)
                ? name
                : $"NULL AS {name}";

        await using (SqliteCommand command =
                     connection.CreateCommand())
        {
            command.CommandText =
                $"SELECT {Column("current_path")}," +
                $"{Column("target_path")}," +
                $"{Column("start_time")}," +
                $"{Column("tab_url")}," +
                $"{Column("site_url")}," +
                $"{Column("referrer")} " +
                $"FROM downloads ORDER BY start_time DESC LIMIT {downloadLimit}";

            await using SqliteDataReader reader =
                await command.ExecuteReaderAsync(token);

            while (await reader.ReadAsync(token))
            {
                checkedRows++;

                string current = StringValue(reader, 0);
                string targetPath = StringValue(reader, 1);
                long raw = LongValue(reader, 2);
                string tabUrl = StringValue(reader, 3);
                string siteUrl = StringValue(reader, 4);
                string referrer = StringValue(reader, 5);

                string selectedPath =
                    !string.IsNullOrWhiteSpace(targetPath)
                        ? targetPath
                        : current;

                DateTimeOffset? timestamp =
                    ChromiumTime(raw);

                bool recent =
                    timestamp is not null &&
                    timestamp.Value >=
                    DateTimeOffset.Now.AddDays(-recentDays);

                bool executableOrArchive =
                    RuleMatcher.IsExecutableOrArchive(
                        selectedPath);

                string combined = string.Join(
                    " ",
                    current,
                    targetPath,
                    tabUrl,
                    siteUrl,
                    referrer);

                bool knownDomain =
                    RuleMatcher.IsKnownDomain(
                        tabUrl,
                        rules) ||
                    RuleMatcher.IsKnownDomain(
                        siteUrl,
                        rules) ||
                    RuleMatcher.IsKnownDomain(
                        referrer,
                        rules);

                bool relevant =
                    knownDomain ||
                    RuleMatcher.FindKnownCheatName(
                        combined,
                        rules) is not null ||
                    RuleMatcher.ContainsHigh(
                        combined,
                        rules) ||
                    (RuleMatcher.ContainsMedium(
                         combined,
                         rules) &&
                     executableOrArchive) ||
                    (recent && executableOrArchive);

                if (!relevant)
                    continue;

                bool fileExists =
                    !string.IsNullOrWhiteSpace(selectedPath) &&
                    File.Exists(selectedPath);

                evidence.Add(new EvidenceRecord
                {
                    Kind = EvidenceKind.Browser,
                    Source = "Browser activity",
                    Name =
                        Path.GetFileName(selectedPath)
                            is { Length: > 0 } fileName
                            ? fileName
                            : "Browser download",
                    Path = selectedPath,
                    Url =
                        !string.IsNullOrWhiteSpace(tabUrl)
                            ? tabUrl
                            : !string.IsNullOrWhiteSpace(siteUrl)
                                ? siteUrl
                                : referrer,
                    Timestamp = timestamp,
                    Detail =
                        knownDomain ||
                        RuleMatcher.ContainsHigh(
                            combined,
                            rules)
                            ? "Potentially cheat-related local download record."
                            : fileExists
                                ? "Recent executable/archive download record retained for correlation."
                                : "Recent executable/archive download record; the referenced local file is no longer present.",
                    Metadata =
                        new Dictionary<string, string>(
                            StringComparer.OrdinalIgnoreCase)
                        {
                            ["Browser"] = profile.Browser,
                            ["Profile"] = profile.Name,
                            ["RecordType"] = "Download",
                            ["FileExists"] = fileExists.ToString(),
                            ["MissingLocalFile"] = (!fileExists).ToString(),
                            ["RecentDownload"] = recent.ToString(),
                            ["ExecutableOrArchive"] =
                                executableOrArchive.ToString(),
                            ["Extension"] =
                                Path.GetExtension(selectedPath),
                            ["KnownDomain"] =
                                knownDomain.ToString()
                        }
                });
            }
        }

        return checkedRows;
    }

    private static async Task<int> ReadFirefox(
        string path,
        Profile profile,
        RuleSet rules,
        ScanMode mode,
        List<EvidenceRecord> evidence,
        CancellationToken token)
    {
        int checkedRows = 0;
        int visitLimit = 12_000;
        int downloadLimit = 3_000;
        int recentDays = mode == ScanMode.Quick
            ? 120
            : 365;

        await using var connection =
            new SqliteConnection($"Data Source={path};Mode=ReadOnly");
        await connection.OpenAsync(token);

        await using (SqliteCommand command =
                     connection.CreateCommand())
        {
            command.CommandText =
                $"SELECT url,title,last_visit_date " +
                $"FROM moz_places " +
                $"WHERE last_visit_date IS NOT NULL " +
                $"ORDER BY last_visit_date DESC LIMIT {visitLimit}";

            await using SqliteDataReader reader =
                await command.ExecuteReaderAsync(token);

            while (await reader.ReadAsync(token))
            {
                checkedRows++;

                string url = StringValue(reader, 0);
                string title = StringValue(reader, 1);
                long raw = LongValue(reader, 2);
                string combined = url + " " + title;

                if (!RuleMatcher.IsKnownDomain(url, rules) &&
                    RuleMatcher.FindKnownCheatName(
                        combined,
                        rules) is null &&
                    !RuleMatcher.ContainsHigh(
                        combined,
                        rules))
                    continue;

                evidence.Add(new EvidenceRecord
                {
                    Kind = EvidenceKind.Browser,
                    Source = "Browser activity",
                    Name = string.IsNullOrWhiteSpace(title)
                        ? "Firefox visit"
                        : title,
                    Url = url,
                    Timestamp = FirefoxTime(raw),
                    Detail =
                        "Potentially relevant Firefox history entry.",
                    Metadata =
                        new Dictionary<string, string>(
                            StringComparer.OrdinalIgnoreCase)
                        {
                            ["Browser"] = profile.Browser,
                            ["Profile"] = profile.Name,
                            ["RecordType"] = "Visit"
                        }
                });
            }
        }

        bool hasAnnotations =
            await TableExists(
                connection,
                "moz_annos",
                token) &&
            await TableExists(
                connection,
                "moz_anno_attributes",
                token);

        if (!hasAnnotations)
            return checkedRows;

        await using (SqliteCommand command =
                     connection.CreateCommand())
        {
            command.CommandText =
                $"SELECT p.url,p.title,p.last_visit_date,a.content " +
                $"FROM moz_places p " +
                $"JOIN moz_annos a ON a.place_id=p.id " +
                $"JOIN moz_anno_attributes aa " +
                $"ON aa.id=a.anno_attribute_id " +
                $"WHERE aa.name='downloads/destinationFileURI' " +
                $"ORDER BY p.last_visit_date DESC LIMIT {downloadLimit}";

            await using SqliteDataReader reader =
                await command.ExecuteReaderAsync(token);

            while (await reader.ReadAsync(token))
            {
                checkedRows++;

                string sourceUrl = StringValue(reader, 0);
                string title = StringValue(reader, 1);
                long raw = LongValue(reader, 2);
                string destinationUri =
                    StringValue(reader, 3);

                string localPath =
                    FileUriToPath(destinationUri);

                DateTimeOffset? timestamp =
                    FirefoxTime(raw);

                bool recent =
                    timestamp is not null &&
                    timestamp.Value >=
                    DateTimeOffset.Now.AddDays(-recentDays);

                bool executableOrArchive =
                    RuleMatcher.IsExecutableOrArchive(
                        localPath);

                string combined = string.Join(
                    " ",
                    sourceUrl,
                    title,
                    destinationUri,
                    localPath);

                bool knownDomain =
                    RuleMatcher.IsKnownDomain(
                        sourceUrl,
                        rules);

                bool relevant =
                    knownDomain ||
                    RuleMatcher.FindKnownCheatName(
                        combined,
                        rules) is not null ||
                    RuleMatcher.ContainsHigh(
                        combined,
                        rules) ||
                    (recent && executableOrArchive);

                if (!relevant)
                    continue;

                bool fileExists =
                    !string.IsNullOrWhiteSpace(localPath) &&
                    File.Exists(localPath);

                evidence.Add(new EvidenceRecord
                {
                    Kind = EvidenceKind.Browser,
                    Source = "Browser activity",
                    Name =
                        Path.GetFileName(localPath)
                            is { Length: > 0 } fileName
                            ? fileName
                            : string.IsNullOrWhiteSpace(title)
                                ? "Firefox download"
                                : title,
                    Path = localPath,
                    Url = sourceUrl,
                    Timestamp = timestamp,
                    Detail = fileExists
                        ? "Recent Firefox executable/archive download record."
                        : "Recent Firefox executable/archive download record; the referenced local file is no longer present.",
                    Metadata =
                        new Dictionary<string, string>(
                            StringComparer.OrdinalIgnoreCase)
                        {
                            ["Browser"] = profile.Browser,
                            ["Profile"] = profile.Name,
                            ["RecordType"] = "Download",
                            ["FileExists"] =
                                fileExists.ToString(),
                            ["MissingLocalFile"] =
                                (!fileExists).ToString(),
                            ["RecentDownload"] =
                                recent.ToString(),
                            ["ExecutableOrArchive"] =
                                executableOrArchive.ToString(),
                            ["Extension"] =
                                Path.GetExtension(localPath),
                            ["KnownDomain"] =
                                knownDomain.ToString()
                        }
                });
            }
        }

        return checkedRows;
    }

    private static async Task<string> CopyDb(
        string source,
        string temp,
        CancellationToken token)
    {
        string directory = Path.Combine(
            temp,
            "browser-" + Guid.NewGuid().ToString("N"));

        Directory.CreateDirectory(directory);

        string destination =
            Path.Combine(
                directory,
                Path.GetFileName(source));

        await using FileStream input =
            new(
                source,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite |
                FileShare.Delete,
                1024 * 1024,
                true);

        await using FileStream output =
            new(
                destination,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                1024 * 1024,
                true);

        await input.CopyToAsync(output, token);
        return destination;
    }

    private static DateTimeOffset? ChromiumTime(
        long microseconds)
    {
        if (microseconds <= 0)
            return null;

        try
        {
            return new DateTimeOffset(
                    1601,
                    1,
                    1,
                    0,
                    0,
                    0,
                    TimeSpan.Zero)
                .AddTicks(microseconds * 10);
        }
        catch
        {
            return null;
        }
    }

    private static DateTimeOffset? FirefoxTime(
        long microseconds)
    {
        if (microseconds <= 0)
            return null;

        try
        {
            return DateTimeOffset
                .FromUnixTimeMilliseconds(
                    microseconds / 1000);
        }
        catch
        {
            return null;
        }
    }

    private static string FileUriToPath(
        string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return "";

        try
        {
            return Uri.TryCreate(
                       value,
                       UriKind.Absolute,
                       out Uri? uri) &&
                   uri.IsFile
                ? uri.LocalPath
                : value;
        }
        catch
        {
            return value;
        }
    }

    private static async Task<bool> TableExists(
        SqliteConnection connection,
        string table,
        CancellationToken token)
    {
        await using SqliteCommand command =
            connection.CreateCommand();

        command.CommandText =
            "SELECT 1 FROM sqlite_master " +
            "WHERE type='table' AND name=$name LIMIT 1";

        command.Parameters.AddWithValue(
            "$name",
            table);

        return await command.ExecuteScalarAsync(token)
            is not null;
    }

    private static async Task<HashSet<string>> Columns(
        SqliteConnection connection,
        string table,
        CancellationToken token)
    {
        var columns =
            new HashSet<string>(
                StringComparer.OrdinalIgnoreCase);

        await using SqliteCommand command =
            connection.CreateCommand();

        command.CommandText =
            $"PRAGMA table_info([{table.Replace(
                "]",
                "]]",
                StringComparison.Ordinal)}])";

        await using SqliteDataReader reader =
            await command.ExecuteReaderAsync(token);

        while (await reader.ReadAsync(token))
        {
            if (!reader.IsDBNull(1))
                columns.Add(reader.GetString(1));
        }

        return columns;
    }

    private static string StringValue(
        SqliteDataReader reader,
        int index) =>
        reader.IsDBNull(index)
            ? ""
            : Convert.ToString(
                reader.GetValue(index)) ?? "";

    private static long LongValue(
        SqliteDataReader reader,
        int index) =>
        reader.IsDBNull(index)
            ? 0
            : Convert.ToInt64(
                reader.GetValue(index));

    private static IEnumerable<string> SafeDirs(
        string path)
    {
        try
        {
            return Directory
                .EnumerateDirectories(path)
                .ToArray();
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    private sealed record Profile(
        string Browser,
        string Name,
        string Path,
        bool Firefox);
}
