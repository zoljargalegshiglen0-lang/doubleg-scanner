using DoubleGScanner.Models;
using DoubleGScanner.Services;
using Microsoft.Data.Sqlite;
using System.Text;

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
        var recoveredKeys =
            new HashSet<string>(
                StringComparer.OrdinalIgnoreCase);

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

                ResidualRecoveryResult recovery =
                    await RecoverResidualBrowserFragmentsAsync(
                        copy,
                        profile,
                        context.Rules,
                        context.Mode,
                        evidence,
                        recoveredKeys,
                        token);

                checkedRows +=
                    recovery.PagesOrChunksScanned;

                if (recovery.Partial)
                    partial = true;
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
                : $"Checked {checkedRows:N0} browser rows/pages across {profiles} profile(s) and retained {evidence.Count:N0} relevant active or residual records. SQLite WAL, rollback-journal, and freelist fragments were sampled read-only; deleted history recovery is not guaranteed after overwrite or VACUUM.",
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

        await CopySharedFileAsync(
            source,
            destination,
            token);

        foreach (string suffix in
                 new[]
                 {
                     "-wal",
                     "-shm",
                     "-journal"
                 })
        {
            string companionSource =
                source + suffix;

            if (!File.Exists(companionSource))
                continue;

            try
            {
                await CopySharedFileAsync(
                    companionSource,
                    destination + suffix,
                    token);
            }
            catch
            {
                // The main database copy remains usable even when a live
                // companion file changes or becomes unavailable.
            }
        }

        return destination;
    }

    private static async Task CopySharedFileAsync(
        string source,
        string destination,
        CancellationToken token)
    {
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
                FileMode.Create,
                FileAccess.Write,
                FileShare.None,
                1024 * 1024,
                true);

        await input.CopyToAsync(
            output,
            token);
    }

    private static async Task<ResidualRecoveryResult>
        RecoverResidualBrowserFragmentsAsync(
            string databasePath,
            Profile profile,
            RuleSet rules,
            ScanMode mode,
            List<EvidenceRecord> evidence,
            HashSet<string> recoveredKeys,
            CancellationToken token)
    {
        int maxPages = mode switch
        {
            ScanMode.Quick => 256,
            ScanMode.Full => 1_024,
            _ => 4_096
        };

        int maxEvidence = mode switch
        {
            ScanMode.Quick => 120,
            ScanMode.Full => 500,
            _ => 1_500
        };

        int scanned = 0;
        bool partial = false;

        try
        {
            scanned += await ScanSqliteFreelistAsync(
                databasePath,
                "SQLite freelist",
                profile,
                rules,
                maxPages,
                maxEvidence,
                evidence,
                recoveredKeys,
                token);
        }
        catch
        {
            partial = true;
        }

        try
        {
            scanned += await ScanWalAsync(
                databasePath + "-wal",
                "SQLite WAL",
                profile,
                rules,
                maxPages,
                maxEvidence,
                evidence,
                recoveredKeys,
                token);
        }
        catch
        {
            partial = true;
        }

        try
        {
            scanned += await ScanRawCompanionAsync(
                databasePath + "-journal",
                "SQLite rollback journal",
                profile,
                rules,
                mode,
                maxEvidence,
                evidence,
                recoveredKeys,
                token);
        }
        catch
        {
            partial = true;
        }

        return new ResidualRecoveryResult(
            scanned,
            partial);
    }

    private static async Task<int> ScanSqliteFreelistAsync(
        string path,
        string recoverySource,
        Profile profile,
        RuleSet rules,
        int maxPages,
        int maxEvidence,
        List<EvidenceRecord> evidence,
        HashSet<string> recoveredKeys,
        CancellationToken token)
    {
        if (!File.Exists(path))
            return 0;

        await using FileStream stream =
            new(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite |
                FileShare.Delete,
                1024 * 1024,
                true);

        if (stream.Length < 100)
            return 0;

        byte[] header = new byte[100];
        if (await ReadExactlyAsync(
                stream,
                header,
                token) < header.Length)
            return 0;

        int pageSize =
            ReadUInt16BigEndian(
                header,
                16);

        if (pageSize == 1)
            pageSize = 65_536;

        if (pageSize < 512 ||
            pageSize > 65_536)
            return 0;

        uint trunkPage =
            ReadUInt32BigEndian(
                header,
                32);

        uint declaredFreePages =
            ReadUInt32BigEndian(
                header,
                36);

        if (trunkPage == 0 ||
            declaredFreePages == 0)
            return 0;

        int scanned = 0;
        var visited =
            new HashSet<uint>();

        byte[] page =
            new byte[pageSize];

        while (
            trunkPage > 0 &&
            scanned < maxPages &&
            visited.Add(trunkPage))
        {
            token.ThrowIfCancellationRequested();

            if (!await ReadPageAsync(
                    stream,
                    trunkPage,
                    page,
                    token))
                break;

            uint nextTrunk =
                ReadUInt32BigEndian(
                    page,
                    0);

            uint leafCount =
                Math.Min(
                    ReadUInt32BigEndian(
                        page,
                        4),
                    (uint)Math.Max(
                        0,
                        (pageSize - 8) / 4));

            for (
                uint index = 0;
                index < leafCount &&
                scanned < maxPages;
                index++)
            {
                uint leafPage =
                    ReadUInt32BigEndian(
                        page,
                        8 + checked((int)index * 4));

                if (leafPage == 0)
                    continue;

                if (!await ReadPageAsync(
                        stream,
                        leafPage,
                        page,
                        token))
                    continue;

                scanned++;

                AddRecoveredFragments(
                    page,
                    recoverySource,
                    profile,
                    rules,
                    maxEvidence,
                    evidence,
                    recoveredKeys);
            }

            trunkPage = nextTrunk;
        }

        return scanned;
    }

    private static async Task<int> ScanWalAsync(
        string path,
        string recoverySource,
        Profile profile,
        RuleSet rules,
        int maxPages,
        int maxEvidence,
        List<EvidenceRecord> evidence,
        HashSet<string> recoveredKeys,
        CancellationToken token)
    {
        if (!File.Exists(path))
            return 0;

        await using FileStream stream =
            new(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite |
                FileShare.Delete,
                1024 * 1024,
                true);

        if (stream.Length < 32)
            return 0;

        byte[] header = new byte[32];
        if (await ReadExactlyAsync(
                stream,
                header,
                token) < header.Length)
            return 0;

        int pageSize =
            checked((int)ReadUInt32BigEndian(
                header,
                8));

        if (pageSize == 0)
            pageSize = 65_536;

        if (pageSize < 512 ||
            pageSize > 65_536)
            return 0;

        int frameSize =
            checked(
                24 +
                pageSize);

        byte[] frame =
            new byte[frameSize];

        int scanned = 0;

        while (
            scanned < maxPages &&
            stream.Position + frameSize <=
            stream.Length)
        {
            token.ThrowIfCancellationRequested();

            int read =
                await ReadExactlyAsync(
                    stream,
                    frame,
                    token);

            if (read < frameSize)
                break;

            scanned++;

            AddRecoveredFragments(
                frame.AsSpan(
                    24,
                    pageSize),
                recoverySource,
                profile,
                rules,
                maxEvidence,
                evidence,
                recoveredKeys);
        }

        return scanned;
    }

    private static async Task<int> ScanRawCompanionAsync(
        string path,
        string recoverySource,
        Profile profile,
        RuleSet rules,
        ScanMode mode,
        int maxEvidence,
        List<EvidenceRecord> evidence,
        HashSet<string> recoveredKeys,
        CancellationToken token)
    {
        if (!File.Exists(path))
            return 0;

        long byteLimit = mode switch
        {
            ScanMode.Quick =>
                8L * 1024 * 1024,
            ScanMode.Full =>
                32L * 1024 * 1024,
            _ =>
                128L * 1024 * 1024
        };

        await using FileStream stream =
            new(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite |
                FileShare.Delete,
                1024 * 1024,
                true);

        byte[] buffer =
            new byte[64 * 1024];

        long readTotal = 0;
        int chunks = 0;

        while (
            readTotal < byteLimit)
        {
            token.ThrowIfCancellationRequested();

            int requested =
                (int)Math.Min(
                    buffer.Length,
                    byteLimit -
                    readTotal);

            int read =
                await stream.ReadAsync(
                    buffer.AsMemory(
                        0,
                        requested),
                    token);

            if (read == 0)
                break;

            readTotal += read;
            chunks++;

            AddRecoveredFragments(
                buffer.AsSpan(
                    0,
                    read),
                recoverySource,
                profile,
                rules,
                maxEvidence,
                evidence,
                recoveredKeys);
        }

        return chunks;
    }

    private static void AddRecoveredFragments(
        ReadOnlySpan<byte> bytes,
        string recoverySource,
        Profile profile,
        RuleSet rules,
        int maxEvidence,
        List<EvidenceRecord> evidence,
        HashSet<string> recoveredKeys)
    {
        if (evidence.Count >= maxEvidence)
            return;

        foreach (string fragment in
                 ExtractPrintableRuns(
                     bytes,
                     5,
                     640))
        {
            KnownCheatNameEntry? named =
                RuleMatcher.FindKnownCheatName(
                    fragment,
                    rules);

            bool knownDomain =
                RuleMatcher.IsKnownDomain(
                    fragment,
                    rules);

            if (named is null &&
                !knownDomain)
                continue;

            string familyName =
                named?.Name ??
                "Known cheat distribution domain";

            string key =
                string.Join(
                    "|",
                    profile.Browser,
                    profile.Name,
                    recoverySource,
                    familyName);

            if (!recoveredKeys.Add(key))
                continue;

            evidence.Add(
                new EvidenceRecord
                {
                    Kind =
                        EvidenceKind.Browser,
                    Source =
                        "Browser residual recovery",
                    Name =
                        familyName,
                    Url =
                        TryExtractUrl(
                            fragment),
                    Detail =
                        "A named cheat-family or known-domain fragment was recovered from SQLite residual storage. It may represent deleted, stale, or duplicated browser history and has no reliable visit timestamp.",
                    Metadata =
                        new Dictionary<string, string>(
                            StringComparer.OrdinalIgnoreCase)
                        {
                            ["Browser"] =
                                profile.Browser,
                            ["Profile"] =
                                profile.Name,
                            ["RecordType"] =
                                "RecoveredBrowserFragment",
                            ["RecoverySource"] =
                                recoverySource,
                            ["FamilyName"] =
                                familyName,
                            ["DeletedHistoryPossible"] =
                                "True",
                            ["TimestampReliable"] =
                                "False",
                            ["RecoveredFragment"] =
                                TruncateFragment(
                                    fragment,
                                    320)
                        }
                });

            if (evidence.Count >= maxEvidence)
                break;
        }
    }

    private static IReadOnlyList<string>
        ExtractPrintableRuns(
            ReadOnlySpan<byte> bytes,
            int minimumLength,
            int maximumLength)
    {
        var output =
            new List<string>();

        var builder =
            new StringBuilder();

        for (int index = 0;
             index < bytes.Length;
             index++)
        {
            byte value =
                bytes[index];

            if (value is >= 32 and <= 126)
            {
                if (builder.Length <
                    maximumLength)
                {
                    builder.Append(
                        (char)value);
                }

                continue;
            }

            FlushPrintableRun(
                builder,
                output,
                minimumLength);
        }

        FlushPrintableRun(
            builder,
            output,
            minimumLength);

        return output;
    }

    private static void FlushPrintableRun(
        StringBuilder builder,
        List<string> output,
        int minimumLength)
    {
        if (builder.Length >= minimumLength)
        {
            string value =
                builder
                    .ToString()
                    .Trim();

            if (!string.IsNullOrWhiteSpace(value))
                output.Add(value);
        }

        builder.Clear();
    }

    private static string? TryExtractUrl(
        string value)
    {
        int http =
            value.IndexOf(
                "http://",
                StringComparison.OrdinalIgnoreCase);

        int https =
            value.IndexOf(
                "https://",
                StringComparison.OrdinalIgnoreCase);

        int start =
            http < 0
                ? https
                : https < 0
                    ? http
                    : Math.Min(
                        http,
                        https);

        if (start < 0)
            return null;

        int end = start;

        while (
            end < value.Length &&
            !char.IsWhiteSpace(
                value[end]) &&
            value[end] is not
                ('"' or '\'' or '<' or '>'))
        {
            end++;
        }

        return value[start..end]
            .TrimEnd(
                '.',
                ',',
                ';',
                ')',
                ']');
    }

    private static string TruncateFragment(
        string value,
        int maximum)
    {
        return value.Length <= maximum
            ? value
            : value[..maximum] + "...";
    }

    private static async Task<bool> ReadPageAsync(
        FileStream stream,
        uint pageNumber,
        byte[] buffer,
        CancellationToken token)
    {
        if (pageNumber == 0)
            return false;

        long offset =
            checked(
                ((long)pageNumber - 1L) *
                buffer.Length);

        if (
            offset < 0 ||
            offset + buffer.Length >
            stream.Length)
            return false;

        stream.Position = offset;

        return await ReadExactlyAsync(
                   stream,
                   buffer,
                   token) ==
               buffer.Length;
    }

    private static async Task<int> ReadExactlyAsync(
        Stream stream,
        byte[] buffer,
        CancellationToken token)
    {
        int offset = 0;

        while (offset < buffer.Length)
        {
            int read =
                await stream.ReadAsync(
                    buffer.AsMemory(
                        offset,
                        buffer.Length -
                        offset),
                    token);

            if (read == 0)
                break;

            offset += read;
        }

        return offset;
    }

    private static ushort ReadUInt16BigEndian(
        byte[] buffer,
        int offset)
    {
        return checked(
            (ushort)(
                (buffer[offset] << 8) |
                buffer[offset + 1]));
    }

    private static uint ReadUInt32BigEndian(
        byte[] buffer,
        int offset)
    {
        return
            ((uint)buffer[offset] << 24) |
            ((uint)buffer[offset + 1] << 16) |
            ((uint)buffer[offset + 2] << 8) |
            buffer[offset + 3];
    }

    private sealed record ResidualRecoveryResult(
        int PagesOrChunksScanned,
        bool Partial);

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
