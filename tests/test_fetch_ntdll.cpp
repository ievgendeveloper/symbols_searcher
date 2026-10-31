#include "fixture_bytes.h"
#include "pdb_stuff/fixtures.h"
#include "pdb_stuff/io.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <string_view>
#include <utility>

namespace
{
    using namespace pdbStuff;
    namespace fs = std::filesystem;

    void WriteBytes(const fs::path& filePath, const Bytes& bytes)
    {
        fs::create_directories(filePath.parent_path());
        std::ofstream outputStream(filePath, std::ios::binary | std::ios::trunc);
        outputStream.write(reinterpret_cast<const char*>(bytes.data()),
                           static_cast<std::streamsize>(bytes.size()));
        if (!outputStream)
        {
            throw std::runtime_error("Cannot write native test fixture");
        }
    }

    class FetchNtdll : public testing::Test
    {
        protected:
            fs::path testDirectory;
            int networkCallCount = 0;
            DownloadFn unexpectedNetworkDownloader = [this](std::string_view, bool) -> Bytes
            {
                ++networkCallCount;
                throw std::runtime_error(
                    "Offline regression test unexpectedly invoked the downloader");
            };

            void SetUp() override
            {
                static std::atomic<uint64_t> directorySequence{0};
                const auto timestampTicks =
                    std::chrono::steady_clock::now().time_since_epoch().count();
                testDirectory = fs::temp_directory_path() /
                                ("symfind-fetch-test-" + std::to_string(timestampTicks) + "-" +
                                 std::to_string(directorySequence.fetch_add(1)));
                if (!fs::create_directory(testDirectory))
                {
                    throw std::runtime_error("Native test directory already exists");
                }
            }

            void TearDown() override
            {
                EXPECT_EQ(networkCallCount, 0);
                std::error_code cleanupError;
                fs::remove_all(testDirectory, cleanupError);
            }

            void CacheArchive(const fs::path& corpusDirectory, const Bytes& archiveBytes,
                              const Json& archivePin)
            {
                WriteBytes(corpusDirectory.parent_path() / "archives" /
                               (archivePin.at("sha256").get<std::string>() + ".tar.gz"),
                           archiveBytes);
            }

            FetchOptions Options(std::string_view label = "local")
            {
                FetchOptions fetchOptions;
                fetchOptions.manifestPath = testDirectory / "empty.json";
                fetchOptions.outputRoot = testDirectory / "out";
                fetchOptions.labels = {std::string(label)};
                fetchOptions.download = unexpectedNetworkDownloader;
                WriteJson(fetchOptions.manifestPath,
                          Json{{"schema_version", 1}, {"fixtures", Json::array()}});
                return fetchOptions;
            }

            Json ImportLocal(const Json& fixturePin = Json{{"label", "local"}})
            {
                WriteBytes(testDirectory / "source.dll", symfind::testFixtures::MakePe());
                WriteBytes(testDirectory / "source.pdb", symfind::testFixtures::MakePdb());
                return ProcessFixture(fixturePin, testDirectory / "out", false,
                                      testDirectory / "source.dll", testDirectory / "source.pdb",
                                      unexpectedNetworkDownloader);
            }
    };

    TEST_F(FetchNtdll, Sha256MatchesIndependentKnownVectors)
    {
        EXPECT_EQ(Sha256(Bytes{}),
                  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        EXPECT_EQ(Sha256(Bytes{'a', 'b', 'c'}),
                  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    TEST_F(FetchNtdll, PeRsdsGuidByteOrderAndBasename)
    {
        const auto peIdentity = ParsePe(symfind::testFixtures::MakePe());
        EXPECT_EQ(peIdentity.at("timestamp"), 0x4ce7c8f9);
        EXPECT_EQ(peIdentity.at("pdb"),
                  (Json{{"name", "ntdll.pdb"}, {"guid", symfind::testFixtures::guid}, {"age", 2}}));
        EXPECT_EQ(DllUrl(peIdentity),
                  std::string(symbolServer) + "/ntdll.dll/4CE7C8F92000/ntdll.dll");
        EXPECT_EQ(PdbUrl(peIdentity.at("pdb")),
                  std::string(symbolServer) +
                      "/ntdll.pdb/6192BFDB9F04442995FFCB0BE95172E12/ntdll.pdb");
    }

    TEST_F(FetchNtdll, CorruptPeDebugDirectoryIsRejected)
    {
        auto peBytes = symfind::testFixtures::MakePe();
        symfind::testFixtures::Put(peBytes, 0x200 + 24, 0xffffff00, 4);
        EXPECT_THROW((void)ParsePe(peBytes), FixtureError);
    }

    TEST_F(FetchNtdll, X86DllIsRejected)
    {
        auto peBytes = symfind::testFixtures::MakePe();
        symfind::testFixtures::Put(peBytes, 0x84, 0x14c, 2);
        EXPECT_THROW((void)ParsePe(peBytes), FixtureError);
    }

    TEST_F(FetchNtdll, PdbNoncontiguousInfoStream)
    {
        const auto pdbIdentity = ParsePdbIdentity(symfind::testFixtures::MakePdb());
        EXPECT_EQ(pdbIdentity.at("guid").get<std::string>(),
                  std::string(symfind::testFixtures::guid));
        EXPECT_EQ(pdbIdentity.at("age"), 2);
    }

    TEST_F(FetchNtdll, WrongPdbGuidAndAgeAreRejected)
    {
        const auto pdbIdentity = ParsePe(symfind::testFixtures::MakePe()).at("pdb");
        EXPECT_THROW((void)ValidatePdb(symfind::testFixtures::MakePdb(3, 3), pdbIdentity),
                     FixtureError);
        std::array<uint8_t, 16> wrongGuid{};
        wrongGuid.back() = 1;
        EXPECT_THROW(
            (void)ValidatePdb(symfind::testFixtures::MakePdb(2, 2, wrongGuid), pdbIdentity),
            FixtureError);
    }

    TEST_F(FetchNtdll, PublishedPdbInfoAgeCanIncreaseOnlyWithMatchingDbiAge)
    {
        const auto pdbIdentity = ParsePe(symfind::testFixtures::MakePe()).at("pdb");
        const auto validatedPdbIdentity =
            ValidatePdb(symfind::testFixtures::MakePdb(4, 2), pdbIdentity);
        EXPECT_EQ(validatedPdbIdentity.at("age"), 4);
        EXPECT_EQ(validatedPdbIdentity.at("dbi_age"), 2);
        EXPECT_THROW((void)ValidatePdb(symfind::testFixtures::MakePdb(1, 2), pdbIdentity),
                     FixtureError);
        EXPECT_THROW((void)ValidatePdb(symfind::testFixtures::MakePdb(4, 3), pdbIdentity),
                     FixtureError);
    }

    TEST_F(FetchNtdll, TruncatedAndInvalidPdbBlocksAreRejected)
    {
        auto pdbBytes = symfind::testFixtures::MakePdb();
        pdbBytes.pop_back();
        EXPECT_THROW((void)ParsePdbIdentity(pdbBytes), FixtureError);
        pdbBytes = symfind::testFixtures::MakePdb();
        symfind::testFixtures::Put(pdbBytes, 512 * 4 + 20, 99, 4);
        EXPECT_THROW((void)ParsePdbIdentity(pdbBytes), FixtureError);
    }

    TEST_F(FetchNtdll, DllAndPdbHashesAreChecked)
    {
        EXPECT_THROW((void)ValidatePe(symfind::testFixtures::MakePe(),
                                      Json{{"sha256", std::string(64, '0')}}),
                     FixtureError);
        EXPECT_THROW((void)ValidatePdb(symfind::testFixtures::MakePdb(),
                                       ParsePe(symfind::testFixtures::MakePe()).at("pdb"),
                                       std::string(64, '0')),
                     FixtureError);
    }

    TEST_F(FetchNtdll, NetworkOptInIsEnforcedBeforeDownloader)
    {
        EXPECT_THROW((void)Download(std::string(symbolServer) + "/ntdll.dll/id/ntdll.dll", false),
                     NetworkDisabled);
        EXPECT_THROW((void)EnsureFile(
                         testDirectory / "missing.pdb", "unused",
                         [](auto)
                         {
                             return Json{};
                         },
                         false, unexpectedNetworkDownloader),
                     NetworkDisabled);
    }

    TEST_F(FetchNtdll, InvalidDownloadNeverReplacesExistingFile)
    {
        const auto cachedPdbPath = testDirectory / "ntdll.pdb";
        const Bytes originalFileBytes{'e', 'x', 'i', 's', 't', 'i', 'n', 'g'};
        WriteBytes(cachedPdbPath, originalFileBytes);
        const auto expectedPdbIdentity = ParsePe(symfind::testFixtures::MakePe()).at("pdb");
        int attemptedDownloads = 0;
        const DownloadFn invalidPdbDownloader = [&](std::string_view, bool)
        {
            ++attemptedDownloads;
            return symfind::testFixtures::MakePdb(3, 3);
        };
        EXPECT_THROW((void)EnsureFile(
                         cachedPdbPath, "unused",
                         [&](auto downloadedPdbBytes)
                         {
                             return ValidatePdb(downloadedPdbBytes, expectedPdbIdentity);
                         },
                         true, invalidPdbDownloader),
                     FixtureError);
        EXPECT_EQ(attemptedDownloads, 1);
        EXPECT_EQ(ReadFile(cachedPdbPath), originalFileBytes);
        for (const auto& directoryEntry : fs::directory_iterator(testDirectory))
        {
            EXPECT_NE(directoryEntry.path().extension(), ".part");
        }
    }

    TEST_F(FetchNtdll, LocalImportIsFullyOfflineAndCanBeRevalidated)
    {
        const auto fixtureResult =
            ImportLocal(Json{{"label", "local"}, {"provenance", {{"kind", "local_import"}}}});
        ASSERT_EQ(fixtureResult.at("status"), "ready");
        const auto revalidatedFixture =
            ProcessFixture(Json{{"label", "local"}, {"pe", fixtureResult.at("pe")}},
                           testDirectory / "out", false, {}, {}, unexpectedNetworkDownloader);
        EXPECT_EQ(revalidatedFixture.at("status"), "ready");
    }

    TEST_F(FetchNtdll, LocalImportWithoutManifestAndCachedLabelVerification)
    {
        auto fetchOptions = Options();
        fetchOptions.manifestPath = testDirectory / "nonexistent.json";
        fetchOptions.sourceDll = testDirectory / "source.dll";
        fetchOptions.sourcePdb = testDirectory / "source.pdb";
        WriteBytes(*fetchOptions.sourceDll, symfind::testFixtures::MakePe());
        WriteBytes(*fetchOptions.sourcePdb, symfind::testFixtures::MakePdb());
        EXPECT_TRUE(ProcessManifest(fetchOptions).successful);
        fetchOptions.sourceDll.reset();
        fetchOptions.sourcePdb.reset();
        fetchOptions.manifestPath = testDirectory / "empty.json";
        EXPECT_TRUE(ProcessManifest(fetchOptions).successful);
    }

    TEST_F(FetchNtdll, InvalidImportIsNotHiddenByAllowMissing)
    {
        auto fetchOptions = Options();
        fetchOptions.sourceDll = testDirectory / "source.dll";
        fetchOptions.sourcePdb = testDirectory / "source.pdb";
        fetchOptions.allowMissing = true;
        WriteBytes(*fetchOptions.sourceDll, symfind::testFixtures::MakePe());
        WriteBytes(*fetchOptions.sourcePdb, symfind::testFixtures::MakePdb(3, 3));
        EXPECT_FALSE(ProcessManifest(fetchOptions).successful);
        EXPECT_EQ(ReadJson(testDirectory / "out/local/manifest.json").at("status"), "invalid");
        EXPECT_FALSE(fs::exists(testDirectory / "out/local/ntdll.pdb"));
    }

    TEST_F(FetchNtdll, FailedValidationKeepsLastKnownPdbHashForLaterImports)
    {
        const auto importedFixture = ImportLocal();
        ASSERT_EQ(importedFixture.at("status"), "ready");
        const auto originalPdbHash = importedFixture.at("pdb").at("sha256");
        auto modifiedPdbBytes = symfind::testFixtures::MakePdb();
        modifiedPdbBytes.back() ^= 1; // Identity stays valid while the full-file pin changes.
        WriteBytes(testDirectory / "out/local/ntdll.pdb", modifiedPdbBytes);
        for (int retryIndex = 0; retryIndex < 2; ++retryIndex)
        {
            const auto failedFixture =
                ProcessFixture(Json{{"label", "local"}}, testDirectory / "out", false,
                               testDirectory / "source.dll", {}, unexpectedNetworkDownloader);
            EXPECT_EQ(failedFixture.at("status"), "invalid");
            EXPECT_EQ(failedFixture.at("expected_pdb_sha256"), originalPdbHash);
        }
        const auto repairedFixture = ProcessFixture(
            Json{{"label", "local"}}, testDirectory / "out", false, testDirectory / "source.dll",
            testDirectory / "source.pdb", unexpectedNetworkDownloader);
        EXPECT_EQ(repairedFixture.at("status"), "ready");
        EXPECT_EQ(repairedFixture.at("pdb").at("sha256"), originalPdbHash);
    }

    TEST_F(FetchNtdll, FailedDllValidationKeepsPinForCachedRevalidation)
    {
        const auto importedFixture = ImportLocal();
        ASSERT_EQ(importedFixture.at("status"), "ready");
        WriteBytes(testDirectory / "out/local/ntdll.dll", Bytes{'b', 'a', 'd'});
        const auto failedFixture =
            ProcessFixture(Json{{"label", "local"}, {"pe", importedFixture.at("pe")}},
                           testDirectory / "out", false, {}, {}, unexpectedNetworkDownloader);
        EXPECT_EQ(failedFixture.at("status"), "invalid");
        EXPECT_EQ(failedFixture.at("expected_pdb_sha256"), importedFixture.at("pdb").at("sha256"));
        WriteBytes(testDirectory / "out/local/ntdll.dll", symfind::testFixtures::MakePe());
        EXPECT_TRUE(ProcessManifest(Options()).successful);
    }

    TEST_F(FetchNtdll, PinnedArchiveImportAndCachedRepairAreOffline)
    {
        const auto corpusDirectory = testDirectory / "out";
        const auto archiveBytes = symfind::testFixtures::MakeArchive();
        const auto archivePin = symfind::testFixtures::ArchiveConfig(archiveBytes);
        CacheArchive(corpusDirectory, archiveBytes, archivePin);
        WriteBytes(corpusDirectory / "nano/ntdll.pdb", symfind::testFixtures::MakePdb());
        const Json fixturePin{{"label", "nano"},
                              {"pe", ParsePe(symfind::testFixtures::MakePe())},
                              {"dll_archive", archivePin},
                              {"pdb_sha256", Sha256(symfind::testFixtures::MakePdb())}};
        const auto fixtureResult =
            ProcessFixture(fixturePin, corpusDirectory, false, {}, {}, unexpectedNetworkDownloader);
        ASSERT_EQ(fixtureResult.at("status"), "ready");
        EXPECT_EQ(ReadFile(corpusDirectory / "nano/ntdll.dll"), symfind::testFixtures::MakePe());
        EXPECT_EQ(fixtureResult.at("dll_url"), archivePin.at("url"));
        WriteBytes(corpusDirectory / "nano/ntdll.dll", Bytes{'b', 'a', 'd'});
        EXPECT_TRUE(ProcessManifest(Options("nano")).successful);
        EXPECT_EQ(ReadFile(corpusDirectory / "nano/ntdll.dll"), symfind::testFixtures::MakePe());
    }

    TEST_F(FetchNtdll, ValidCachedDllDoesNotNeedArchiveOrNetwork)
    {
        const auto corpusDirectory = testDirectory / "out";
        WriteBytes(corpusDirectory / "nano/ntdll.dll", symfind::testFixtures::MakePe());
        const auto validatedPeIdentity = EnsureImageFile(
            corpusDirectory / "nano/ntdll.dll", ParsePe(symfind::testFixtures::MakePe()),
            symfind::testFixtures::ArchiveConfig(symfind::testFixtures::MakeArchive()),
            corpusDirectory, false, unexpectedNetworkDownloader);
        EXPECT_EQ(validatedPeIdentity.at("sha256"), Sha256(symfind::testFixtures::MakePe()));
        EXPECT_FALSE(fs::exists(testDirectory / "archives"));
    }

    TEST_F(FetchNtdll, WrongArchiveHashOrSizeNeverCreatesDll)
    {
        const auto corpusDirectory = testDirectory / "out";
        const auto archiveBytes = symfind::testFixtures::MakeArchive();
        for (bool wrongHash : {true, false})
        {
            auto archivePin = symfind::testFixtures::ArchiveConfig(archiveBytes);
            if (wrongHash)
            {
                archivePin["sha256"] = std::string(64, '0');
                archivePin["url"] =
                    "https://mcr.microsoft.com/v2/windows/nanoserver/blobs/sha256:" +
                    std::string(64, '0');
            }
            else
            {
                archivePin["file_size"] = 1;
            }
            CacheArchive(corpusDirectory, archiveBytes, archivePin);
            EXPECT_THROW((void)EnsureImageFile(corpusDirectory / "nano/ntdll.dll",
                                               ParsePe(symfind::testFixtures::MakePe()), archivePin,
                                               corpusDirectory, false, unexpectedNetworkDownloader),
                         FixtureError);
            EXPECT_FALSE(fs::exists(corpusDirectory / "nano/ntdll.dll"));
        }
    }

    TEST_F(FetchNtdll, ArchiveMemberPathsAndNonMicrosoftSourcesAreRejected)
    {
        const auto archivePin =
            symfind::testFixtures::ArchiveConfig(symfind::testFixtures::MakeArchive());
        for (const std::string archiveMemberPath :
             {"../ntdll.dll", "/ntdll.dll", "Files/../ntdll.dll", "Files\\ntdll.dll",
              "C:ntdll.dll"})
        {
            SCOPED_TRACE(archiveMemberPath);
            auto unsafeArchivePin = archivePin;
            unsafeArchivePin["member"] = archiveMemberPath;
            EXPECT_THROW((void)ValidateArchiveConfig(unsafeArchivePin), FixtureError);
        }
        const auto archiveUrl = archivePin.at("url").get<std::string>();
        auto servercoreUrl = archiveUrl;
        servercoreUrl.replace(servercoreUrl.find("nanoserver"), 10, "servercore");
        for (const auto& unsupportedUrl : {archiveUrl + "/extra", servercoreUrl,
                                           std::string("https://example.com/archive.tar.gz")})
        {
            EXPECT_FALSE(IsSupportedDownloadUrl(unsupportedUrl));
        }
    }

    TEST_F(FetchNtdll, MissingOrLinkedArchiveMemberIsRejected)
    {
        const auto corpusDirectory = testDirectory / "out";
        for (const auto& archiveBytes :
             {symfind::testFixtures::MakeArchive("other/ntdll.dll"),
              symfind::testFixtures::MakeArchive(symfind::testFixtures::dllMember, {}, '2')})
        {
            const auto archivePin = symfind::testFixtures::ArchiveConfig(archiveBytes);
            CacheArchive(corpusDirectory, archiveBytes, archivePin);
            EXPECT_THROW((void)EnsureImageFile(corpusDirectory / "nano/ntdll.dll",
                                               ParsePe(symfind::testFixtures::MakePe()), archivePin,
                                               corpusDirectory, false, unexpectedNetworkDownloader),
                         FixtureError);
        }
        EXPECT_FALSE(fs::exists(corpusDirectory / "nano/ntdll.dll"));
    }

    TEST_F(FetchNtdll, ArchivePayloadIsBoundedAndPePinIsStrict)
    {
        const auto corpusDirectory = testDirectory / "out";
        const auto archiveBytes = symfind::testFixtures::MakeArchive();
        const auto archivePin = symfind::testFixtures::ArchiveConfig(archiveBytes);
        CacheArchive(corpusDirectory, archiveBytes, archivePin);
        const auto archivePath = corpusDirectory.parent_path() / "archives" /
                                 (archivePin.at("sha256").get<std::string>() + ".tar.gz");
        EXPECT_THROW((void)ReadArchiveMember(archivePath, symfind::testFixtures::dllMember, 512),
                     FixtureError);
        EXPECT_THROW((void)EnsureImageFile(corpusDirectory / "nano/ntdll.dll",
                                           Json{{"sha256", std::string(64, '0')}}, archivePin,
                                           corpusDirectory, false, unexpectedNetworkDownloader),
                     FixtureError);
        EXPECT_FALSE(fs::exists(corpusDirectory / "nano/ntdll.dll"));
    }

    TEST_F(FetchNtdll, MissingArchiveDoesNotStartNetworkWithoutOptIn)
    {
        const auto corpusDirectory = testDirectory / "out";
        EXPECT_THROW((void)EnsureImageFile(
                         corpusDirectory / "nano/ntdll.dll",
                         ParsePe(symfind::testFixtures::MakePe()),
                         symfind::testFixtures::ArchiveConfig(symfind::testFixtures::MakeArchive()),
                         corpusDirectory, false, unexpectedNetworkDownloader),
                     NetworkDisabled);
    }

    TEST_F(FetchNtdll, CorruptTarAndIncompleteOrTrailingGzipAreRejected)
    {
        auto tarBytes = symfind::testFixtures::MakeTar();
        tarBytes[0] ^= 1; // Keep gzip CRC valid, but invalidate only the tar header checksum.
        const auto filePath = testDirectory / "corrupted.tar.gz";
        WriteBytes(filePath, symfind::testFixtures::GzipBytes(tarBytes));
        EXPECT_THROW((void)ReadArchiveMember(filePath, symfind::testFixtures::dllMember),
                     FixtureError);
        auto truncatedArchive = symfind::testFixtures::MakeArchive();
        truncatedArchive.resize(truncatedArchive.size() - 5);
        WriteBytes(filePath, truncatedArchive);
        EXPECT_THROW((void)ReadArchiveMember(filePath, symfind::testFixtures::dllMember),
                     FixtureError);
        auto archiveWithCorruptCrc = symfind::testFixtures::MakeArchive();
        archiveWithCorruptCrc[archiveWithCorruptCrc.size() - 8] ^= 1;
        WriteBytes(filePath, archiveWithCorruptCrc);
        EXPECT_THROW((void)ReadArchiveMember(filePath, symfind::testFixtures::dllMember),
                     FixtureError);
        auto archiveWithTrailingData = symfind::testFixtures::MakeArchive();
        archiveWithTrailingData.push_back(0);
        WriteBytes(filePath, archiveWithTrailingData);
        EXPECT_THROW((void)ReadArchiveMember(filePath, symfind::testFixtures::dllMember),
                     FixtureError);
        auto concatenatedArchives = symfind::testFixtures::MakeArchive();
        const auto secondArchive = symfind::testFixtures::MakeArchive();
        concatenatedArchives.insert(concatenatedArchives.end(), secondArchive.begin(),
                                    secondArchive.end());
        WriteBytes(filePath, concatenatedArchives);
        EXPECT_THROW((void)ReadArchiveMember(filePath, symfind::testFixtures::dllMember),
                     FixtureError);
    }

    TEST_F(FetchNtdll, ArchiveScanLimitAlsoBoundsSkippedPayload)
    {
        const auto filePath = testDirectory / "skipped.tar.gz";
        WriteBytes(filePath, symfind::testFixtures::MakeArchive("other/ntdll.dll", Bytes(4096)));
        EXPECT_THROW(
            (void)ReadArchiveMember(filePath, symfind::testFixtures::dllMember, maxDllBytes, 1024),
            FixtureError);
    }

    TEST_F(FetchNtdll, WinbindexPinKeepsExplicitClientProvenance)
    {
        Json manifestDocument{
            {"fixtures",
             Json::array(
                 {Json{{"label", "server-candidate"},
                       {"provenance", {{"os_coverage", false}, {"proven_os", "Windows 10 1607"}}},
                       {"winbindex_selector",
                        {{"windows_version", "1607"}, {"version_prefix", "10.0.14393."}}}}})}};
        const Json winbindexMetadata{
            {std::string(64, 'a'),
             {{"fileInfo",
               {{"machineType", 34404},
                {"virtualSize", 0x2000},
                {"size", 1000},
                {"timestamp", 10},
                {"version", "10.0.14393.0 (build)"}}},
              {"windowsVersions",
               {{"1607",
                 {{"BASE", {{"sourcePaths", Json::array({"Windows\\System32\\ntdll.dll"})}}}}}}}}}};
        RefreshClientPins(manifestDocument, symfind::testFixtures::GzipJson(winbindexMetadata));
        const auto& fixturePin = manifestDocument.at("fixtures").at(0);
        EXPECT_EQ(fixturePin.at("pe").at("version"), "10.0.14393.0");
        EXPECT_EQ(fixturePin.at("provenance").at("os_coverage"), false);
        EXPECT_EQ(fixturePin.at("provenance").at("proven_os"), "Windows 10 1607");
    }
} // namespace
