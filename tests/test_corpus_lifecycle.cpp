#include "fixture_bytes.h"
#include "pdb_stuff/corpus.h"
#include "symfind/compat.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{
    using namespace pdbStuff;
    namespace fs = std::filesystem;

    struct FileStamp
    {
            bool isDirectory = false;
            fs::file_time_type modifiedTime;
            Bytes fileContents;
            bool operator==(const FileStamp& otherStamp) const
            {
                return isDirectory == otherStamp.isDirectory &&
                       modifiedTime == otherStamp.modifiedTime &&
                       fileContents == otherStamp.fileContents;
            }
            bool operator!=(const FileStamp& otherStamp) const
            {
                return !(*this == otherStamp);
            }
    };

    using TreeSnapshot = std::map<std::string, FileStamp>;

    TreeSnapshot Snapshot(const fs::path& directory)
    {
        TreeSnapshot treeSnapshot;
        if (!fs::exists(directory))
        {
            return treeSnapshot;
        }
        const auto recordFileStamp = [&](const fs::path& path)
        {
            const bool isDirectory = fs::is_directory(path);
            treeSnapshot.emplace(path.lexically_relative(directory).generic_string(),
                                 FileStamp{isDirectory, fs::last_write_time(path),
                                           isDirectory ? Bytes{} : ReadFile(path)});
        };
        recordFileStamp(directory);
        for (const auto& directoryEntry : fs::recursive_directory_iterator(directory))
        {
            recordFileStamp(directoryEntry.path());
        }
        return treeSnapshot;
    }

    bool IsWithin(const fs::path& path, const fs::path& directory)
    {
        const auto absolutePath = fs::weakly_canonical(path);
        const auto absoluteDirectory = fs::weakly_canonical(directory);
        auto candidateComponent = absolutePath.begin();
        for (auto expectedComponent = absoluteDirectory.begin();
             expectedComponent != absoluteDirectory.end();
             ++expectedComponent, ++candidateComponent)
        {
            if (candidateComponent == absolutePath.end() ||
                *candidateComponent != *expectedComponent)
            {
                return false;
            }
        }
        return true;
    }

    bool HasStagedPairFile(const CorpusResult& corpusResult, std::string_view label,
                           std::string_view fixtureFilename)
    {
        if (!fs::is_directory(corpusResult.stagingRoot))
        {
            return false;
        }
        for (const auto& directoryEntry :
             fs::recursive_directory_iterator(corpusResult.stagingRoot))
        {
            if (directoryEntry.is_regular_file() &&
                directoryEntry.path().filename() == fixtureFilename &&
                directoryEntry.path().parent_path().filename() == label)
            {
                return true;
            }
        }
        return false;
    }

    struct PairFixture
    {
            std::string label;
            Bytes dll;
            Bytes pdb;
            Json pin;
            std::string imageUrl;
            std::string symbolsUrl;
    };

    PairFixture MakePairFixture(std::string label, uint8_t identitySuffix)
    {
        PairFixture fixturePair;
        fixturePair.label = std::move(label);
        fixturePair.dll = symfind::testFixtures::MakePe();
        auto pdbSignature = symfind::testFixtures::guidBytes;
        pdbSignature.back() ^= identitySuffix;
        std::copy(pdbSignature.begin(), pdbSignature.end(), fixturePair.dll.begin() + 0x244);
        symfind::testFixtures::Put(fixturePair.dll, 0x88, 0x4ce7c8f9u + identitySuffix, 4);
        fixturePair.pdb = symfind::testFixtures::MakePdb(2, 2, pdbSignature);
        const auto peIdentity = ParsePe(fixturePair.dll);
        fixturePair.pin = Json{{"label", fixturePair.label},
                               {"pe", peIdentity},
                               {"pdb_sha256", Sha256(fixturePair.pdb)}};
        fixturePair.imageUrl = DllUrl(peIdentity);
        fixturePair.symbolsUrl = PdbUrl(peIdentity.at("pdb"));
        return fixturePair;
    }

    class CorpusLifecycle : public testing::Test
    {
        protected:
            fs::path testDirectory;
            fs::path pinnedManifestPath;
            fs::path liveCorpusDirectory;
            fs::path networkChecksDirectory;
            std::vector<PairFixture> fixturePairs;
            std::map<std::string, Bytes> downloadResponses;
            std::vector<std::string> requestedUrls;
            DownloadFn fixtureDownloader = [this](std::string_view downloadUrl, bool networkAllowed)
            {
                EXPECT_TRUE(networkAllowed);
                requestedUrls.emplace_back(downloadUrl);
                const auto responseEntry = downloadResponses.find(std::string(downloadUrl));
                if (responseEntry == downloadResponses.end())
                {
                    throw std::runtime_error("Unexpected offline test transport URL");
                }
                return responseEntry->second;
            };

            void SetUp() override
            {
                static std::atomic<uint64_t> directorySequence{0};
                const auto timestampTicks =
                    std::chrono::steady_clock::now().time_since_epoch().count();
                testDirectory = fs::weakly_canonical(fs::temp_directory_path()) /
                                ("symfind-corpus-lifecycle-" + std::to_string(timestampTicks) +
                                 "-" + std::to_string(directorySequence.fetch_add(1)));
                if (!fs::create_directory(testDirectory))
                {
                    throw std::runtime_error("Lifecycle test directory already exists");
                }
                pinnedManifestPath = testDirectory / "pinned.json";
                liveCorpusDirectory = testDirectory / "cache";
                networkChecksDirectory = testDirectory / "checks";
                fixturePairs = {MakePairFixture("alpha", 1), MakePairFixture("bravo", 2),
                                MakePairFixture("charlie", 3)};
                for (const auto& fixturePair : fixturePairs)
                {
                    downloadResponses[fixturePair.imageUrl] = fixturePair.dll;
                    downloadResponses[fixturePair.symbolsUrl] = fixturePair.pdb;
                }
                WriteJson(pinnedManifestPath, Pins());
            }

            void TearDown() override
            {
                // Verify the recursive cleanup target is the uniquely created test
                // directory directly under the system temporary directory.
                if (testDirectory.parent_path() !=
                        fs::weakly_canonical(fs::temp_directory_path()) ||
                    !symfind::StartsWith(testDirectory.filename().string(),
                                         "symfind-corpus-lifecycle-"))
                {
                    ADD_FAILURE() << "Refusing cleanup outside the lifecycle test directory";
                    return;
                }
                std::error_code cleanupError;
                fs::remove_all(testDirectory, cleanupError);
                EXPECT_FALSE(cleanupError) << cleanupError.message();
            }

            Json Pins() const
            {
                Json fixtureEntries = Json::array();
                for (const auto& fixturePair : fixturePairs)
                {
                    fixtureEntries.push_back(fixturePair.pin);
                }
                return Json{{"schema_version", 1}, {"fixtures", fixtureEntries}};
            }

            void Install(size_t fixtureCount)
            {
                Json fixtureEntries = Json::array();
                for (size_t fixtureIndex = 0; fixtureIndex < fixtureCount; ++fixtureIndex)
                {
                    const auto sourceDllPath =
                        testDirectory / "sources" / (fixturePairs[fixtureIndex].label + ".dll");
                    const auto sourcePdbPath =
                        testDirectory / "sources" / (fixturePairs[fixtureIndex].label + ".pdb");
                    (void)AtomicWrite(sourceDllPath, fixturePairs[fixtureIndex].dll);
                    (void)AtomicWrite(sourcePdbPath, fixturePairs[fixtureIndex].pdb);
                    const auto importedFixture =
                        ProcessFixture(fixturePairs[fixtureIndex].pin, liveCorpusDirectory, false,
                                       sourceDllPath, sourcePdbPath, fixtureDownloader);
                    ASSERT_EQ(importedFixture.at("status"), "ready");
                    fixtureEntries.push_back(importedFixture);
                }
                WriteJson(liveCorpusDirectory / "manifest.json",
                          Json{{"schema_version", 1}, {"fixtures", fixtureEntries}});
                ASSERT_TRUE(requestedUrls.empty());
            }

            std::multiset<std::string> AllUrls() const
            {
                std::multiset<std::string> downloadUrls;
                for (const auto& fixturePair : fixturePairs)
                {
                    downloadUrls.insert(fixturePair.imageUrl);
                    downloadUrls.insert(fixturePair.symbolsUrl);
                }
                return downloadUrls;
            }

            void ExpectReport(const CorpusResult& corpusResult)
            {
                EXPECT_TRUE(fs::is_directory(corpusResult.stagingRoot));
                EXPECT_TRUE(fs::is_regular_file(corpusResult.reportManifest));
                EXPECT_TRUE(IsWithin(corpusResult.reportManifest, corpusResult.stagingRoot));
                EXPECT_FALSE(IsWithin(corpusResult.stagingRoot, liveCorpusDirectory));
                EXPECT_FALSE(IsWithin(liveCorpusDirectory, corpusResult.stagingRoot));
            }
    };

    TEST_F(CorpusLifecycle, ValidCacheMakesNoNetworkRequestsAndNoFilesystemChanges)
    {
        Install(fixturePairs.size());
        const auto snapshotBefore = Snapshot(testDirectory);
        for (const bool networkAllowed : {false, true})
        {
            const auto corpusResult = EnsureCorpus(pinnedManifestPath, liveCorpusDirectory,
                                                   networkAllowed, fixtureDownloader);
            EXPECT_TRUE(corpusResult.successful);
            EXPECT_FALSE(corpusResult.provisioned);
            EXPECT_TRUE(corpusResult.stagingRoot.empty());
            EXPECT_TRUE(requestedUrls.empty());
            EXPECT_EQ(Snapshot(testDirectory), snapshotBefore);
        }
    }

    TEST_F(CorpusLifecycle, FixtureErrorsAreInvalidButNetworkFailuresWithNoFilesAreMissing)
    {
        for (const std::string_view failureKind : {"fixture", "network-disabled", "transport"})
        {
            SCOPED_TRACE(failureKind);
            const DownloadFn failingDownloader = [&](std::string_view, bool) -> Bytes
            {
                if (failureKind == "fixture")
                {
                    throw FixtureError("Synthetic fixture validation failure");
                }
                if (failureKind == "network-disabled")
                {
                    throw NetworkDisabled("Synthetic disabled network");
                }
                throw std::runtime_error("Synthetic transport failure");
            };
            const auto fixtureResult = ProcessFixture(
                fixturePairs[0].pin, testDirectory / failureKind, true, {}, {}, failingDownloader);
            EXPECT_EQ(fixtureResult.at("status"), failureKind == "fixture" ? "invalid" : "missing");
            EXPECT_FALSE(fixtureResult.at("reason").get<std::string>().empty());
        }
    }

    TEST_F(CorpusLifecycle, AbsentCorpusPublishesEveryPinnedPairThenReusesItWithoutChanges)
    {
        ASSERT_FALSE(fs::exists(liveCorpusDirectory));
        const auto pinnedManifestBytes = ReadFile(pinnedManifestPath);
        const auto pinnedManifestModifiedTime = fs::last_write_time(pinnedManifestPath);
        const DownloadFn stagingDownloader = [&](std::string_view downloadUrl, bool networkAllowed)
        {
            EXPECT_FALSE(fs::exists(liveCorpusDirectory));
            return fixtureDownloader(downloadUrl, networkAllowed);
        };
        const auto corpusResult =
            EnsureCorpus(pinnedManifestPath, liveCorpusDirectory, true, stagingDownloader);
        ASSERT_TRUE(corpusResult.successful);
        EXPECT_TRUE(corpusResult.provisioned);
        EXPECT_EQ((std::multiset<std::string>(requestedUrls.begin(), requestedUrls.end())),
                  AllUrls());
        ASSERT_TRUE(fs::is_regular_file(liveCorpusDirectory / "manifest.json"));
        EXPECT_EQ(ReadJson(liveCorpusDirectory / "manifest.json").at("fixtures").size(),
                  fixturePairs.size());
        for (const auto& fixturePair : fixturePairs)
        {
            EXPECT_EQ(ReadFile(liveCorpusDirectory / fixturePair.label / "ntdll.dll"),
                      fixturePair.dll);
            EXPECT_EQ(ReadFile(liveCorpusDirectory / fixturePair.label / "ntdll.pdb"),
                      fixturePair.pdb);
            const auto fixtureManifest =
                ReadJson(liveCorpusDirectory / fixturePair.label / "manifest.json");
            EXPECT_EQ(fixtureManifest.at("status"), "ready");
            EXPECT_EQ(fs::path(fixtureManifest.at("dll").get<std::string>()),
                      liveCorpusDirectory / fixturePair.label / "ntdll.dll");
            EXPECT_EQ(fs::path(fixtureManifest.at("pdb_file").get<std::string>()),
                      liveCorpusDirectory / fixturePair.label / "ntdll.pdb");
        }
        EXPECT_EQ(ReadFile(pinnedManifestPath), pinnedManifestBytes);
        EXPECT_EQ(fs::last_write_time(pinnedManifestPath), pinnedManifestModifiedTime);
        ExpectReport(corpusResult);
        requestedUrls.clear();
        const auto snapshotBefore = Snapshot(testDirectory);
        const auto cachedCorpusResult =
            EnsureCorpus(pinnedManifestPath, liveCorpusDirectory, false, fixtureDownloader);
        EXPECT_TRUE(cachedCorpusResult.successful);
        EXPECT_FALSE(cachedCorpusResult.provisioned);
        EXPECT_TRUE(requestedUrls.empty());
        EXPECT_EQ(Snapshot(testDirectory), snapshotBefore);
    }

    TEST_F(CorpusLifecycle,
           ArchiveBootstrapPublishesPinnedArchiveAndLaterRepairReusesItWithoutNetwork)
    {
        const auto archiveBytes = symfind::testFixtures::MakeArchive(
            symfind::testFixtures::dllMember, fixturePairs[0].dll);
        const auto archivePin = symfind::testFixtures::ArchiveConfig(archiveBytes);
        const auto archiveUrl = archivePin.at("url").get<std::string>();
        fixturePairs[0].pin["dll_archive"] = archivePin;
        downloadResponses[archiveUrl] = archiveBytes;
        downloadResponses.erase(fixturePairs[0].imageUrl);
        WriteJson(pinnedManifestPath, Pins());
        const auto preparedCorpusResult =
            EnsureCorpus(pinnedManifestPath, liveCorpusDirectory, true, fixtureDownloader);
        ASSERT_TRUE(preparedCorpusResult.successful) << preparedCorpusResult.reason << '\n'
                                                     << preparedCorpusResult.fixtures.dump(2);
        const auto cachedArchivePath = liveCorpusDirectory.parent_path() / "archives" /
                                       (archivePin.at("sha256").get<std::string>() + ".tar.gz");
        ASSERT_TRUE(fs::is_regular_file(cachedArchivePath));
        EXPECT_EQ(ReadFile(cachedArchivePath), archiveBytes);
        EXPECT_EQ(std::count(requestedUrls.begin(), requestedUrls.end(), archiveUrl), 1);
        EXPECT_EQ(std::count(requestedUrls.begin(), requestedUrls.end(), fixturePairs[0].imageUrl),
                  0);
        const auto archiveModifiedTime = fs::last_write_time(cachedArchivePath);
        const auto unaffectedFixtureSnapshot =
            Snapshot(liveCorpusDirectory / fixturePairs[1].label);
        const auto pdbPath = liveCorpusDirectory / fixturePairs[0].label / "ntdll.pdb";
        const auto pdbBytes = ReadFile(pdbPath);
        const auto pdbModifiedTime = fs::last_write_time(pdbPath);
        ASSERT_TRUE(fs::remove(liveCorpusDirectory / fixturePairs[0].label / "ntdll.dll"));
        requestedUrls.clear();
        const DownloadFn unexpectedNetworkDownloader = [&](std::string_view downloadUrl,
                                                           bool) -> Bytes
        {
            requestedUrls.emplace_back(downloadUrl);
            throw std::runtime_error("Pinned local archive repair must not contact the network");
        };
        const auto repairedCorpusResult = EnsureCorpus(pinnedManifestPath, liveCorpusDirectory,
                                                       true, unexpectedNetworkDownloader);
        ASSERT_TRUE(repairedCorpusResult.successful);
        EXPECT_TRUE(repairedCorpusResult.provisioned);
        EXPECT_TRUE(requestedUrls.empty());
        EXPECT_EQ(ReadFile(liveCorpusDirectory / fixturePairs[0].label / "ntdll.dll"),
                  fixturePairs[0].dll);
        EXPECT_EQ(ReadFile(cachedArchivePath), archiveBytes);
        EXPECT_EQ(fs::last_write_time(cachedArchivePath), archiveModifiedTime);
        EXPECT_EQ(ReadFile(pdbPath), pdbBytes);
        EXPECT_EQ(fs::last_write_time(pdbPath), pdbModifiedTime);
        EXPECT_EQ(Snapshot(liveCorpusDirectory / fixturePairs[1].label), unaffectedFixtureSnapshot);
    }

    TEST_F(CorpusLifecycle, LaterFixtureFailureDoesNotPublishEarlierValidatedArchiveOrAnyPairs)
    {
        const auto archiveBytes = symfind::testFixtures::MakeArchive(
            symfind::testFixtures::dllMember, fixturePairs[0].dll);
        const auto archivePin = symfind::testFixtures::ArchiveConfig(archiveBytes);
        const auto archiveUrl = archivePin.at("url").get<std::string>();
        fixturePairs[0].pin["dll_archive"] = archivePin;
        downloadResponses[archiveUrl] = archiveBytes;
        downloadResponses.erase(fixturePairs[0].imageUrl);
        WriteJson(pinnedManifestPath, Pins());
        const DownloadFn failingDownloader = [&](std::string_view downloadUrl, bool networkAllowed)
        {
            if (downloadUrl == fixturePairs[2].symbolsUrl)
            {
                requestedUrls.emplace_back(downloadUrl);
                throw std::runtime_error("Synthetic final PDB download failure");
            }
            return fixtureDownloader(downloadUrl, networkAllowed);
        };
        const auto corpusResult =
            EnsureCorpus(pinnedManifestPath, liveCorpusDirectory, true, failingDownloader);
        EXPECT_FALSE(corpusResult.successful);
        EXPECT_FALSE(fs::exists(liveCorpusDirectory));
        const auto archiveName = archivePin.at("sha256").get<std::string>() + ".tar.gz";
        EXPECT_FALSE(fs::exists(liveCorpusDirectory.parent_path() / "archives" / archiveName));
        ASSERT_TRUE(fs::is_regular_file(corpusResult.stagingRoot / "archives" / archiveName))
            << corpusResult.reason << '\n'
            << corpusResult.fixtures.dump(2);
        EXPECT_EQ(ReadFile(corpusResult.stagingRoot / "archives" / archiveName), archiveBytes);
        EXPECT_TRUE(HasStagedPairFile(corpusResult, fixturePairs[0].label, "ntdll.dll"));
        EXPECT_TRUE(HasStagedPairFile(corpusResult, fixturePairs[0].label, "ntdll.pdb"));
        ExpectReport(corpusResult);
    }

    TEST_F(CorpusLifecycle, MissingPdbDownloadsOnlyThatFileAndPreservesExistingCacheFiles)
    {
        Install(fixturePairs.size());
        ASSERT_TRUE(fs::remove(liveCorpusDirectory / fixturePairs[1].label / "ntdll.pdb"));
        const auto alphaBefore = Snapshot(liveCorpusDirectory / fixturePairs[0].label);
        const auto bravoDllPath = liveCorpusDirectory / fixturePairs[1].label / "ntdll.dll";
        const auto dllBytes = ReadFile(bravoDllPath);
        const auto dllModifiedTime = fs::last_write_time(bravoDllPath);
        const DownloadFn stagingDownloader = [&](std::string_view downloadUrl, bool networkAllowed)
        {
            EXPECT_FALSE(fs::exists(liveCorpusDirectory / fixturePairs[1].label / "ntdll.pdb"));
            EXPECT_EQ(ReadFile(bravoDllPath), dllBytes);
            return fixtureDownloader(downloadUrl, networkAllowed);
        };
        const auto corpusResult =
            EnsureCorpus(pinnedManifestPath, liveCorpusDirectory, true, stagingDownloader);
        ASSERT_TRUE(corpusResult.successful);
        EXPECT_TRUE(corpusResult.provisioned);
        EXPECT_EQ(requestedUrls, (std::vector<std::string>{fixturePairs[1].symbolsUrl}));
        EXPECT_EQ(ReadFile(liveCorpusDirectory / fixturePairs[1].label / "ntdll.pdb"),
                  fixturePairs[1].pdb);
        EXPECT_EQ(ReadFile(bravoDllPath), dllBytes);
        EXPECT_EQ(fs::last_write_time(bravoDllPath), dllModifiedTime);
        EXPECT_EQ(Snapshot(liveCorpusDirectory / fixturePairs[0].label), alphaBefore);
        requestedUrls.clear();
        const auto snapshotAfter = Snapshot(testDirectory);
        EXPECT_TRUE(EnsureCorpus(pinnedManifestPath, liveCorpusDirectory, false, fixtureDownloader)
                        .successful);
        EXPECT_EQ(Snapshot(testDirectory), snapshotAfter);
        EXPECT_TRUE(requestedUrls.empty());
    }

    TEST_F(CorpusLifecycle, MissingPairsAreNotPublishedUntilEveryDownloadIsValidated)
    {
        Install(1);
        const auto existingFixtureSnapshot = Snapshot(liveCorpusDirectory / fixturePairs[0].label);
        const DownloadFn stagingDownloader = [&](std::string_view downloadUrl, bool networkAllowed)
        {
            for (size_t fixtureIndex = 1; fixtureIndex < fixturePairs.size(); ++fixtureIndex)
            {
                EXPECT_FALSE(fs::exists(liveCorpusDirectory / fixturePairs[fixtureIndex].label /
                                        "ntdll.dll"));
                EXPECT_FALSE(fs::exists(liveCorpusDirectory / fixturePairs[fixtureIndex].label /
                                        "ntdll.pdb"));
            }
            EXPECT_EQ(Snapshot(liveCorpusDirectory / fixturePairs[0].label),
                      existingFixtureSnapshot);
            return fixtureDownloader(downloadUrl, networkAllowed);
        };
        const auto corpusResult =
            EnsureCorpus(pinnedManifestPath, liveCorpusDirectory, true, stagingDownloader);
        ASSERT_TRUE(corpusResult.successful);
        EXPECT_TRUE(corpusResult.provisioned);
        EXPECT_EQ(requestedUrls.size(), 4);
        EXPECT_EQ(Snapshot(liveCorpusDirectory / fixturePairs[0].label), existingFixtureSnapshot);
        for (size_t fixtureIndex = 1; fixtureIndex < fixturePairs.size(); ++fixtureIndex)
        {
            EXPECT_EQ(
                ReadFile(liveCorpusDirectory / fixturePairs[fixtureIndex].label / "ntdll.dll"),
                fixturePairs[fixtureIndex].dll);
            EXPECT_EQ(
                ReadFile(liveCorpusDirectory / fixturePairs[fixtureIndex].label / "ntdll.pdb"),
                fixturePairs[fixtureIndex].pdb);
        }
    }

    TEST_F(CorpusLifecycle,
           NetworkHashAndPdbIdentityFailuresKeepWorkingCorpusAndPreventPartialPublication)
    {
        Install(1);
        for (const std::string_view failureKind : {"network", "dll-hash", "pdb-identity"})
        {
            SCOPED_TRACE(failureKind);
            auto manifestJson = Pins();
            auto invalidPdbBytes = fixturePairs[2].pdb;
            invalidPdbBytes[512 * 5 + 12] ^= 1;
            if (failureKind == "pdb-identity")
            {
                manifestJson.at("fixtures").at(2)["pdb_sha256"] = Sha256(invalidPdbBytes);
            }
            WriteJson(pinnedManifestPath, manifestJson);
            requestedUrls.clear();
            const auto snapshotBefore = Snapshot(liveCorpusDirectory);
            const DownloadFn failingDownloader =
                [&](std::string_view downloadUrl, bool networkAllowed)
            {
                if (downloadUrl == fixturePairs[2].symbolsUrl && failureKind == "network")
                {
                    requestedUrls.emplace_back(downloadUrl);
                    throw std::runtime_error("Synthetic network interruption");
                }
                auto downloadedBytes = fixtureDownloader(downloadUrl, networkAllowed);
                if (downloadUrl == fixturePairs[2].imageUrl && failureKind == "dll-hash")
                {
                    downloadedBytes.back() ^= 1;
                }
                if (downloadUrl == fixturePairs[2].symbolsUrl && failureKind == "pdb-identity")
                {
                    return invalidPdbBytes;
                }
                return downloadedBytes;
            };
            const auto corpusResult =
                EnsureCorpus(pinnedManifestPath, liveCorpusDirectory, true, failingDownloader);
            EXPECT_FALSE(corpusResult.successful);
            EXPECT_EQ(Snapshot(liveCorpusDirectory), snapshotBefore);
            ExpectReport(corpusResult);
            EXPECT_TRUE(HasStagedPairFile(corpusResult, fixturePairs[1].label, "ntdll.dll"));
            EXPECT_TRUE(HasStagedPairFile(corpusResult, fixturePairs[1].label, "ntdll.pdb"));
            EXPECT_EQ(
                std::count(requestedUrls.begin(), requestedUrls.end(), fixturePairs[0].imageUrl),
                0);
            EXPECT_EQ(
                std::count(requestedUrls.begin(), requestedUrls.end(), fixturePairs[0].symbolsUrl),
                0);
        }
    }

    TEST_F(CorpusLifecycle, InvalidExistingPinnedFilesFailBeforeNetworkOrAnyStagingChanges)
    {
        Install(fixturePairs.size());
        for (const std::string_view fixtureFilename : {"ntdll.dll", "ntdll.pdb"})
        {
            SCOPED_TRACE(fixtureFilename);
            const auto path = liveCorpusDirectory / fixturePairs[0].label / fixtureFilename;
            const auto originalFileBytes = ReadFile(path);
            auto corruptedFileBytes = originalFileBytes;
            corruptedFileBytes.back() ^= 1;
            (void)AtomicWrite(path, corruptedFileBytes);
            const auto snapshotBefore = Snapshot(testDirectory);
            EXPECT_THROW((void)EnsureCorpus(pinnedManifestPath, liveCorpusDirectory, true,
                                            fixtureDownloader),
                         FixtureError);
            EXPECT_TRUE(requestedUrls.empty());
            EXPECT_EQ(Snapshot(testDirectory), snapshotBefore);
            (void)AtomicWrite(path, originalFileBytes);
        }
    }

    TEST_F(CorpusLifecycle, EveryNetworkAuditUsesFreshIsolatedStorageAndLeavesLiveCacheUntouched)
    {
        Install(fixturePairs.size());
        const auto snapshotBefore = Snapshot(liveCorpusDirectory);
        const auto pinnedManifestBytes = ReadFile(pinnedManifestPath);
        const auto pinnedManifestModifiedTime = fs::last_write_time(pinnedManifestPath);
        fs::path previousRunDirectory;
        for (int runIndex = 0; runIndex < 2; ++runIndex)
        {
            requestedUrls.clear();
            const auto corpusResult =
                VerifyFreshCorpus(pinnedManifestPath, networkChecksDirectory, liveCorpusDirectory,
                                  true, fixtureDownloader);
            ASSERT_TRUE(corpusResult.successful);
            EXPECT_NE(corpusResult.stagingRoot, previousRunDirectory);
            EXPECT_EQ((std::multiset<std::string>(requestedUrls.begin(), requestedUrls.end())),
                      AllUrls());
            EXPECT_EQ(Snapshot(liveCorpusDirectory), snapshotBefore);
            EXPECT_EQ(ReadFile(pinnedManifestPath), pinnedManifestBytes);
            EXPECT_EQ(fs::last_write_time(pinnedManifestPath), pinnedManifestModifiedTime);
            ExpectReport(corpusResult);
            previousRunDirectory = corpusResult.stagingRoot;
        }
    }

    TEST_F(CorpusLifecycle, FailedNetworkAuditCannotFallBackToValidCachedBytes)
    {
        Install(fixturePairs.size());
        const auto snapshotBefore = Snapshot(liveCorpusDirectory);
        downloadResponses.at(fixturePairs[0].imageUrl).back() ^= 1;
        const auto corpusResult = VerifyFreshCorpus(pinnedManifestPath, networkChecksDirectory,
                                                    liveCorpusDirectory, true, fixtureDownloader);
        EXPECT_FALSE(corpusResult.successful);
        EXPECT_FALSE(requestedUrls.empty());
        EXPECT_EQ(Snapshot(liveCorpusDirectory), snapshotBefore);
        ExpectReport(corpusResult);
    }

    TEST_F(CorpusLifecycle, MissingOfflineCorpusAndOfflineAuditFailWithoutWritesOrTransportCalls)
    {
        Install(1);
        auto snapshotBefore = Snapshot(testDirectory);
        EXPECT_THROW(
            (void)EnsureCorpus(pinnedManifestPath, liveCorpusDirectory, false, fixtureDownloader),
            NetworkDisabled);
        EXPECT_TRUE(requestedUrls.empty());
        EXPECT_EQ(Snapshot(testDirectory), snapshotBefore);
        snapshotBefore = Snapshot(testDirectory);
        EXPECT_THROW((void)VerifyFreshCorpus(pinnedManifestPath, networkChecksDirectory,
                                             liveCorpusDirectory, false, fixtureDownloader),
                     NetworkDisabled);
        EXPECT_TRUE(requestedUrls.empty());
        EXPECT_EQ(Snapshot(testDirectory), snapshotBefore);
    }

    TEST_F(CorpusLifecycle, FreshAuditRejectsRelatedLiveAndCheckPathsBeforeWrites)
    {
        Install(fixturePairs.size());
        std::vector<fs::path> unsafeOutputPaths{liveCorpusDirectory, testDirectory,
                                                liveCorpusDirectory / "audit",
                                                liveCorpusDirectory / "child" / ".."};
#ifdef _WIN32
        unsafeOutputPaths.push_back(testDirectory / "CaChE");
#endif
        for (const auto& outputDirectory : unsafeOutputPaths)
        {
            SCOPED_TRACE(outputDirectory.string());
            const auto snapshotBefore = Snapshot(testDirectory);
            EXPECT_THROW((void)VerifyFreshCorpus(pinnedManifestPath, outputDirectory,
                                                 liveCorpusDirectory, true, fixtureDownloader),
                         FixtureError);
            EXPECT_TRUE(requestedUrls.empty());
            EXPECT_EQ(Snapshot(testDirectory), snapshotBefore);
        }
    }

    TEST_F(CorpusLifecycle, CorpusOutputRejectsRootRegularFileAndInputManifestOverlap)
    {
        const auto plainFilePath = testDirectory / "plain-file";
        (void)AtomicWrite(plainFilePath, Bytes{'x'});
        for (const auto& outputDirectory :
             {plainFilePath, testDirectory, testDirectory / "child" / ".."})
        {
            SCOPED_TRACE(outputDirectory.string());
            const auto snapshotBefore = Snapshot(testDirectory);
            EXPECT_THROW(
                (void)EnsureCorpus(pinnedManifestPath, outputDirectory, true, fixtureDownloader),
                FixtureError);
            EXPECT_TRUE(requestedUrls.empty());
            EXPECT_EQ(Snapshot(testDirectory), snapshotBefore);
        }
        // Offline mode prevents touching a system root even if its dedicated
        // path guard regresses; NetworkDisabled is not accepted as that guard.
        try
        {
            (void)EnsureCorpus(pinnedManifestPath, testDirectory.root_path(), false,
                               fixtureDownloader);
            ADD_FAILURE() << "Filesystem-root output was accepted";
        }
        catch (const NetworkDisabled&)
        {
            ADD_FAILURE() << "Filesystem-root guard ran after missing-file handling";
        }
        catch (const FixtureError&)
        {
        }
        EXPECT_TRUE(requestedUrls.empty());
    }

    TEST_F(CorpusLifecycle, RequiredRemotePinsCannotBeOmittedOrDowngradedToAllowMissing)
    {
        Install(fixturePairs.size());
        for (const std::string_view missingPin :
             {"dll-sha256", "pdb-sha256", "pe", "pdb-identity", "invalid-hash", "empty-manifest"})
        {
            SCOPED_TRACE(missingPin);
            auto manifestDocument = Pins();
            auto& manifestEntry = manifestDocument.at("fixtures").at(1);
            if (missingPin == "dll-sha256")
            {
                manifestEntry.at("pe").erase("sha256");
            }
            else if (missingPin == "pdb-sha256")
            {
                manifestEntry.erase("pdb_sha256");
            }
            else if (missingPin == "pe")
            {
                manifestEntry.erase("pe");
            }
            else if (missingPin == "pdb-identity")
            {
                manifestEntry.at("pe").erase("pdb");
            }
            else if (missingPin == "invalid-hash")
            {
                manifestEntry["pdb_sha256"] = std::string(64, 'x');
            }
            else
            {
                manifestDocument["fixtures"] = Json::array();
            }
            WriteJson(pinnedManifestPath, manifestDocument);
            const auto snapshotBefore = Snapshot(testDirectory);
            EXPECT_THROW((void)EnsureCorpus(pinnedManifestPath, liveCorpusDirectory, true,
                                            fixtureDownloader),
                         FixtureError);
            EXPECT_THROW((void)VerifyFreshCorpus(pinnedManifestPath, networkChecksDirectory,
                                                 liveCorpusDirectory, true, fixtureDownloader),
                         FixtureError);
            EXPECT_TRUE(requestedUrls.empty());
            EXPECT_EQ(Snapshot(testDirectory), snapshotBefore);
        }
    }
} // namespace
