#include "fixture_bytes.h"
#include "pdb_stuff/corpus.h"

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
    using namespace pdb_stuff;
    using namespace symfind::test_fixtures;
    namespace fs = std::filesystem;

    struct FileStamp
    {
            bool directory = false;
            fs::file_time_type modified;
            Bytes bytes;
            bool operator==(const FileStamp&) const = default;
    };

    using TreeSnapshot = std::map<std::string, FileStamp>;

    TreeSnapshot snapshot(const fs::path& directory)
    {
        TreeSnapshot result;
        if (!fs::exists(directory))
            return result;
        const auto record = [&](const fs::path& path)
        {
            const bool is_directory = fs::is_directory(path);
            result.emplace(path.lexically_relative(directory).generic_string(),
                           FileStamp{is_directory, fs::last_write_time(path), is_directory ? Bytes{} : read_file(path)});
        };
        record(directory);
        for (const auto& entry : fs::recursive_directory_iterator(directory))
            record(entry.path());
        return result;
    }

    bool is_within(const fs::path& path, const fs::path& directory)
    {
        const auto absolute_path = fs::weakly_canonical(path);
        const auto absolute_directory = fs::weakly_canonical(directory);
        auto candidate = absolute_path.begin();
        for (auto expected = absolute_directory.begin(); expected != absolute_directory.end(); ++expected, ++candidate)
            if (candidate == absolute_path.end() || *candidate != *expected)
                return false;
        return true;
    }

    bool has_staged_pair_file(const CorpusResult& result, std::string_view label, std::string_view filename)
    {
        if (!fs::is_directory(result.staging_root))
            return false;
        for (const auto& entry : fs::recursive_directory_iterator(result.staging_root))
            if (entry.is_regular_file() && entry.path().filename() == filename && entry.path().parent_path().filename() == label)
                return true;
        return false;
    }

    struct PairFixture
    {
            std::string label;
            Bytes dll;
            Bytes pdb;
            Json pin;
            std::string image_url;
            std::string symbols_url;
    };

    PairFixture pair_fixture(std::string label, uint8_t identity)
    {
        PairFixture pair;
        pair.label = std::move(label);
        pair.dll = make_pe();
        auto signature = guid_bytes;
        signature.back() ^= identity;
        std::copy(signature.begin(), signature.end(), pair.dll.begin() + 0x244);
        put(pair.dll, 0x88, 0x4ce7c8f9u + identity, 4);
        pair.pdb = make_pdb(2, 2, signature);
        const auto image = parse_pe(pair.dll);
        pair.pin = Json{{"label", pair.label}, {"pe", image}, {"pdb_sha256", sha256(pair.pdb)}};
        pair.image_url = dll_url(image);
        pair.symbols_url = pdb_url(image.at("pdb"));
        return pair;
    }

    class CorpusLifecycle : public testing::Test
    {
        protected:
            fs::path root;
            fs::path manifest;
            fs::path live;
            fs::path checks;
            std::vector<PairFixture> pairs;
            std::map<std::string, Bytes> remote;
            std::vector<std::string> requests;
            DownloadFn transport = [this](std::string_view url, bool allowed)
            {
                EXPECT_TRUE(allowed);
                requests.emplace_back(url);
                const auto found = remote.find(std::string(url));
                if (found == remote.end())
                    throw std::runtime_error("Unexpected offline test transport URL");
                return found->second;
            };

            void SetUp() override
            {
                static std::atomic<uint64_t> sequence{0};
                const auto tick = std::chrono::steady_clock::now().time_since_epoch().count();
                root = fs::weakly_canonical(fs::temp_directory_path()) /
                       ("symfind-corpus-lifecycle-" + std::to_string(tick) + "-" + std::to_string(sequence.fetch_add(1)));
                if (!fs::create_directory(root))
                    throw std::runtime_error("Lifecycle test directory already exists");
                manifest = root / "pinned.json";
                live = root / "cache";
                checks = root / "checks";
                pairs = {pair_fixture("alpha", 1), pair_fixture("bravo", 2), pair_fixture("charlie", 3)};
                for (const auto& pair : pairs)
                {
                    remote[pair.image_url] = pair.dll;
                    remote[pair.symbols_url] = pair.pdb;
                }
                write_json(manifest, pins());
            }

            void TearDown() override
            {
                // Verify the recursive cleanup target is the uniquely created test
                // directory directly under the system temporary directory.
                if (root.parent_path() != fs::weakly_canonical(fs::temp_directory_path()) ||
                    !root.filename().string().starts_with("symfind-corpus-lifecycle-"))
                {
                    ADD_FAILURE() << "Refusing cleanup outside the lifecycle test directory";
                    return;
                }
                std::error_code error;
                fs::remove_all(root, error);
                EXPECT_FALSE(error) << error.message();
            }

            Json pins() const
            {
                Json fixtures = Json::array();
                for (const auto& pair : pairs)
                    fixtures.push_back(pair.pin);
                return Json{{"schema_version", 1}, {"fixtures", fixtures}};
            }

            void install(size_t count)
            {
                Json fixtures = Json::array();
                for (size_t i = 0; i < count; ++i)
                {
                    const auto source_dll = root / "sources" / (pairs[i].label + ".dll");
                    const auto source_pdb = root / "sources" / (pairs[i].label + ".pdb");
                    (void)atomic_write(source_dll, pairs[i].dll);
                    (void)atomic_write(source_pdb, pairs[i].pdb);
                    const auto imported = process_fixture(pairs[i].pin, live, false, source_dll, source_pdb, transport);
                    ASSERT_EQ(imported.at("status"), "ready");
                    fixtures.push_back(imported);
                }
                write_json(live / "manifest.json", Json{{"schema_version", 1}, {"fixtures", fixtures}});
                ASSERT_TRUE(requests.empty());
            }

            std::multiset<std::string> all_urls() const
            {
                std::multiset<std::string> urls;
                for (const auto& pair : pairs)
                {
                    urls.insert(pair.image_url);
                    urls.insert(pair.symbols_url);
                }
                return urls;
            }

            void expect_report(const CorpusResult& result)
            {
                EXPECT_TRUE(fs::is_directory(result.staging_root));
                EXPECT_TRUE(fs::is_regular_file(result.report_manifest));
                EXPECT_TRUE(is_within(result.report_manifest, result.staging_root));
                EXPECT_FALSE(is_within(result.staging_root, live));
                EXPECT_FALSE(is_within(live, result.staging_root));
            }
    };

    TEST_F(CorpusLifecycle, ValidCacheMakesNoNetworkRequestsAndNoFilesystemChanges)
    {
        install(pairs.size());
        const auto before = snapshot(root);
        for (const bool network_allowed : {false, true})
        {
            const auto result = ensure_corpus(manifest, live, network_allowed, transport);
            EXPECT_TRUE(result.successful);
            EXPECT_FALSE(result.provisioned);
            EXPECT_TRUE(result.staging_root.empty());
            EXPECT_TRUE(requests.empty());
            EXPECT_EQ(snapshot(root), before);
        }
    }

    TEST_F(CorpusLifecycle, AbsentCorpusPublishesEveryPinnedPairThenReusesItWithoutChanges)
    {
        ASSERT_FALSE(fs::exists(live));
        const auto source_bytes = read_file(manifest);
        const auto source_time = fs::last_write_time(manifest);
        const DownloadFn staged = [&](std::string_view url, bool allowed)
        {
            EXPECT_FALSE(fs::exists(live));
            return transport(url, allowed);
        };
        const auto result = ensure_corpus(manifest, live, true, staged);
        ASSERT_TRUE(result.successful);
        EXPECT_TRUE(result.provisioned);
        EXPECT_EQ((std::multiset<std::string>(requests.begin(), requests.end())), all_urls());
        ASSERT_TRUE(fs::is_regular_file(live / "manifest.json"));
        EXPECT_EQ(read_json(live / "manifest.json").at("fixtures").size(), pairs.size());
        for (const auto& pair : pairs)
        {
            EXPECT_EQ(read_file(live / pair.label / "ntdll.dll"), pair.dll);
            EXPECT_EQ(read_file(live / pair.label / "ntdll.pdb"), pair.pdb);
            const auto metadata = read_json(live / pair.label / "manifest.json");
            EXPECT_EQ(metadata.at("status"), "ready");
            EXPECT_EQ(fs::path(metadata.at("dll").get<std::string>()), live / pair.label / "ntdll.dll");
            EXPECT_EQ(fs::path(metadata.at("pdb_file").get<std::string>()), live / pair.label / "ntdll.pdb");
        }
        EXPECT_EQ(read_file(manifest), source_bytes);
        EXPECT_EQ(fs::last_write_time(manifest), source_time);
        expect_report(result);
        requests.clear();
        const auto before = snapshot(root);
        const auto reused = ensure_corpus(manifest, live, false, transport);
        EXPECT_TRUE(reused.successful);
        EXPECT_FALSE(reused.provisioned);
        EXPECT_TRUE(requests.empty());
        EXPECT_EQ(snapshot(root), before);
    }

    TEST_F(CorpusLifecycle, ArchiveBootstrapPublishesPinnedArchiveAndLaterRepairReusesItWithoutNetwork)
    {
        const auto archive = make_archive(dll_member, pairs[0].dll);
        const auto archive_pin = archive_config(archive);
        const auto archive_url = archive_pin.at("url").get<std::string>();
        pairs[0].pin["dll_archive"] = archive_pin;
        remote[archive_url] = archive;
        remote.erase(pairs[0].image_url);
        write_json(manifest, pins());
        const auto prepared = ensure_corpus(manifest, live, true, transport);
        ASSERT_TRUE(prepared.successful) << prepared.reason << '\n'
                                         << prepared.fixtures.dump(2);
        const auto cached_archive = live.parent_path() / "archives" / (archive_pin.at("sha256").get<std::string>() + ".tar.gz");
        ASSERT_TRUE(fs::is_regular_file(cached_archive));
        EXPECT_EQ(read_file(cached_archive), archive);
        EXPECT_EQ(std::count(requests.begin(), requests.end(), archive_url), 1);
        EXPECT_EQ(std::count(requests.begin(), requests.end(), pairs[0].image_url), 0);
        const auto archive_time = fs::last_write_time(cached_archive);
        const auto unaffected = snapshot(live / pairs[1].label);
        const auto pdb_path = live / pairs[0].label / "ntdll.pdb";
        const auto pdb_bytes = read_file(pdb_path);
        const auto pdb_time = fs::last_write_time(pdb_path);
        ASSERT_TRUE(fs::remove(live / pairs[0].label / "ntdll.dll"));
        requests.clear();
        const DownloadFn no_network = [&](std::string_view url, bool) -> Bytes
        {
            requests.emplace_back(url);
            throw std::runtime_error("Pinned local archive repair must not contact the network");
        };
        const auto repaired = ensure_corpus(manifest, live, true, no_network);
        ASSERT_TRUE(repaired.successful);
        EXPECT_TRUE(repaired.provisioned);
        EXPECT_TRUE(requests.empty());
        EXPECT_EQ(read_file(live / pairs[0].label / "ntdll.dll"), pairs[0].dll);
        EXPECT_EQ(read_file(cached_archive), archive);
        EXPECT_EQ(fs::last_write_time(cached_archive), archive_time);
        EXPECT_EQ(read_file(pdb_path), pdb_bytes);
        EXPECT_EQ(fs::last_write_time(pdb_path), pdb_time);
        EXPECT_EQ(snapshot(live / pairs[1].label), unaffected);
    }

    TEST_F(CorpusLifecycle, LaterFixtureFailureDoesNotPublishEarlierValidatedArchiveOrAnyPairs)
    {
        const auto archive = make_archive(dll_member, pairs[0].dll);
        const auto archive_pin = archive_config(archive);
        const auto archive_url = archive_pin.at("url").get<std::string>();
        pairs[0].pin["dll_archive"] = archive_pin;
        remote[archive_url] = archive;
        remote.erase(pairs[0].image_url);
        write_json(manifest, pins());
        const DownloadFn failing = [&](std::string_view url, bool allowed)
        {
            if (url == pairs[2].symbols_url)
            {
                requests.emplace_back(url);
                throw std::runtime_error("Synthetic final PDB download failure");
            }
            return transport(url, allowed);
        };
        const auto result = ensure_corpus(manifest, live, true, failing);
        EXPECT_FALSE(result.successful);
        EXPECT_FALSE(fs::exists(live));
        const auto archive_name = archive_pin.at("sha256").get<std::string>() + ".tar.gz";
        EXPECT_FALSE(fs::exists(live.parent_path() / "archives" / archive_name));
        ASSERT_TRUE(fs::is_regular_file(result.staging_root / "archives" / archive_name))
            << result.reason << '\n'
            << result.fixtures.dump(2);
        EXPECT_EQ(read_file(result.staging_root / "archives" / archive_name), archive);
        EXPECT_TRUE(has_staged_pair_file(result, pairs[0].label, "ntdll.dll"));
        EXPECT_TRUE(has_staged_pair_file(result, pairs[0].label, "ntdll.pdb"));
        expect_report(result);
    }

    TEST_F(CorpusLifecycle, MissingPdbDownloadsOnlyThatFileAndPreservesExistingCacheFiles)
    {
        install(pairs.size());
        ASSERT_TRUE(fs::remove(live / pairs[1].label / "ntdll.pdb"));
        const auto alpha_before = snapshot(live / pairs[0].label);
        const auto bravo_dll = live / pairs[1].label / "ntdll.dll";
        const auto dll_bytes = read_file(bravo_dll);
        const auto dll_time = fs::last_write_time(bravo_dll);
        const DownloadFn staged = [&](std::string_view url, bool allowed)
        {
            EXPECT_FALSE(fs::exists(live / pairs[1].label / "ntdll.pdb"));
            EXPECT_EQ(read_file(bravo_dll), dll_bytes);
            return transport(url, allowed);
        };
        const auto result = ensure_corpus(manifest, live, true, staged);
        ASSERT_TRUE(result.successful);
        EXPECT_TRUE(result.provisioned);
        EXPECT_EQ(requests, (std::vector<std::string>{pairs[1].symbols_url}));
        EXPECT_EQ(read_file(live / pairs[1].label / "ntdll.pdb"), pairs[1].pdb);
        EXPECT_EQ(read_file(bravo_dll), dll_bytes);
        EXPECT_EQ(fs::last_write_time(bravo_dll), dll_time);
        EXPECT_EQ(snapshot(live / pairs[0].label), alpha_before);
        requests.clear();
        const auto after = snapshot(root);
        EXPECT_TRUE(ensure_corpus(manifest, live, false, transport).successful);
        EXPECT_EQ(snapshot(root), after);
        EXPECT_TRUE(requests.empty());
    }

    TEST_F(CorpusLifecycle, MissingPairsAreNotPublishedUntilEveryDownloadIsValidated)
    {
        install(1);
        const auto previous = snapshot(live / pairs[0].label);
        const DownloadFn staged = [&](std::string_view url, bool allowed)
        {
            for (size_t i = 1; i < pairs.size(); ++i)
            {
                EXPECT_FALSE(fs::exists(live / pairs[i].label / "ntdll.dll"));
                EXPECT_FALSE(fs::exists(live / pairs[i].label / "ntdll.pdb"));
            }
            EXPECT_EQ(snapshot(live / pairs[0].label), previous);
            return transport(url, allowed);
        };
        const auto result = ensure_corpus(manifest, live, true, staged);
        ASSERT_TRUE(result.successful);
        EXPECT_TRUE(result.provisioned);
        EXPECT_EQ(requests.size(), 4);
        EXPECT_EQ(snapshot(live / pairs[0].label), previous);
        for (size_t i = 1; i < pairs.size(); ++i)
        {
            EXPECT_EQ(read_file(live / pairs[i].label / "ntdll.dll"), pairs[i].dll);
            EXPECT_EQ(read_file(live / pairs[i].label / "ntdll.pdb"), pairs[i].pdb);
        }
    }

    TEST_F(CorpusLifecycle, NetworkHashAndPdbIdentityFailuresKeepWorkingCorpusAndPreventPartialPublication)
    {
        install(1);
        for (const std::string_view failure : {"network", "dll-hash", "pdb-identity"})
        {
            SCOPED_TRACE(failure);
            auto manifest_json = pins();
            auto bad_pdb = pairs[2].pdb;
            bad_pdb[512 * 5 + 12] ^= 1;
            if (failure == "pdb-identity")
                manifest_json.at("fixtures").at(2)["pdb_sha256"] = sha256(bad_pdb);
            write_json(manifest, manifest_json);
            requests.clear();
            const auto before = snapshot(live);
            const DownloadFn failing = [&](std::string_view url, bool allowed)
            {
                if (url == pairs[2].symbols_url && failure == "network")
                {
                    requests.emplace_back(url);
                    throw std::runtime_error("Synthetic network interruption");
                }
                auto bytes = transport(url, allowed);
                if (url == pairs[2].image_url && failure == "dll-hash")
                    bytes.back() ^= 1;
                if (url == pairs[2].symbols_url && failure == "pdb-identity")
                    return bad_pdb;
                return bytes;
            };
            const auto result = ensure_corpus(manifest, live, true, failing);
            EXPECT_FALSE(result.successful);
            EXPECT_EQ(snapshot(live), before);
            expect_report(result);
            EXPECT_TRUE(has_staged_pair_file(result, pairs[1].label, "ntdll.dll"));
            EXPECT_TRUE(has_staged_pair_file(result, pairs[1].label, "ntdll.pdb"));
            EXPECT_EQ(std::count(requests.begin(), requests.end(), pairs[0].image_url), 0);
            EXPECT_EQ(std::count(requests.begin(), requests.end(), pairs[0].symbols_url), 0);
        }
    }

    TEST_F(CorpusLifecycle, InvalidExistingPinnedFilesFailBeforeNetworkOrAnyStagingChanges)
    {
        install(pairs.size());
        for (const std::string_view filename : {"ntdll.dll", "ntdll.pdb"})
        {
            SCOPED_TRACE(filename);
            const auto path = live / pairs[0].label / filename;
            const auto original = read_file(path);
            auto corrupted = original;
            corrupted.back() ^= 1;
            (void)atomic_write(path, corrupted);
            const auto before = snapshot(root);
            EXPECT_THROW((void)ensure_corpus(manifest, live, true, transport), FixtureError);
            EXPECT_TRUE(requests.empty());
            EXPECT_EQ(snapshot(root), before);
            (void)atomic_write(path, original);
        }
    }

    TEST_F(CorpusLifecycle, EveryNetworkAuditUsesFreshIsolatedStorageAndLeavesLiveCacheUntouched)
    {
        install(pairs.size());
        const auto before = snapshot(live);
        const auto source_manifest = read_file(manifest);
        const auto source_time = fs::last_write_time(manifest);
        fs::path previous_run;
        for (int run = 0; run < 2; ++run)
        {
            requests.clear();
            const auto result = verify_fresh_corpus(manifest, checks, live, true, transport);
            ASSERT_TRUE(result.successful);
            EXPECT_NE(result.staging_root, previous_run);
            EXPECT_EQ((std::multiset<std::string>(requests.begin(), requests.end())), all_urls());
            EXPECT_EQ(snapshot(live), before);
            EXPECT_EQ(read_file(manifest), source_manifest);
            EXPECT_EQ(fs::last_write_time(manifest), source_time);
            expect_report(result);
            previous_run = result.staging_root;
        }
    }

    TEST_F(CorpusLifecycle, FailedNetworkAuditCannotFallBackToValidCachedBytes)
    {
        install(pairs.size());
        const auto before = snapshot(live);
        remote.at(pairs[0].image_url).back() ^= 1;
        const auto result = verify_fresh_corpus(manifest, checks, live, true, transport);
        EXPECT_FALSE(result.successful);
        EXPECT_FALSE(requests.empty());
        EXPECT_EQ(snapshot(live), before);
        expect_report(result);
    }

    TEST_F(CorpusLifecycle, MissingOfflineCorpusAndOfflineAuditFailWithoutWritesOrTransportCalls)
    {
        install(1);
        auto before = snapshot(root);
        EXPECT_THROW((void)ensure_corpus(manifest, live, false, transport), NetworkDisabled);
        EXPECT_TRUE(requests.empty());
        EXPECT_EQ(snapshot(root), before);
        before = snapshot(root);
        EXPECT_THROW((void)verify_fresh_corpus(manifest, checks, live, false, transport), NetworkDisabled);
        EXPECT_TRUE(requests.empty());
        EXPECT_EQ(snapshot(root), before);
    }

    TEST_F(CorpusLifecycle, FreshAuditRejectsRelatedLiveAndCheckPathsBeforeWrites)
    {
        install(pairs.size());
        std::vector<fs::path> unsafe{live, root, live / "audit", live / "child" / ".."};
#ifdef _WIN32
        unsafe.push_back(root / "CaChE");
#endif
        for (const auto& output : unsafe)
        {
            SCOPED_TRACE(output.string());
            const auto before = snapshot(root);
            EXPECT_THROW((void)verify_fresh_corpus(manifest, output, live, true, transport), FixtureError);
            EXPECT_TRUE(requests.empty());
            EXPECT_EQ(snapshot(root), before);
        }
    }

    TEST_F(CorpusLifecycle, CorpusOutputRejectsRootRegularFileAndInputManifestOverlap)
    {
        const auto plain_file = root / "plain-file";
        (void)atomic_write(plain_file, Bytes{'x'});
        for (const auto& output : {plain_file, root, root / "child" / ".."})
        {
            SCOPED_TRACE(output.string());
            const auto before = snapshot(root);
            EXPECT_THROW((void)ensure_corpus(manifest, output, true, transport), FixtureError);
            EXPECT_TRUE(requests.empty());
            EXPECT_EQ(snapshot(root), before);
        }
        // Offline mode prevents touching a system root even if its dedicated
        // path guard regresses; NetworkDisabled is not accepted as that guard.
        try
        {
            (void)ensure_corpus(manifest, root.root_path(), false, transport);
            ADD_FAILURE() << "Filesystem-root output was accepted";
        }
        catch (const NetworkDisabled&)
        {
            ADD_FAILURE() << "Filesystem-root guard ran after missing-file handling";
        }
        catch (const FixtureError&)
        {
        }
        EXPECT_TRUE(requests.empty());
    }

    TEST_F(CorpusLifecycle, RequiredRemotePinsCannotBeOmittedOrDowngradedToAllowMissing)
    {
        install(pairs.size());
        for (const std::string_view missing : {"dll-sha256", "pdb-sha256", "pe", "pdb-identity", "invalid-hash", "empty-manifest"})
        {
            SCOPED_TRACE(missing);
            auto input = pins();
            auto& entry = input.at("fixtures").at(1);
            if (missing == "dll-sha256")
                entry.at("pe").erase("sha256");
            else if (missing == "pdb-sha256")
                entry.erase("pdb_sha256");
            else if (missing == "pe")
                entry.erase("pe");
            else if (missing == "pdb-identity")
                entry.at("pe").erase("pdb");
            else if (missing == "invalid-hash")
                entry["pdb_sha256"] = std::string(64, 'x');
            else
                input["fixtures"] = Json::array();
            write_json(manifest, input);
            const auto before = snapshot(root);
            EXPECT_THROW((void)ensure_corpus(manifest, live, true, transport), FixtureError);
            EXPECT_THROW((void)verify_fresh_corpus(manifest, checks, live, true, transport), FixtureError);
            EXPECT_TRUE(requests.empty());
            EXPECT_EQ(snapshot(root), before);
        }
    }
} // namespace
