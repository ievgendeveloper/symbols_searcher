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
    using namespace pdb_stuff;
    namespace fs = std::filesystem;
    using namespace symfind::test_fixtures;

    void write_bytes(const fs::path& path, const Bytes& bytes)
    {
        fs::create_directories(path.parent_path());
        std::ofstream stream(path, std::ios::binary | std::ios::trunc);
        stream.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        if (!stream)
            throw std::runtime_error("Cannot write native test fixture");
    }

    class FetchNtdll : public testing::Test
    {
        protected:
            fs::path root;
            int network_calls = 0;
            DownloadFn no_network = [this](std::string_view, bool) -> Bytes
            {
                ++network_calls;
                throw std::runtime_error("Offline regression test unexpectedly invoked the downloader");
            };

            void SetUp() override
            {
                static std::atomic<uint64_t> sequence{0};
                const auto tick = std::chrono::steady_clock::now().time_since_epoch().count();
                root = fs::temp_directory_path() / ("symfind-fetch-test-" + std::to_string(tick) +
                                                    "-" + std::to_string(sequence.fetch_add(1)));
                if (!fs::create_directory(root))
                    throw std::runtime_error("Native test directory already exists");
            }

            void TearDown() override
            {
                EXPECT_EQ(network_calls, 0);
                std::error_code error;
                fs::remove_all(root, error);
            }

            void cache_archive(const fs::path& output, const Bytes& data, const Json& config)
            {
                write_bytes(output.parent_path() / "archives" / (config.at("sha256").get<std::string>() + ".tar.gz"), data);
            }

            FetchOptions options(std::string_view label = "local")
            {
                FetchOptions result;
                result.manifest_path = root / "empty.json";
                result.output_root = root / "out";
                result.labels = {std::string(label)};
                result.download = no_network;
                write_json(result.manifest_path, Json{{"schema_version", 1}, {"fixtures", Json::array()}});
                return result;
            }

            Json import_local(const Json& entry = Json{{"label", "local"}})
            {
                write_bytes(root / "source.dll", make_pe());
                write_bytes(root / "source.pdb", make_pdb());
                return process_fixture(entry, root / "out", false, root / "source.dll", root / "source.pdb", no_network);
            }
    };

    TEST_F(FetchNtdll, Sha256MatchesIndependentKnownVectors)
    {
        EXPECT_EQ(sha256(Bytes{}), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        EXPECT_EQ(sha256(Bytes{'a', 'b', 'c'}), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    TEST_F(FetchNtdll, PeRsdsGuidByteOrderAndBasename)
    {
        const auto identity = parse_pe(make_pe());
        EXPECT_EQ(identity.at("timestamp"), 0x4ce7c8f9);
        EXPECT_EQ(identity.at("pdb"), (Json{{"name", "ntdll.pdb"}, {"guid", guid}, {"age", 2}}));
        EXPECT_EQ(dll_url(identity), std::string(symbol_server) + "/ntdll.dll/4CE7C8F92000/ntdll.dll");
        EXPECT_EQ(pdb_url(identity.at("pdb")), std::string(symbol_server) +
                                                   "/ntdll.pdb/6192BFDB9F04442995FFCB0BE95172E12/ntdll.pdb");
    }

    TEST_F(FetchNtdll, CorruptPeDebugDirectoryIsRejected)
    {
        auto data = make_pe();
        put(data, 0x200 + 24, 0xffffff00, 4);
        EXPECT_THROW((void)parse_pe(data), FixtureError);
    }

    TEST_F(FetchNtdll, X86DllIsRejected)
    {
        auto data = make_pe();
        put(data, 0x84, 0x14c, 2);
        EXPECT_THROW((void)parse_pe(data), FixtureError);
    }

    TEST_F(FetchNtdll, PdbNoncontiguousInfoStream)
    {
        const auto identity = parse_pdb_identity(make_pdb());
        EXPECT_EQ(identity.at("guid").get<std::string>(), std::string(guid));
        EXPECT_EQ(identity.at("age"), 2);
    }

    TEST_F(FetchNtdll, WrongPdbGuidAndAgeAreRejected)
    {
        const auto identity = parse_pe(make_pe()).at("pdb");
        EXPECT_THROW((void)validate_pdb(make_pdb(3, 3), identity), FixtureError);
        std::array<uint8_t, 16> wrong{};
        wrong.back() = 1;
        EXPECT_THROW((void)validate_pdb(make_pdb(2, 2, wrong), identity), FixtureError);
    }

    TEST_F(FetchNtdll, PublishedPdbInfoAgeCanIncreaseOnlyWithMatchingDbiAge)
    {
        const auto identity = parse_pe(make_pe()).at("pdb");
        const auto result = validate_pdb(make_pdb(4, 2), identity);
        EXPECT_EQ(result.at("age"), 4);
        EXPECT_EQ(result.at("dbi_age"), 2);
        EXPECT_THROW((void)validate_pdb(make_pdb(1, 2), identity), FixtureError);
        EXPECT_THROW((void)validate_pdb(make_pdb(4, 3), identity), FixtureError);
    }

    TEST_F(FetchNtdll, TruncatedAndInvalidPdbBlocksAreRejected)
    {
        auto data = make_pdb();
        data.pop_back();
        EXPECT_THROW((void)parse_pdb_identity(data), FixtureError);
        data = make_pdb();
        put(data, 512 * 4 + 20, 99, 4);
        EXPECT_THROW((void)parse_pdb_identity(data), FixtureError);
    }

    TEST_F(FetchNtdll, DllAndPdbHashesAreChecked)
    {
        EXPECT_THROW((void)validate_pe(make_pe(), Json{{"sha256", std::string(64, '0')}}), FixtureError);
        EXPECT_THROW((void)validate_pdb(make_pdb(), parse_pe(make_pe()).at("pdb"), std::string(64, '0')), FixtureError);
    }

    TEST_F(FetchNtdll, NetworkOptInIsEnforcedBeforeDownloader)
    {
        EXPECT_THROW((void)download(std::string(symbol_server) + "/ntdll.dll/id/ntdll.dll", false), NetworkDisabled);
        EXPECT_THROW((void)ensure_file(root / "missing.pdb", "unused", [](auto)
                                       { return Json{}; }, false, no_network),
                     NetworkDisabled);
    }

    TEST_F(FetchNtdll, InvalidDownloadNeverReplacesExistingFile)
    {
        const auto path = root / "ntdll.pdb";
        const Bytes original{'e', 'x', 'i', 's', 't', 'i', 'n', 'g'};
        write_bytes(path, original);
        const auto identity = parse_pe(make_pe()).at("pdb");
        int attempted_downloads = 0;
        const DownloadFn invalid = [&](std::string_view, bool)
        {
            ++attempted_downloads;
            return make_pdb(3, 3);
        };
        EXPECT_THROW((void)ensure_file(path, "unused", [&](auto bytes)
                                       { return validate_pdb(bytes, identity); }, true, invalid),
                     FixtureError);
        EXPECT_EQ(attempted_downloads, 1);
        EXPECT_EQ(read_file(path), original);
        for (const auto& entry : fs::directory_iterator(root))
            EXPECT_NE(entry.path().extension(), ".part");
    }

    TEST_F(FetchNtdll, LocalImportIsFullyOfflineAndCanBeRevalidated)
    {
        const auto result = import_local(Json{{"label", "local"}, {"provenance", {{"kind", "local_import"}}}});
        ASSERT_EQ(result.at("status"), "ready");
        const auto again = process_fixture(Json{{"label", "local"}, {"pe", result.at("pe")}},
                                           root / "out", false, {}, {}, no_network);
        EXPECT_EQ(again.at("status"), "ready");
    }

    TEST_F(FetchNtdll, LocalImportWithoutManifestAndCachedLabelVerification)
    {
        auto config = options();
        config.manifest_path = root / "nonexistent.json";
        config.source_dll = root / "source.dll";
        config.source_pdb = root / "source.pdb";
        write_bytes(*config.source_dll, make_pe());
        write_bytes(*config.source_pdb, make_pdb());
        EXPECT_TRUE(process_manifest(config).successful);
        config.source_dll.reset();
        config.source_pdb.reset();
        config.manifest_path = root / "empty.json";
        EXPECT_TRUE(process_manifest(config).successful);
    }

    TEST_F(FetchNtdll, InvalidImportIsNotHiddenByAllowMissing)
    {
        auto config = options();
        config.source_dll = root / "source.dll";
        config.source_pdb = root / "source.pdb";
        config.allow_missing = true;
        write_bytes(*config.source_dll, make_pe());
        write_bytes(*config.source_pdb, make_pdb(3, 3));
        EXPECT_FALSE(process_manifest(config).successful);
        EXPECT_EQ(read_json(root / "out/local/manifest.json").at("status"), "invalid");
        EXPECT_FALSE(fs::exists(root / "out/local/ntdll.pdb"));
    }

    TEST_F(FetchNtdll, FailedValidationKeepsLastKnownPdbHashForLaterImports)
    {
        const auto ready = import_local();
        ASSERT_EQ(ready.at("status"), "ready");
        const auto original_hash = ready.at("pdb").at("sha256");
        auto changed = make_pdb();
        changed.back() ^= 1; // Identity stays valid while the full-file pin changes.
        write_bytes(root / "out/local/ntdll.pdb", changed);
        for (int retry = 0; retry < 2; ++retry)
        {
            const auto failed = process_fixture(Json{{"label", "local"}}, root / "out", false,
                                                root / "source.dll", {}, no_network);
            EXPECT_EQ(failed.at("status"), "invalid");
            EXPECT_EQ(failed.at("expected_pdb_sha256"), original_hash);
        }
        const auto repaired = process_fixture(Json{{"label", "local"}}, root / "out", false,
                                              root / "source.dll", root / "source.pdb", no_network);
        EXPECT_EQ(repaired.at("status"), "ready");
        EXPECT_EQ(repaired.at("pdb").at("sha256"), original_hash);
    }

    TEST_F(FetchNtdll, FailedDllValidationKeepsPinForCachedRevalidation)
    {
        const auto ready = import_local();
        ASSERT_EQ(ready.at("status"), "ready");
        write_bytes(root / "out/local/ntdll.dll", Bytes{'b', 'a', 'd'});
        const auto failed = process_fixture(Json{{"label", "local"}, {"pe", ready.at("pe")}},
                                            root / "out", false, {}, {}, no_network);
        EXPECT_EQ(failed.at("status"), "invalid");
        EXPECT_EQ(failed.at("expected_pdb_sha256"), ready.at("pdb").at("sha256"));
        write_bytes(root / "out/local/ntdll.dll", make_pe());
        EXPECT_TRUE(process_manifest(options()).successful);
    }

    TEST_F(FetchNtdll, PinnedArchiveImportAndCachedRepairAreOffline)
    {
        const auto output = root / "out";
        const auto data = make_archive();
        const auto archive = archive_config(data);
        cache_archive(output, data, archive);
        write_bytes(output / "nano/ntdll.pdb", make_pdb());
        const Json entry{{"label", "nano"}, {"pe", parse_pe(make_pe())}, {"dll_archive", archive}, {"pdb_sha256", sha256(make_pdb())}};
        const auto result = process_fixture(entry, output, false, {}, {}, no_network);
        ASSERT_EQ(result.at("status"), "ready");
        EXPECT_EQ(read_file(output / "nano/ntdll.dll"), make_pe());
        EXPECT_EQ(result.at("dll_url"), archive.at("url"));
        write_bytes(output / "nano/ntdll.dll", Bytes{'b', 'a', 'd'});
        EXPECT_TRUE(process_manifest(options("nano")).successful);
        EXPECT_EQ(read_file(output / "nano/ntdll.dll"), make_pe());
    }

    TEST_F(FetchNtdll, ValidCachedDllDoesNotNeedArchiveOrNetwork)
    {
        const auto output = root / "out";
        write_bytes(output / "nano/ntdll.dll", make_pe());
        const auto result = ensure_image_file(output / "nano/ntdll.dll", parse_pe(make_pe()),
                                              archive_config(make_archive()), output, false, no_network);
        EXPECT_EQ(result.at("sha256"), sha256(make_pe()));
        EXPECT_FALSE(fs::exists(root / "archives"));
    }

    TEST_F(FetchNtdll, WrongArchiveHashOrSizeNeverCreatesDll)
    {
        const auto output = root / "out";
        const auto data = make_archive();
        for (bool wrong_hash : {true, false})
        {
            auto config = archive_config(data);
            if (wrong_hash)
            {
                config["sha256"] = std::string(64, '0');
                config["url"] = "https://mcr.microsoft.com/v2/windows/nanoserver/blobs/sha256:" + std::string(64, '0');
            }
            else
                config["file_size"] = 1;
            cache_archive(output, data, config);
            EXPECT_THROW((void)ensure_image_file(output / "nano/ntdll.dll", parse_pe(make_pe()), config,
                                                 output, false, no_network),
                         FixtureError);
            EXPECT_FALSE(fs::exists(output / "nano/ntdll.dll"));
        }
    }

    TEST_F(FetchNtdll, ArchiveMemberPathsAndNonMicrosoftSourcesAreRejected)
    {
        const auto config = archive_config(make_archive());
        for (const std::string name : {"../ntdll.dll", "/ntdll.dll", "Files/../ntdll.dll", "Files\\ntdll.dll", "C:ntdll.dll"})
        {
            SCOPED_TRACE(name);
            auto unsafe = config;
            unsafe["member"] = name;
            EXPECT_THROW((void)validate_archive_config(unsafe), FixtureError);
        }
        const auto url = config.at("url").get<std::string>();
        auto other = url;
        other.replace(other.find("nanoserver"), 10, "servercore");
        for (const auto& invalid : {url + "/extra", other, std::string("https://example.com/archive.tar.gz")})
        {
            EXPECT_FALSE(is_supported_download_url(invalid));
        }
    }

    TEST_F(FetchNtdll, MissingOrLinkedArchiveMemberIsRejected)
    {
        const auto output = root / "out";
        for (const auto& data : {make_archive("other/ntdll.dll"), make_archive(dll_member, {}, '2')})
        {
            const auto config = archive_config(data);
            cache_archive(output, data, config);
            EXPECT_THROW((void)ensure_image_file(output / "nano/ntdll.dll", parse_pe(make_pe()), config,
                                                 output, false, no_network),
                         FixtureError);
        }
        EXPECT_FALSE(fs::exists(output / "nano/ntdll.dll"));
    }

    TEST_F(FetchNtdll, ArchivePayloadIsBoundedAndPePinIsStrict)
    {
        const auto output = root / "out";
        const auto data = make_archive();
        const auto config = archive_config(data);
        cache_archive(output, data, config);
        const auto path = output.parent_path() / "archives" / (config.at("sha256").get<std::string>() + ".tar.gz");
        EXPECT_THROW((void)read_archive_member(path, dll_member, 512), FixtureError);
        EXPECT_THROW((void)ensure_image_file(output / "nano/ntdll.dll", Json{{"sha256", std::string(64, '0')}},
                                             config, output, false, no_network),
                     FixtureError);
        EXPECT_FALSE(fs::exists(output / "nano/ntdll.dll"));
    }

    TEST_F(FetchNtdll, MissingArchiveDoesNotStartNetworkWithoutOptIn)
    {
        const auto output = root / "out";
        EXPECT_THROW((void)ensure_image_file(output / "nano/ntdll.dll", parse_pe(make_pe()),
                                             archive_config(make_archive()), output, false, no_network),
                     NetworkDisabled);
    }

    TEST_F(FetchNtdll, CorruptTarAndIncompleteOrTrailingGzipAreRejected)
    {
        auto tar = make_tar();
        tar[0] ^= 1; // Keep gzip CRC valid, but invalidate only the tar header checksum.
        const auto path = root / "corrupted.tar.gz";
        write_bytes(path, gzip_bytes(tar));
        EXPECT_THROW((void)read_archive_member(path, dll_member), FixtureError);
        auto truncated = make_archive();
        truncated.resize(truncated.size() - 5);
        write_bytes(path, truncated);
        EXPECT_THROW((void)read_archive_member(path, dll_member), FixtureError);
        auto corrupt_crc = make_archive();
        corrupt_crc[corrupt_crc.size() - 8] ^= 1;
        write_bytes(path, corrupt_crc);
        EXPECT_THROW((void)read_archive_member(path, dll_member), FixtureError);
        auto trailing = make_archive();
        trailing.push_back(0);
        write_bytes(path, trailing);
        EXPECT_THROW((void)read_archive_member(path, dll_member), FixtureError);
        auto concatenated = make_archive();
        const auto second = make_archive();
        concatenated.insert(concatenated.end(), second.begin(), second.end());
        write_bytes(path, concatenated);
        EXPECT_THROW((void)read_archive_member(path, dll_member), FixtureError);
    }

    TEST_F(FetchNtdll, ArchiveScanLimitAlsoBoundsSkippedPayload)
    {
        const auto path = root / "skipped.tar.gz";
        write_bytes(path, make_archive("other/ntdll.dll", Bytes(4096)));
        EXPECT_THROW((void)read_archive_member(path, dll_member, max_dll_bytes, 1024), FixtureError);
    }

    TEST_F(FetchNtdll, WinbindexPinKeepsExplicitClientProvenance)
    {
        Json manifest{{"fixtures", Json::array({Json{{"label", "server-candidate"},
                                                     {"provenance", {{"os_coverage", false}, {"proven_os", "Windows 10 1607"}}},
                                                     {"winbindex_selector", {{"windows_version", "1607"}, {"version_prefix", "10.0.14393."}}}}})}};
        const Json metadata{{std::string(64, 'a'), {{"fileInfo", {{"machineType", 34404}, {"virtualSize", 0x2000}, {"size", 1000}, {"timestamp", 10}, {"version", "10.0.14393.0 (build)"}}}, {"windowsVersions", {{"1607", {{"BASE", {{"sourcePaths", Json::array({"Windows\\System32\\ntdll.dll"})}}}}}}}}}};
        refresh_client_pins(manifest, gzip_json(metadata));
        const auto& entry = manifest.at("fixtures").at(0);
        EXPECT_EQ(entry.at("pe").at("version"), "10.0.14393.0");
        EXPECT_EQ(entry.at("provenance").at("os_coverage"), false);
        EXPECT_EQ(entry.at("provenance").at("proven_os"), "Windows 10 1607");
    }
} // namespace
