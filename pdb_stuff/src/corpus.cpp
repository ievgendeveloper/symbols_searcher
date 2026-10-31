#include "pdb_stuff/corpus.h"
#include "pdb_stuff/io.h"
#include "symfind/compat.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <iomanip>
#include <limits>
#include <map>
#include <regex>
#include <set>
#include <sstream>
#include <system_error>

namespace pdbStuff
{
    namespace
    {
        namespace fs = std::filesystem;

        std::string PathText(const fs::path& path)
        {
            return path.u8string();
        }

        fs::path Normalized(const fs::path& path)
        {
            if (path.empty())
            {
                throw FixtureError("corpus paths must not be empty");
            }
            return fs::weakly_canonical(fs::absolute(path));
        }

        bool SameComponent(const fs::path& a, const fs::path& b)
        {
            const auto& left = a.native();
            const auto& right = b.native();
            return CompareStringOrdinal(left.c_str(), static_cast<int>(left.size()), right.c_str(),
                                        static_cast<int>(right.size()), TRUE) == CSTR_EQUAL;
        }

        bool Within(const fs::path& child, const fs::path& parent)
        {
            auto part = child.begin();
            for (const auto& prefix : parent)
            {
                if (part == child.end() || !SameComponent(*part, prefix))
                {
                    return false;
                }
                ++part;
            }
            return true;
        }

        void CheckOutputPath(const fs::path& output, const fs::path& manifest)
        {
            if (output == output.root_path() || output.parent_path() == output)
            {
                throw FixtureError("filesystem root cannot be used as a corpus/check directory");
            }
            if (Within(manifest, output))
            {
                throw FixtureError("pinned manifest must be outside the corpus/check directory");
            }
            if (fs::exists(output) && !fs::is_directory(output))
            {
                throw FixtureError("corpus/check output is not a directory");
            }
        }

        bool Present(const fs::path& path)
        {
            std::error_code error;
            const auto status = fs::symlink_status(path, error);
            if (status.type() == fs::file_type::not_found)
            {
                return false;
            }
            if (error)
            {
                throw fs::filesystem_error("inspect cached fixture", path, error);
            }
            return fs::exists(status);
        }

        std::string RequiredString(const Json& value, const char* key)
        {
            if (!value.is_object() || !value.contains(key) || !value.at(key).is_string())
            {
                throw FixtureError(std::string("required string pin is absent: ") + key);
            }
            return value.at(key).get<std::string>();
        }

        std::uint64_t RequiredInteger(const Json& value, const char* key)
        {
            if (!value.is_object() || !value.contains(key) || !value.at(key).is_number_integer() ||
                (!value.at(key).is_number_unsigned() && value.at(key).get<std::int64_t>() < 0))
            {
                throw FixtureError(std::string("required unsigned pin is absent: ") + key);
            }
            return value.at(key).get<std::uint64_t>();
        }

        void RequireHash(const std::string& value)
        {
            static const std::regex hash("[a-f0-9]{64}");
            if (!std::regex_match(value, hash))
            {
                throw FixtureError("SHA256 pins must contain 64 lowercase hexadecimal digits");
            }
        }

        std::string FoldedLabel(std::string value)
        {
            std::transform(value.begin(), value.end(), value.begin(),
                           [](unsigned char c)
                           {
                               return c >= 'A' && c <= 'Z' ? static_cast<char>(c + ('a' - 'A'))
                                                           : static_cast<char>(c);
                           });
            return value;
        }

        struct PinnedManifest
        {
                Json document;
                std::string hash;
        };

        PinnedManifest LoadPins(const fs::path& path)
        {
            const auto bytes = ReadFile(path);
            Json manifest;
            try
            {
                manifest = Json::parse(bytes.begin(), bytes.end());
            }
            catch (const Json::exception& error)
            {
                throw FixtureError(std::string("invalid corpus manifest: ") + error.what());
            }
            if (!manifest.is_object() || !manifest.contains("schema_version") ||
                !manifest.at("schema_version").is_number_integer() ||
                manifest.at("schema_version") != 1 || !manifest.contains("fixtures") ||
                !manifest.at("fixtures").is_array() || manifest.at("fixtures").empty())
            {
                throw FixtureError(
                    "corpus manifest must have schema_version 1 and a nonempty fixtures array");
            }
            std::set<std::string> labels;
            static const std::regex labelPattern("[A-Za-z0-9][A-Za-z0-9_.-]*");
            static const std::regex reserved("(con|prn|aux|nul|com[1-9]|lpt[1-9])(\\..*)?",
                                             std::regex::icase);
            static const std::regex guid("[A-F0-9]{32}");
            for (const auto& entry : manifest.at("fixtures"))
            {
                const auto label = RequiredString(entry, "label");
                if (!std::regex_match(label, labelPattern) || label.size() > 255 ||
                    label.back() == '.' || std::regex_match(label, reserved) ||
                    !labels.insert(FoldedLabel(label)).second)
                {
                    throw FixtureError("invalid or duplicate corpus label: " + label);
                }
                if (!entry.contains("pe") || !entry.at("pe").is_object())
                {
                    throw FixtureError("required PE pin is absent: " + label);
                }
                const auto& pe = entry.at("pe");
                if (RequiredInteger(pe, "machine") != 0x8664 ||
                    RequiredInteger(pe, "timestamp") > std::numeric_limits<std::uint32_t>::max() ||
                    RequiredInteger(pe, "image_size") == 0 ||
                    RequiredInteger(pe, "image_size") > std::numeric_limits<std::uint32_t>::max() ||
                    RequiredInteger(pe, "file_size") == 0 ||
                    RequiredInteger(pe, "file_size") > maxDllBytes)
                {
                    throw FixtureError("invalid x64 PE pin: " + label);
                }
                if (pe.contains("version") && !pe.at("version").is_null() &&
                    !pe.at("version").is_string())
                {
                    throw FixtureError("PE version pin must be a string or null");
                }
                if (pe.contains("checksum") && !pe.at("checksum").is_null() &&
                    RequiredInteger(pe, "checksum") > std::numeric_limits<std::uint32_t>::max())
                {
                    throw FixtureError("PE checksum pin is out of range");
                }
                RequireHash(RequiredString(pe, "sha256"));
                RequireHash(RequiredString(entry, "pdb_sha256"));
                if (!pe.contains("pdb") || !pe.at("pdb").is_object())
                {
                    throw FixtureError("required PE PDB identity is absent: " + label);
                }
                const auto& identity = pe.at("pdb");
                if (RequiredString(identity, "name") != "ntdll.pdb" ||
                    !std::regex_match(RequiredString(identity, "guid"), guid) ||
                    RequiredInteger(identity, "age") > std::numeric_limits<std::uint32_t>::max())
                {
                    throw FixtureError("invalid PDB identity pin: " + label);
                }
                if (entry.contains("dll_archive") && !entry.at("dll_archive").is_null())
                {
                    ValidateArchiveConfig(entry.at("dll_archive"));
                }
                if (entry.contains("provenance") && !entry.at("provenance").is_null() &&
                    !entry.at("provenance").is_object())
                {
                    throw FixtureError("fixture provenance must be an object or null");
                }
                if (entry.contains("target_os") && !entry.at("target_os").is_null() &&
                    !entry.at("target_os").is_string())
                {
                    throw FixtureError("fixture target_os must be a string or null");
                }
            }
            return {std::move(manifest), Sha256(bytes)};
        }

        struct CachedFixture
        {
                Json entry;
                Json result;
                bool dll = false;
                bool pdb = false;
                bool Ready() const
                {
                    return dll && pdb;
                }
        };

        std::vector<CachedFixture> InspectCache(const PinnedManifest& pins, const fs::path& corpus)
        {
            std::vector<CachedFixture> result;
            for (const auto& entry : pins.document.at("fixtures"))
            {
                const auto label = entry.at("label").get<std::string>();
                const auto folder = corpus / label;
                if (!Within(Normalized(folder), corpus))
                {
                    throw FixtureError("fixture directory escapes corpus root: " + label);
                }
                if (Present(folder) && !fs::is_directory(folder))
                {
                    throw FixtureError("fixture path is not a directory: " + label);
                }
                const auto dll = folder / "ntdll.dll", pdb = folder / "ntdll.pdb";
                CachedFixture cached{entry,
                                     Json{{"label", label},
                                          {"target_os", entry.value("target_os", Json(nullptr))},
                                          {"provenance", entry.value("provenance", Json::object())},
                                          {"expected_pe", entry.at("pe")},
                                          {"expected_pdb_sha256", entry.at("pdb_sha256")}}};
                cached.dll = Present(dll);
                cached.pdb = Present(pdb);
                try
                {
                    if (cached.dll)
                    {
                        if (!fs::is_regular_file(dll))
                        {
                            throw FixtureError("cached DLL is not a regular file");
                        }
                        cached.result["pe"] =
                            ValidatePe(ReadFile(dll, maxDllBytes), entry.at("pe"));
                        cached.result["dll"] = PathText(dll);
                    }
                    if (cached.pdb)
                    {
                        if (!fs::is_regular_file(pdb))
                        {
                            throw FixtureError("cached PDB is not a regular file");
                        }
                        cached.result["pdb"] =
                            ValidatePdb(ReadFile(pdb), entry.at("pe").at("pdb"),
                                        entry.at("pdb_sha256").get<std::string>());
                        cached.result["pdb_file"] = PathText(pdb);
                    }
                }
                catch (const std::exception& error)
                {
                    throw FixtureError("invalid existing fixture " + label + ": " + error.what());
                }
                cached.result["status"] = cached.Ready() ? "ready" : "missing";
                if (!cached.Ready())
                {
                    cached.result["reason"] = "missing " +
                                              std::string(cached.dll ? "" : "ntdll.dll") +
                                              (!cached.dll && !cached.pdb ? " and " : "") +
                                              (cached.pdb ? "" : "ntdll.pdb");
                }
                result.push_back(std::move(cached));
            }
            return result;
        }

        std::string RunToken()
        {
            std::array<std::uint8_t, 16> random{};
            if (BCryptGenRandom(nullptr, random.data(), static_cast<ULONG>(random.size()),
                                BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
            {
                throw FixtureError("could not create a corpus run identity");
            }
            std::ostringstream text;
            // Keep full 128-bit randomness while leaving room for archive SHA
            // filenames and atomic-write suffixes beneath long checkout/temp paths.
            text << "r-";
            for (const auto byte : random)
            {
                text << std::hex << std::setfill('0') << std::setw(2)
                     << static_cast<unsigned>(byte);
            }
            return text.str();
        }

        fs::path NewRun(const fs::path& base)
        {
            fs::create_directories(base);
            for (unsigned attempt = 0; attempt < 10; ++attempt)
            {
                const auto run = base / RunToken();
                if (fs::create_directory(run))
                {
                    return run;
                }
            }
            throw FixtureError("could not create an isolated corpus directory");
        }

        class PublicationLock
        {
            public:
                explicit PublicationLock(const fs::path& corpus)
                {
                    auto key = corpus.native();
                    if (!key.empty())
                    {
                        CharUpperBuffW(key.data(), static_cast<DWORD>(key.size()));
                    }
                    const auto bytes =
                        nonstd::span(reinterpret_cast<const std::uint8_t*>(key.data()),
                                     key.size() * sizeof(wchar_t));
                    const auto digest = Sha256(bytes);
                    const std::wstring name =
                        L"Local\\symfind-corpus-" + std::wstring(digest.begin(), digest.end());
                    m_mutex = CreateMutexW(nullptr, FALSE, name.c_str());
                    if (!m_mutex)
                    {
                        throw std::system_error(GetLastError(), std::system_category(),
                                                "create corpus publication mutex");
                    }
                    const auto status = WaitForSingleObject(m_mutex, 60000);
                    if (status != WAIT_OBJECT_0 && status != WAIT_ABANDONED)
                    {
                        CloseHandle(m_mutex);
                        m_mutex = nullptr;
                        throw FixtureError("timed out waiting for corpus publication");
                    }
                }
                ~PublicationLock()
                {
                    if (m_mutex)
                    {
                        ReleaseMutex(m_mutex);
                        CloseHandle(m_mutex);
                    }
                }
                PublicationLock(const PublicationLock&) = delete;
                PublicationLock& operator=(const PublicationLock&) = delete;

            private:
                HANDLE m_mutex = nullptr;
        };

        DownloadFn TracedTransport(const DownloadFn& transport, Json& trace)
        {
            return [transport, &trace](std::string_view url, bool allowed)
            {
                if (!allowed)
                {
                    throw NetworkDisabled("network disabled for corpus verification");
                }
                Json item{{"url", url}};
                try
                {
                    auto bytes = transport ? transport(url, true) : Download(url, true);
                    item["file_size"] = bytes.size();
                    if (bytes.size() > maxDownloadBytes)
                    {
                        throw FixtureError("download exceeds the 256 MiB fixture limit");
                    }
                    item["sha256"] = Sha256(bytes);
                    if (symfind::EndsWith(url, "/ntdll.dll") ||
                        symfind::EndsWith(url, "/ntdll.pdb"))
                    {
                        try
                        {
                            item["identity"] = symfind::EndsWith(url, "/ntdll.dll")
                                                   ? ParsePe(bytes)
                                                   : ParsePdbIdentity(bytes);
                        }
                        catch (const std::exception& error)
                        {
                            item["identity_error"] = error.what();
                        }
                    }
                    trace.push_back(std::move(item));
                    return bytes;
                }
                catch (const std::exception& error)
                {
                    item["error"] = error.what();
                    trace.push_back(std::move(item));
                    throw;
                }
            };
        }

        void SaveReport(const PinnedManifest& pins, const fs::path& source, const std::string& mode,
                        const fs::path& live, const Json& trace, const CorpusResult& result)
        {
            WriteJson(result.reportManifest, Json{{"schema_version", 1},
                                                  {"mode", mode},
                                                  {"successful", result.successful},
                                                  {"provisioned", result.provisioned},
                                                  {"reason", result.reason},
                                                  {"source_manifest", PathText(source)},
                                                  {"source_manifest_sha256", pins.hash},
                                                  {"protected_corpus", PathText(live)},
                                                  {"staging_root", PathText(result.stagingRoot)},
                                                  {"fixtures", result.fixtures},
                                                  {"downloads", trace}});
        }

        void RetainReport(const PinnedManifest& pins, const fs::path& source,
                          const std::string& mode, const fs::path& live, const Json& trace,
                          CorpusResult& result)
        {
            try
            {
                SaveReport(pins, source, mode, live, trace, result);
            }
            catch (const std::exception& error)
            {
                result.successful = false;
                result.reason += (result.reason.empty() ? "" : "; ") +
                                 std::string("could not save corpus report: ") + error.what();
            }
        }

        struct Move
        {
                fs::path from, to;
        };

        void MoveWithoutReplace(const fs::path& from, const fs::path& to)
        {
            if (!MoveFileExW(from.c_str(), to.c_str(), MOVEFILE_WRITE_THROUGH))
            {
                throw std::system_error(GetLastError(), std::system_category(),
                                        "publish absent corpus file/directory");
            }
        }

        void CopyPartial(const CachedFixture& cached, const fs::path& live, const fs::path& stage)
        {
            const auto label = cached.entry.at("label").get<std::string>();
            if (cached.dll)
            {
                AtomicWrite(stage / label / "ntdll.dll",
                            ReadFile(live / label / "ntdll.dll", maxDllBytes),
                            [&](auto bytes)
                            {
                                return ValidatePe(bytes, cached.entry.at("pe"));
                            });
            }
            if (cached.pdb)
            {
                AtomicWrite(stage / label / "ntdll.pdb", ReadFile(live / label / "ntdll.pdb"),
                            [&](auto bytes)
                            {
                                return ValidatePdb(
                                    bytes, cached.entry.at("pe").at("pdb"),
                                    cached.entry.at("pdb_sha256").get<std::string>());
                            });
            }
            // Bootstrap may reuse an already pinned archive, but the isolated
            // fresh verifier never calls this helper and has no live cache input.
            if (!cached.dll && cached.entry.contains("dll_archive") &&
                !cached.entry.at("dll_archive").is_null())
            {
                const auto& archive = cached.entry.at("dll_archive");
                const auto name = archive.at("sha256").get<std::string>() + ".tar.gz";
                const auto path = live.parent_path() / "archives" / name;
                if (Present(path))
                {
                    AtomicWrite(stage.parent_path() / "archives" / name, ReadFile(path),
                                [&](auto bytes)
                                {
                                    return ValidateArchive(bytes, archive);
                                });
                }
            }
        }
    } // namespace

    CorpusResult EnsureCorpus(const fs::path& manifestPath, const fs::path& corpusRoot,
                              bool allowNetwork, const DownloadFn& downloader)
    {
        const auto source = Normalized(manifestPath), live = Normalized(corpusRoot);
        CheckOutputPath(live, source);
        const auto pins = LoadPins(source);
        auto cached = InspectCache(pins, live);
        CorpusResult result;
        for (const auto& fixture : cached)
        {
            result.fixtures.push_back(fixture.result);
        }
        if (std::all_of(cached.begin(), cached.end(),
                        [](const auto& entry)
                        {
                            return entry.Ready();
                        }))
        {
            result.successful = true;
            return result; // No writes, locks, timestamps, archives, or HTTP.
        }
        if (!allowNetwork)
        {
            throw NetworkDisabled("corpus is incomplete; explicit --allow-network is required to "
                                  "prepare missing fixtures");
        }

        const auto base = live.parent_path() / "tmp" / "corpus-preparation";
        if (Within(Normalized(base), live))
        {
            throw FixtureError("preparation staging directory must be outside the live corpus");
        }
        result.stagingRoot = NewRun(base);
        result.reportManifest = result.stagingRoot / "manifest.json";
        const auto stage = result.stagingRoot / "corpus";
        Json trace = Json::array();
        const auto transport = TracedTransport(downloader, trace);
        try
        {
            WriteJson(result.stagingRoot / "pinned-manifest.json", pins.document);
            result.fixtures = Json::array();
            bool allReady = true;
            for (const auto& fixture : cached)
            {
                if (fixture.Ready())
                {
                    result.fixtures.push_back(fixture.result);
                }
                else
                {
                    CopyPartial(fixture, live, stage);
                    const auto prepared =
                        ProcessFixture(fixture.entry, stage, true, {}, {}, transport);
                    if (prepared.at("status") != "ready")
                    {
                        allReady = false;
                    }
                    result.fixtures.push_back(prepared);
                }
            }
            if (!allReady)
            {
                result.reason = "one or more pinned fixtures could not be prepared; live corpus "
                                "was not changed";
                RetainReport(pins, source, "prepare", live, trace, result);
                return result;
            }

            PublicationLock lock(live);
            cached = InspectCache(
                pins, live); // Another process may have completed or modified the cache.
            std::vector<Move> plan;
            result.fixtures = Json::array();
            for (const auto& fixture : cached)
            {
                if (fixture.Ready())
                {
                    result.fixtures.push_back(fixture.result);
                    continue;
                }
                const auto label = fixture.entry.at("label").get<std::string>();
                const auto image = ValidatePe(ReadFile(stage / label / "ntdll.dll", maxDllBytes),
                                              fixture.entry.at("pe"));
                const auto symbols =
                    ValidatePdb(ReadFile(stage / label / "ntdll.pdb"), image.at("pdb"),
                                fixture.entry.at("pdb_sha256").get<std::string>());
                Json prepared = ReadJson(stage / label / "manifest.json");
                prepared["dll"] = PathText(live / label / "ntdll.dll");
                prepared["pdb_file"] = PathText(live / label / "ntdll.pdb");
                prepared["pe"] = image;
                prepared["pdb"] = symbols;
                prepared["status"] = "ready";
                WriteJson(stage / label / "manifest.json", prepared);
                result.fixtures.push_back(prepared);
                if (!Present(live / label))
                {
                    plan.push_back({stage / label, live / label});
                }
                else
                {
                    if (!fixture.dll)
                    {
                        plan.push_back({stage / label / "ntdll.dll", live / label / "ntdll.dll"});
                    }
                    if (!fixture.pdb)
                    {
                        plan.push_back({stage / label / "ntdll.pdb", live / label / "ntdll.pdb"});
                    }
                    if (!Present(live / label / "manifest.json"))
                    {
                        plan.push_back(
                            {stage / label / "manifest.json", live / label / "manifest.json"});
                    }
                }
            }
            if (!Present(live / "manifest.json"))
            {
                const auto aggregate = result.stagingRoot / "publication" / "manifest.json";
                WriteJson(aggregate, Json{{"schema_version", 1}, {"fixtures", result.fixtures}});
                plan.push_back({aggregate, live / "manifest.json"});
            }

            // Archives are reusable bootstrap inputs, with the same exact pins
            // as the DLLs. Publish them only after every missing pair validated;
            // the fresh verifier never enters this publication path.
            const auto archiveCache = live.parent_path() / "archives";
            bool publishesArchives = false;
            std::set<fs::path> scheduledArchives;
            for (const auto& entry : pins.document.at("fixtures"))
            {
                if (!entry.contains("dll_archive") || entry.at("dll_archive").is_null())
                {
                    continue;
                }
                const auto& archive = entry.at("dll_archive");
                const auto name = archive.at("sha256").get<std::string>() + ".tar.gz";
                const auto stagedArchive = result.stagingRoot / "archives" / name;
                if (!Present(stagedArchive))
                {
                    continue;
                }
                const auto cachedArchive = archiveCache / name;
                (void)ValidateArchive(ReadFile(stagedArchive), archive);
                if (Present(cachedArchive))
                {
                    (void)ValidateArchive(ReadFile(cachedArchive), archive);
                }
                else if (scheduledArchives.insert(cachedArchive).second)
                {
                    plan.push_back({stagedArchive, cachedArchive});
                    publishesArchives = true;
                }
            }
            if (publishesArchives && Present(archiveCache) && !fs::is_directory(archiveCache))
            {
                throw FixtureError("archive cache is not a directory");
            }

            // Every fixture is complete and verified before any live publication.
            // MoveFileEx without REPLACE_EXISTING closes the final race: an
            // unexpected existing destination is never overwritten.
            std::vector<fs::path> createdDirectories;
            std::vector<Move> completed;
            try
            {
                if (!Present(live))
                {
                    fs::create_directories(live);
                    createdDirectories.push_back(live);
                }
                if (publishesArchives && !Present(archiveCache))
                {
                    fs::create_directories(archiveCache);
                    createdDirectories.push_back(archiveCache);
                }
                for (const auto& move : plan)
                {
                    MoveWithoutReplace(move.from, move.to);
                    completed.push_back(move);
                }
                const auto confirmed = InspectCache(pins, live);
                if (!std::all_of(confirmed.begin(), confirmed.end(),
                                 [](const auto& entry)
                                 {
                                     return entry.Ready();
                                 }))
                {
                    throw FixtureError("published corpus is incomplete");
                }
                result.fixtures = Json::array();
                for (const auto& fixture : confirmed)
                {
                    result.fixtures.push_back(fixture.result);
                }
                result.provisioned = !completed.empty();
                result.successful = true;
            }
            catch (const std::exception& error)
            {
                result.reason = error.what();
                for (auto move = completed.rbegin(); move != completed.rend(); ++move)
                {
                    try
                    {
                        MoveWithoutReplace(move->to, move->from);
                    }
                    catch (const std::exception& undo)
                    {
                        result.reason += "; rollback retained created path " + PathText(move->to) +
                                         ": " + undo.what();
                    }
                }
                for (auto directory = createdDirectories.rbegin();
                     directory != createdDirectories.rend(); ++directory)
                {
                    std::error_code ignored;
                    fs::remove(*directory, ignored); // Only our empty directory; never recursive.
                }
            }
        }
        catch (const std::exception& error)
        {
            result.successful = false;
            result.reason = error.what();
        }
        RetainReport(pins, source, "prepare", live, trace, result);
        return result;
    }

    CorpusResult VerifyFreshCorpus(const fs::path& manifestPath, const fs::path& checkRoot,
                                   const fs::path& protectedCorpusRoot, bool allowNetwork,
                                   const DownloadFn& downloader)
    {
        const auto source = Normalized(manifestPath), checks = Normalized(checkRoot),
                   live = Normalized(protectedCorpusRoot);
        CheckOutputPath(checks, source);
        CheckOutputPath(live, source);
        if (Within(checks, live) || Within(live, checks))
        {
            throw FixtureError("fresh verification directory must be separate from the live corpus "
                               "and its ancestors");
        }
        const auto pins = LoadPins(source);
        if (!allowNetwork)
        {
            throw NetworkDisabled("fresh corpus verification requires explicit --allow-network");
        }

        CorpusResult result;
        result.stagingRoot = NewRun(checks);
        result.reportManifest = result.stagingRoot / "manifest.json";
        const auto output = result.stagingRoot / "corpus";
        Json trace = Json::array();
        const auto transport = TracedTransport(downloader, trace);
        try
        {
            WriteJson(result.stagingRoot / "pinned-manifest.json", pins.document);
            result.successful = true;
            for (const auto& entry : pins.document.at("fixtures"))
            {
                const auto fixture = ProcessFixture(entry, output, true, {}, {}, transport);
                if (fixture.at("status") != "ready")
                {
                    result.successful = false;
                }
                result.fixtures.push_back(fixture);
            }
            if (!result.successful)
            {
                result.reason = "fresh downloads did not reproduce every exact DLL/PDB pin";
            }
            WriteJson(output / "manifest.json",
                      Json{{"schema_version", 1}, {"fixtures", result.fixtures}});
        }
        catch (const std::exception& error)
        {
            result.successful = false;
            result.reason = error.what();
        }
        RetainReport(pins, source, "fresh_network_verification", live, trace, result);
        return result;
    }
} // namespace pdbStuff
