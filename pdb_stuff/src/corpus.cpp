#include "pdb_stuff/corpus.h"
#include "pdb_stuff/io.h"

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

namespace pdb_stuff
{
    namespace
    {
        namespace fs = std::filesystem;

        std::string path_text(const fs::path& path)
        {
            const auto text = path.u8string();
            return {reinterpret_cast<const char*>(text.data()), text.size()};
        }

        fs::path normalized(const fs::path& path)
        {
            if (path.empty())
                throw FixtureError("corpus paths must not be empty");
            return fs::weakly_canonical(fs::absolute(path));
        }

        bool same_component(const fs::path& a, const fs::path& b)
        {
            const auto& left = a.native();
            const auto& right = b.native();
            return CompareStringOrdinal(left.c_str(), static_cast<int>(left.size()),
                                        right.c_str(), static_cast<int>(right.size()), TRUE) == CSTR_EQUAL;
        }

        bool within(const fs::path& child, const fs::path& parent)
        {
            auto part = child.begin();
            for (const auto& prefix : parent)
            {
                if (part == child.end() || !same_component(*part, prefix))
                    return false;
                ++part;
            }
            return true;
        }

        void check_output_path(const fs::path& output, const fs::path& manifest)
        {
            if (output == output.root_path() || output.parent_path() == output)
                throw FixtureError("filesystem root cannot be used as a corpus/check directory");
            if (within(manifest, output))
                throw FixtureError("pinned manifest must be outside the corpus/check directory");
            if (fs::exists(output) && !fs::is_directory(output))
                throw FixtureError("corpus/check output is not a directory");
        }

        bool present(const fs::path& path)
        {
            std::error_code error;
            const auto status = fs::symlink_status(path, error);
            if (status.type() == fs::file_type::not_found)
                return false;
            if (error)
                throw fs::filesystem_error("inspect cached fixture", path, error);
            return fs::exists(status);
        }

        std::string required_string(const Json& value, const char* key)
        {
            if (!value.is_object() || !value.contains(key) || !value.at(key).is_string())
                throw FixtureError(std::string("required string pin is absent: ") + key);
            return value.at(key).get<std::string>();
        }

        std::uint64_t required_integer(const Json& value, const char* key)
        {
            if (!value.is_object() || !value.contains(key) || !value.at(key).is_number_integer() ||
                (!value.at(key).is_number_unsigned() && value.at(key).get<std::int64_t>() < 0))
                throw FixtureError(std::string("required unsigned pin is absent: ") + key);
            return value.at(key).get<std::uint64_t>();
        }

        void require_hash(const std::string& value)
        {
            static const std::regex hash("[a-f0-9]{64}");
            if (!std::regex_match(value, hash))
                throw FixtureError("SHA256 pins must contain 64 lowercase hexadecimal digits");
        }

        std::string folded_label(std::string value)
        {
            std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c)
                           { return c >= 'A' && c <= 'Z' ? static_cast<char>(c + ('a' - 'A')) : static_cast<char>(c); });
            return value;
        }

        struct PinnedManifest
        {
                Json document;
                std::string hash;
        };

        PinnedManifest load_pins(const fs::path& path)
        {
            const auto bytes = read_file(path);
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
                !manifest.at("schema_version").is_number_integer() || manifest.at("schema_version") != 1 ||
                !manifest.contains("fixtures") || !manifest.at("fixtures").is_array() || manifest.at("fixtures").empty())
                throw FixtureError("corpus manifest must have schema_version 1 and a nonempty fixtures array");
            std::set<std::string> labels;
            static const std::regex label_pattern("[A-Za-z0-9][A-Za-z0-9_.-]*");
            static const std::regex reserved("(con|prn|aux|nul|com[1-9]|lpt[1-9])(\\..*)?", std::regex::icase);
            static const std::regex guid("[A-F0-9]{32}");
            for (const auto& entry : manifest.at("fixtures"))
            {
                const auto label = required_string(entry, "label");
                if (!std::regex_match(label, label_pattern) || label.size() > 255 || label.back() == '.' ||
                    std::regex_match(label, reserved) || !labels.insert(folded_label(label)).second)
                    throw FixtureError("invalid or duplicate corpus label: " + label);
                if (!entry.contains("pe") || !entry.at("pe").is_object())
                    throw FixtureError("required PE pin is absent: " + label);
                const auto& pe = entry.at("pe");
                if (required_integer(pe, "machine") != 0x8664 ||
                    required_integer(pe, "timestamp") > std::numeric_limits<std::uint32_t>::max() ||
                    required_integer(pe, "image_size") == 0 ||
                    required_integer(pe, "image_size") > std::numeric_limits<std::uint32_t>::max() ||
                    required_integer(pe, "file_size") == 0 || required_integer(pe, "file_size") > max_dll_bytes)
                    throw FixtureError("invalid x64 PE pin: " + label);
                if (pe.contains("version") && !pe.at("version").is_null() && !pe.at("version").is_string())
                    throw FixtureError("PE version pin must be a string or null");
                if (pe.contains("checksum") && !pe.at("checksum").is_null() &&
                    required_integer(pe, "checksum") > std::numeric_limits<std::uint32_t>::max())
                    throw FixtureError("PE checksum pin is out of range");
                require_hash(required_string(pe, "sha256"));
                require_hash(required_string(entry, "pdb_sha256"));
                if (!pe.contains("pdb") || !pe.at("pdb").is_object())
                    throw FixtureError("required PE PDB identity is absent: " + label);
                const auto& identity = pe.at("pdb");
                if (required_string(identity, "name") != "ntdll.pdb" ||
                    !std::regex_match(required_string(identity, "guid"), guid) ||
                    required_integer(identity, "age") > std::numeric_limits<std::uint32_t>::max())
                    throw FixtureError("invalid PDB identity pin: " + label);
                if (entry.contains("dll_archive") && !entry.at("dll_archive").is_null())
                    validate_archive_config(entry.at("dll_archive"));
                if (entry.contains("provenance") && !entry.at("provenance").is_null() && !entry.at("provenance").is_object())
                    throw FixtureError("fixture provenance must be an object or null");
                if (entry.contains("target_os") && !entry.at("target_os").is_null() && !entry.at("target_os").is_string())
                    throw FixtureError("fixture target_os must be a string or null");
            }
            return {std::move(manifest), sha256(bytes)};
        }

        struct CachedFixture
        {
                Json entry;
                Json result;
                bool dll = false;
                bool pdb = false;
                bool ready() const { return dll && pdb; }
        };

        std::vector<CachedFixture> inspect_cache(const PinnedManifest& pins, const fs::path& corpus)
        {
            std::vector<CachedFixture> result;
            for (const auto& entry : pins.document.at("fixtures"))
            {
                const auto label = entry.at("label").get<std::string>();
                const auto folder = corpus / label;
                if (!within(normalized(folder), corpus))
                    throw FixtureError("fixture directory escapes corpus root: " + label);
                if (present(folder) && !fs::is_directory(folder))
                    throw FixtureError("fixture path is not a directory: " + label);
                const auto dll = folder / "ntdll.dll", pdb = folder / "ntdll.pdb";
                CachedFixture cached{entry, Json{{"label", label}, {"target_os", entry.value("target_os", Json(nullptr))}, {"provenance", entry.value("provenance", Json::object())}, {"expected_pe", entry.at("pe")}, {"expected_pdb_sha256", entry.at("pdb_sha256")}}};
                cached.dll = present(dll);
                cached.pdb = present(pdb);
                try
                {
                    if (cached.dll)
                    {
                        if (!fs::is_regular_file(dll))
                            throw FixtureError("cached DLL is not a regular file");
                        cached.result["pe"] = validate_pe(read_file(dll, max_dll_bytes), entry.at("pe"));
                        cached.result["dll"] = path_text(dll);
                    }
                    if (cached.pdb)
                    {
                        if (!fs::is_regular_file(pdb))
                            throw FixtureError("cached PDB is not a regular file");
                        cached.result["pdb"] = validate_pdb(read_file(pdb), entry.at("pe").at("pdb"),
                                                            entry.at("pdb_sha256").get<std::string>());
                        cached.result["pdb_file"] = path_text(pdb);
                    }
                }
                catch (const std::exception& error)
                {
                    throw FixtureError("invalid existing fixture " + label + ": " + error.what());
                }
                cached.result["status"] = cached.ready() ? "ready" : "missing";
                if (!cached.ready())
                    cached.result["reason"] = "missing " + std::string(cached.dll ? "" : "ntdll.dll") +
                                              (!cached.dll && !cached.pdb ? " and " : "") + (cached.pdb ? "" : "ntdll.pdb");
                result.push_back(std::move(cached));
            }
            return result;
        }

        std::string run_token()
        {
            std::array<std::uint8_t, 16> random{};
            if (BCryptGenRandom(nullptr, random.data(), static_cast<ULONG>(random.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
                throw FixtureError("could not create a corpus run identity");
            std::ostringstream text;
            // Keep full 128-bit randomness while leaving room for archive SHA
            // filenames and atomic-write suffixes beneath long checkout/temp paths.
            text << "r-";
            for (const auto byte : random)
                text << std::hex << std::setfill('0') << std::setw(2) << static_cast<unsigned>(byte);
            return text.str();
        }

        fs::path new_run(const fs::path& base)
        {
            fs::create_directories(base);
            for (unsigned attempt = 0; attempt < 10; ++attempt)
            {
                const auto run = base / run_token();
                if (fs::create_directory(run))
                    return run;
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
                        CharUpperBuffW(key.data(), static_cast<DWORD>(key.size()));
                    const auto bytes = std::span(reinterpret_cast<const std::uint8_t*>(key.data()), key.size() * sizeof(wchar_t));
                    const auto digest = sha256(bytes);
                    const std::wstring name = L"Local\\symfind-corpus-" + std::wstring(digest.begin(), digest.end());
                    mutex_ = CreateMutexW(nullptr, FALSE, name.c_str());
                    if (!mutex_)
                        throw std::system_error(GetLastError(), std::system_category(), "create corpus publication mutex");
                    const auto status = WaitForSingleObject(mutex_, 60000);
                    if (status != WAIT_OBJECT_0 && status != WAIT_ABANDONED)
                    {
                        CloseHandle(mutex_);
                        mutex_ = nullptr;
                        throw FixtureError("timed out waiting for corpus publication");
                    }
                }
                ~PublicationLock()
                {
                    if (mutex_)
                    {
                        ReleaseMutex(mutex_);
                        CloseHandle(mutex_);
                    }
                }
                PublicationLock(const PublicationLock&) = delete;
                PublicationLock& operator=(const PublicationLock&) = delete;

            private:
                HANDLE mutex_ = nullptr;
        };

        DownloadFn traced_transport(const DownloadFn& transport, Json& trace)
        {
            return [transport, &trace](std::string_view url, bool allowed)
            {
                if (!allowed)
                    throw NetworkDisabled("network disabled for corpus verification");
                Json item{{"url", url}};
                try
                {
                    auto bytes = transport ? transport(url, true) : download(url, true);
                    item["file_size"] = bytes.size();
                    if (bytes.size() > max_download_bytes)
                        throw FixtureError("download exceeds the 256 MiB fixture limit");
                    item["sha256"] = sha256(bytes);
                    if (url.ends_with("/ntdll.dll") || url.ends_with("/ntdll.pdb"))
                    {
                        try
                        {
                            item["identity"] = url.ends_with("/ntdll.dll") ? parse_pe(bytes) : parse_pdb_identity(bytes);
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

        void save_report(const PinnedManifest& pins, const fs::path& source, const std::string& mode,
                         const fs::path& live, const Json& trace, const CorpusResult& result)
        {
            write_json(result.report_manifest, Json{{"schema_version", 1}, {"mode", mode}, {"successful", result.successful}, {"provisioned", result.provisioned}, {"reason", result.reason}, {"source_manifest", path_text(source)}, {"source_manifest_sha256", pins.hash}, {"protected_corpus", path_text(live)}, {"staging_root", path_text(result.staging_root)}, {"fixtures", result.fixtures}, {"downloads", trace}});
        }

        void retain_report(const PinnedManifest& pins, const fs::path& source, const std::string& mode,
                           const fs::path& live, const Json& trace, CorpusResult& result)
        {
            try
            {
                save_report(pins, source, mode, live, trace, result);
            }
            catch (const std::exception& error)
            {
                result.successful = false;
                result.reason += (result.reason.empty() ? "" : "; ") + std::string("could not save corpus report: ") + error.what();
            }
        }

        struct Move
        {
                fs::path from, to;
        };

        void move_without_replace(const fs::path& from, const fs::path& to)
        {
            if (!MoveFileExW(from.c_str(), to.c_str(), MOVEFILE_WRITE_THROUGH))
                throw std::system_error(GetLastError(), std::system_category(), "publish absent corpus file/directory");
        }

        void copy_partial(const CachedFixture& cached, const fs::path& live, const fs::path& stage)
        {
            const auto label = cached.entry.at("label").get<std::string>();
            if (cached.dll)
                atomic_write(stage / label / "ntdll.dll", read_file(live / label / "ntdll.dll", max_dll_bytes),
                             [&](auto bytes)
                             { return validate_pe(bytes, cached.entry.at("pe")); });
            if (cached.pdb)
                atomic_write(stage / label / "ntdll.pdb", read_file(live / label / "ntdll.pdb"),
                             [&](auto bytes)
                             { return validate_pdb(bytes, cached.entry.at("pe").at("pdb"), cached.entry.at("pdb_sha256").get<std::string>()); });
            // Bootstrap may reuse an already pinned archive, but the isolated
            // fresh verifier never calls this helper and has no live cache input.
            if (!cached.dll && cached.entry.contains("dll_archive") && !cached.entry.at("dll_archive").is_null())
            {
                const auto& archive = cached.entry.at("dll_archive");
                const auto name = archive.at("sha256").get<std::string>() + ".tar.gz";
                const auto path = live.parent_path() / "archives" / name;
                if (present(path))
                    atomic_write(stage.parent_path() / "archives" / name, read_file(path),
                                 [&](auto bytes)
                                 { return validate_archive(bytes, archive); });
            }
        }
    } // namespace

    CorpusResult ensure_corpus(const fs::path& manifest_path, const fs::path& corpus_root,
                               bool allow_network, const DownloadFn& downloader)
    {
        const auto source = normalized(manifest_path), live = normalized(corpus_root);
        check_output_path(live, source);
        const auto pins = load_pins(source);
        auto cached = inspect_cache(pins, live);
        CorpusResult result;
        for (const auto& fixture : cached)
            result.fixtures.push_back(fixture.result);
        if (std::all_of(cached.begin(), cached.end(), [](const auto& entry)
                        { return entry.ready(); }))
        {
            result.successful = true;
            return result; // No writes, locks, timestamps, archives, or HTTP.
        }
        if (!allow_network)
            throw NetworkDisabled("corpus is incomplete; explicit --allow-network is required to prepare missing fixtures");

        const auto base = live.parent_path() / "tmp" / "corpus-preparation";
        if (within(normalized(base), live))
            throw FixtureError("preparation staging directory must be outside the live corpus");
        result.staging_root = new_run(base);
        result.report_manifest = result.staging_root / "manifest.json";
        const auto stage = result.staging_root / "corpus";
        Json trace = Json::array();
        const auto transport = traced_transport(downloader, trace);
        try
        {
            write_json(result.staging_root / "pinned-manifest.json", pins.document);
            result.fixtures = Json::array();
            bool all_ready = true;
            for (const auto& fixture : cached)
            {
                if (fixture.ready())
                    result.fixtures.push_back(fixture.result);
                else
                {
                    copy_partial(fixture, live, stage);
                    const auto prepared = process_fixture(fixture.entry, stage, true, {}, {}, transport);
                    if (prepared.at("status") != "ready")
                        all_ready = false;
                    result.fixtures.push_back(prepared);
                }
            }
            if (!all_ready)
            {
                result.reason = "one or more pinned fixtures could not be prepared; live corpus was not changed";
                retain_report(pins, source, "prepare", live, trace, result);
                return result;
            }

            PublicationLock lock(live);
            cached = inspect_cache(pins, live); // Another process may have completed or modified the cache.
            std::vector<Move> plan;
            result.fixtures = Json::array();
            for (const auto& fixture : cached)
            {
                if (fixture.ready())
                {
                    result.fixtures.push_back(fixture.result);
                    continue;
                }
                const auto label = fixture.entry.at("label").get<std::string>();
                const auto image = validate_pe(read_file(stage / label / "ntdll.dll", max_dll_bytes), fixture.entry.at("pe"));
                const auto symbols = validate_pdb(read_file(stage / label / "ntdll.pdb"), image.at("pdb"), fixture.entry.at("pdb_sha256").get<std::string>());
                Json prepared = read_json(stage / label / "manifest.json");
                prepared["dll"] = path_text(live / label / "ntdll.dll");
                prepared["pdb_file"] = path_text(live / label / "ntdll.pdb");
                prepared["pe"] = image;
                prepared["pdb"] = symbols;
                prepared["status"] = "ready";
                write_json(stage / label / "manifest.json", prepared);
                result.fixtures.push_back(prepared);
                if (!present(live / label))
                    plan.push_back({stage / label, live / label});
                else
                {
                    if (!fixture.dll)
                        plan.push_back({stage / label / "ntdll.dll", live / label / "ntdll.dll"});
                    if (!fixture.pdb)
                        plan.push_back({stage / label / "ntdll.pdb", live / label / "ntdll.pdb"});
                    if (!present(live / label / "manifest.json"))
                        plan.push_back({stage / label / "manifest.json", live / label / "manifest.json"});
                }
            }
            if (!present(live / "manifest.json"))
            {
                const auto aggregate = result.staging_root / "publication" / "manifest.json";
                write_json(aggregate, Json{{"schema_version", 1}, {"fixtures", result.fixtures}});
                plan.push_back({aggregate, live / "manifest.json"});
            }

            // Archives are reusable bootstrap inputs, with the same exact pins
            // as the DLLs. Publish them only after every missing pair validated;
            // the fresh verifier never enters this publication path.
            const auto archive_cache = live.parent_path() / "archives";
            bool publishes_archives = false;
            std::set<fs::path> scheduled_archives;
            for (const auto& entry : pins.document.at("fixtures"))
            {
                if (!entry.contains("dll_archive") || entry.at("dll_archive").is_null())
                    continue;
                const auto& archive = entry.at("dll_archive");
                const auto name = archive.at("sha256").get<std::string>() + ".tar.gz";
                const auto staged_archive = result.staging_root / "archives" / name;
                if (!present(staged_archive))
                    continue;
                const auto cached_archive = archive_cache / name;
                (void)validate_archive(read_file(staged_archive), archive);
                if (present(cached_archive))
                    (void)validate_archive(read_file(cached_archive), archive);
                else if (scheduled_archives.insert(cached_archive).second)
                {
                    plan.push_back({staged_archive, cached_archive});
                    publishes_archives = true;
                }
            }
            if (publishes_archives && present(archive_cache) && !fs::is_directory(archive_cache))
                throw FixtureError("archive cache is not a directory");

            // Every fixture is complete and verified before any live publication.
            // MoveFileEx without REPLACE_EXISTING closes the final race: an
            // unexpected existing destination is never overwritten.
            std::vector<fs::path> created_directories;
            std::vector<Move> completed;
            try
            {
                if (!present(live))
                {
                    fs::create_directories(live);
                    created_directories.push_back(live);
                }
                if (publishes_archives && !present(archive_cache))
                {
                    fs::create_directories(archive_cache);
                    created_directories.push_back(archive_cache);
                }
                for (const auto& move : plan)
                {
                    move_without_replace(move.from, move.to);
                    completed.push_back(move);
                }
                const auto confirmed = inspect_cache(pins, live);
                if (!std::all_of(confirmed.begin(), confirmed.end(), [](const auto& entry)
                                 { return entry.ready(); }))
                    throw FixtureError("published corpus is incomplete");
                result.fixtures = Json::array();
                for (const auto& fixture : confirmed)
                    result.fixtures.push_back(fixture.result);
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
                        move_without_replace(move->to, move->from);
                    }
                    catch (const std::exception& undo)
                    {
                        result.reason += "; rollback retained created path " + path_text(move->to) + ": " + undo.what();
                    }
                }
                for (auto directory = created_directories.rbegin(); directory != created_directories.rend(); ++directory)
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
        retain_report(pins, source, "prepare", live, trace, result);
        return result;
    }

    CorpusResult verify_fresh_corpus(const fs::path& manifest_path, const fs::path& check_root,
                                     const fs::path& protected_corpus_root, bool allow_network,
                                     const DownloadFn& downloader)
    {
        const auto source = normalized(manifest_path), checks = normalized(check_root), live = normalized(protected_corpus_root);
        check_output_path(checks, source);
        check_output_path(live, source);
        if (within(checks, live) || within(live, checks))
            throw FixtureError("fresh verification directory must be separate from the live corpus and its ancestors");
        const auto pins = load_pins(source);
        if (!allow_network)
            throw NetworkDisabled("fresh corpus verification requires explicit --allow-network");

        CorpusResult result;
        result.staging_root = new_run(checks);
        result.report_manifest = result.staging_root / "manifest.json";
        const auto output = result.staging_root / "corpus";
        Json trace = Json::array();
        const auto transport = traced_transport(downloader, trace);
        try
        {
            write_json(result.staging_root / "pinned-manifest.json", pins.document);
            result.successful = true;
            for (const auto& entry : pins.document.at("fixtures"))
            {
                const auto fixture = process_fixture(entry, output, true, {}, {}, transport);
                if (fixture.at("status") != "ready")
                    result.successful = false;
                result.fixtures.push_back(fixture);
            }
            if (!result.successful)
                result.reason = "fresh downloads did not reproduce every exact DLL/PDB pin";
            write_json(output / "manifest.json", Json{{"schema_version", 1}, {"fixtures", result.fixtures}});
        }
        catch (const std::exception& error)
        {
            result.successful = false;
            result.reason = error.what();
        }
        retain_report(pins, source, "fresh_network_verification", live, trace, result);
        return result;
    }
} // namespace pdb_stuff
