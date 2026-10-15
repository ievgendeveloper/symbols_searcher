#include <pdb_stuff/fixtures.h>
#include <pdb_stuff/io.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <limits>
#include <map>
#include <regex>
#include <set>
#include <sstream>
#include <system_error>
#include <utility>

namespace pdb_stuff
{
    namespace
    {

        class View
        {
            public:
                explicit View(std::span<const std::uint8_t> bytes) : bytes_(bytes) {}
                std::span<const std::uint8_t> slice(std::size_t offset, std::size_t size) const
                {
                    if (offset > bytes_.size() || size > bytes_.size() - offset)
                        throw FixtureError("file range is outside the file");
                    return bytes_.subspan(offset, size);
                }
                std::uint16_t u16(std::size_t offset) const { return number<std::uint16_t>(offset); }
                std::uint32_t u32(std::size_t offset) const { return number<std::uint32_t>(offset); }
                std::size_t size() const { return bytes_.size(); }

            private:
                template <class T>
                T number(std::size_t offset) const
                {
                    const auto bytes = slice(offset, sizeof(T));
                    T result = 0;
                    for (std::size_t i = 0; i < sizeof(T); ++i)
                        result |= static_cast<T>(bytes[i]) << (8 * i);
                    return result;
                }
                std::span<const std::uint8_t> bytes_;
        };

        std::string hex_bytes(std::span<const std::uint8_t> bytes, bool uppercase = false)
        {
            const char* digits = uppercase ? "0123456789ABCDEF" : "0123456789abcdef";
            std::string result;
            result.reserve(bytes.size() * 2);
            for (const auto byte : bytes)
            {
                result.push_back(digits[byte >> 4]);
                result.push_back(digits[byte & 15]);
            }
            return result;
        }

        std::string guid_hex(std::span<const std::uint8_t> bytes)
        {
            if (bytes.size() != 16)
                throw FixtureError("invalid GUID length");
            std::array<std::uint8_t, 16> ordered{};
            constexpr std::array<std::size_t, 16> order{3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15};
            for (std::size_t i = 0; i < ordered.size(); ++i)
                ordered[i] = bytes[order[i]];
            return hex_bytes(ordered, true);
        }

        std::string string_field(const Json& value, std::string_view key, std::string fallback = {})
        {
            if (!value.is_object())
                return fallback;
            const auto found = value.find(std::string(key));
            if (found == value.end() || found->is_null())
                return fallback;
            if (!found->is_string())
                throw FixtureError("manifest field " + std::string(key) + " must be a string");
            return found->get<std::string>();
        }

        Json object_field(const Json& value, std::string_view key)
        {
            if (!value.is_object())
                return Json::object();
            const auto found = value.find(std::string(key));
            if (found == value.end() || found->is_null())
                return Json::object();
            if (!found->is_object())
                throw FixtureError("manifest field " + std::string(key) + " must be an object");
            return *found;
        }

        std::uint64_t unsigned_field(const Json& value, std::string_view key)
        {
            const auto found = value.find(std::string(key));
            if (found == value.end() || !found->is_number_integer() ||
                (!found->is_number_unsigned() && found->get<std::int64_t>() < 0))
                throw FixtureError("manifest field " + std::string(key) + " must be an unsigned integer");
            return found->get<std::uint64_t>();
        }

        std::uint32_t u32_field(const Json& value, std::string_view key)
        {
            const auto result = unsigned_field(value, key);
            if (result > std::numeric_limits<std::uint32_t>::max())
                throw FixtureError("manifest integer is out of range: " + std::string(key));
            return static_cast<std::uint32_t>(result);
        }

        std::string path_string(const std::filesystem::path& path)
        {
            const auto value = path.u8string();
            return std::string(reinterpret_cast<const char*>(value.data()), value.size());
        }

        void check_status(NTSTATUS status, std::string_view operation)
        {
            if (status >= 0)
                return;
            std::ostringstream message;
            message << operation << " failed (NTSTATUS 0x" << std::hex << static_cast<std::uint32_t>(status) << ')';
            throw FixtureError(message.str());
        }

        bool valid_label(std::string_view label)
        {
            static const std::regex pattern("[A-Za-z0-9][A-Za-z0-9_.-]*");
            return std::regex_match(label.begin(), label.end(), pattern) && label != "." && label != "..";
        }

        Bytes fetch_bytes(std::string_view url, bool allow_network, const DownloadFn& downloader)
        {
            // The opt-in is enforced here as well as in the HTTP implementation. Tests may
            // inject transports, but an injected transport cannot bypass offline mode.
            if (!allow_network)
                throw NetworkDisabled("network disabled; rerun with --allow-network to download missing files");
            auto bytes = downloader ? downloader(url, true) : download(url, true);
            if (bytes.size() > max_download_bytes)
                throw FixtureError("download exceeds the 256 MiB fixture limit");
            return bytes;
        }

        std::string cached_pe_hash(const Json& previous)
        {
            auto digest = string_field(object_field(previous, "pe"), "sha256");
            return digest.empty() ? string_field(object_field(previous, "expected_pe"), "sha256") : digest;
        }

        std::string cached_pdb_hash(const Json& previous)
        {
            auto digest = string_field(previous, "expected_pdb_sha256");
            return digest.empty() ? string_field(object_field(previous, "pdb"), "sha256") : digest;
        }

        std::string utc_now()
        {
            SYSTEMTIME time{};
            GetSystemTime(&time);
            std::ostringstream result;
            result << std::setfill('0') << std::setw(4) << time.wYear << '-' << std::setw(2) << time.wMonth
                   << '-' << std::setw(2) << time.wDay << 'T' << std::setw(2) << time.wHour << ':'
                   << std::setw(2) << time.wMinute << ':' << std::setw(2) << time.wSecond << '.'
                   << std::setw(3) << time.wMilliseconds << "Z";
            return result.str();
        }

    } // namespace

    std::string sha256(std::span<const std::uint8_t> data)
    {
        if (data.size() > std::numeric_limits<ULONG>::max())
            throw FixtureError("SHA256 input is too large");
        struct HashHandles
        {
                Bytes object;
                BCRYPT_ALG_HANDLE provider = nullptr;
                BCRYPT_HASH_HANDLE hash = nullptr;
                ~HashHandles()
                {
                    if (hash)
                        BCryptDestroyHash(hash);
                    if (provider)
                        BCryptCloseAlgorithmProvider(provider, 0);
                }
        } handles;
        check_status(BCryptOpenAlgorithmProvider(&handles.provider, BCRYPT_SHA256_ALGORITHM, nullptr, 0),
                     "BCryptOpenAlgorithmProvider");
        ULONG object_size = 0, returned = 0;
        check_status(BCryptGetProperty(handles.provider, BCRYPT_OBJECT_LENGTH,
                                       reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size), &returned, 0),
                     "BCryptGetProperty");
        if (returned != sizeof(object_size) || object_size > 1024 * 1024)
            throw FixtureError("invalid BCrypt SHA256 object size");
        handles.object.resize(object_size);
        check_status(BCryptCreateHash(handles.provider, &handles.hash, handles.object.data(), object_size, nullptr, 0, 0),
                     "BCryptCreateHash");
        if (!data.empty())
            check_status(BCryptHashData(handles.hash, const_cast<PUCHAR>(data.data()), static_cast<ULONG>(data.size()), 0),
                         "BCryptHashData");
        std::array<std::uint8_t, 32> digest{};
        check_status(BCryptFinishHash(handles.hash, digest.data(), static_cast<ULONG>(digest.size()), 0),
                     "BCryptFinishHash");
        return hex_bytes(digest);
    }

    Json parse_pe(std::span<const std::uint8_t> data)
    {
        if (data.size() > max_download_bytes)
            throw FixtureError("PE exceeds the 256 MiB fixture limit");
        const View file(data);
        const auto mz = file.slice(0, 2);
        if (mz[0] != 'M' || mz[1] != 'Z')
            throw FixtureError("not a PE file: missing MZ signature");
        const auto pe = static_cast<std::size_t>(file.u32(0x3c));
        const auto signature = file.slice(pe, 4);
        if (signature[0] != 'P' || signature[1] != 'E' || signature[2] || signature[3])
            throw FixtureError("not a PE file: missing PE signature");
        const auto machine = file.u16(pe + 4);
        const auto section_count = file.u16(pe + 6);
        const auto timestamp = file.u32(pe + 8);
        const auto optional_size = file.u16(pe + 20);
        const auto optional_offset = pe + 24;
        const View optional(file.slice(optional_offset, optional_size));
        if (machine != 0x8664 || optional.u16(0) != 0x20b)
            throw FixtureError("the current fixture corpus requires x64 PE32+ (machine 0x8664)");
        const auto image_size = optional.u32(56);
        const auto headers_size = optional.u32(60);
        const auto checksum = optional.u32(64);
        if (optional.u32(108) < 7 || optional_size < 112 + 7 * 8)
            throw FixtureError("PE has no debug directory");
        const auto resource_rva = optional.u32(112 + 2 * 8);
        const auto resource_size = optional.u32(112 + 2 * 8 + 4);
        const auto debug_rva = optional.u32(112 + 6 * 8);
        const auto debug_size = optional.u32(112 + 6 * 8 + 4);
        struct Section
        {
                std::uint32_t address, raw_size, raw_offset;
        };
        std::vector<Section> sections;
        sections.reserve(section_count);
        for (std::size_t i = 0; i < section_count; ++i)
        {
            const auto offset = optional_offset + optional_size + i * 40;
            file.slice(offset, 40);
            sections.push_back({file.u32(offset + 12), file.u32(offset + 16), file.u32(offset + 20)});
        }
        const auto rva_offset = [&](std::uint32_t rva, std::size_t length) -> std::size_t
        {
            if (rva < headers_size && length <= static_cast<std::size_t>(headers_size) - rva)
            {
                file.slice(rva, length);
                return rva;
            }
            for (const auto& section : sections)
            {
                if (rva < section.address)
                    continue;
                const auto relative = static_cast<std::size_t>(rva - section.address);
                if (relative <= section.raw_size && length <= section.raw_size - relative)
                {
                    const auto offset = static_cast<std::size_t>(section.raw_offset) + relative;
                    file.slice(offset, length);
                    return offset;
                }
            }
            throw FixtureError("PE RVA does not point to file-backed data");
        };
        if (!debug_rva || !debug_size || debug_size % 28)
            throw FixtureError("missing or malformed PE debug directory");
        const auto debug_offset = rva_offset(debug_rva, debug_size);
        Json identity;
        for (std::size_t relative = 0; relative < debug_size; relative += 28)
        {
            const auto offset = debug_offset + relative;
            if (file.u32(offset + 12) != 2)
                continue;
            const auto size = file.u32(offset + 16);
            const auto address = file.u32(offset + 20);
            const auto pointer = file.u32(offset + 24);
            const auto record = file.slice(pointer ? pointer : rva_offset(address, size), size);
            if (record.size() < 4 || !std::equal(record.begin(), record.begin() + 4, "RSDS"))
                continue;
            if (record.size() < 25)
                throw FixtureError("truncated RSDS debug record");
            const auto end = std::find(record.begin() + 24, record.end(), 0);
            if (end == record.end())
                throw FixtureError("RSDS PDB filename has no terminator");
            std::string name(record.begin() + 24, end);
            if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, name.data(), static_cast<int>(name.size()), nullptr, 0))
                throw FixtureError("RSDS PDB filename is not UTF-8");
            std::replace(name.begin(), name.end(), '\\', '/');
            if (const auto slash = name.rfind('/'); slash != std::string::npos)
                name.erase(0, slash + 1);
            static const std::regex pdb_name("[A-Za-z0-9_.-]+\\.pdb", std::regex::icase);
            if (!std::regex_match(name, pdb_name))
                throw FixtureError("unsafe or unsupported RSDS PDB filename");
            const View rsds(record);
            const Json current{{"name", name}, {"guid", guid_hex(rsds.slice(4, 16))}, {"age", rsds.u32(20)}};
            if (!identity.is_null() && identity != current)
                throw FixtureError("PE contains conflicting RSDS records");
            identity = current;
        }
        if (identity.is_null())
            throw FixtureError("PE has no RSDS PDB identity");

        Json version = nullptr;
        if (resource_rva && resource_size)
        {
            const auto root = rva_offset(resource_rva, resource_size);
            const View resources(file.slice(root, resource_size));
            const auto entries = [&](std::size_t relative)
            {
                resources.slice(relative, 16);
                const auto count = static_cast<std::size_t>(resources.u16(relative + 12)) + resources.u16(relative + 14);
                resources.slice(relative + 16, count * 8);
                std::vector<std::pair<std::uint32_t, std::uint32_t>> result;
                result.reserve(count);
                for (std::size_t i = 0; i < count; ++i)
                    result.emplace_back(resources.u32(relative + 16 + i * 8), resources.u32(relative + 20 + i * 8));
                return result;
            };
            std::function<std::optional<std::span<const std::uint8_t>>(std::size_t, unsigned)> first_leaf;
            first_leaf = [&](std::size_t relative, unsigned depth) -> std::optional<std::span<const std::uint8_t>>
            {
                if (depth > 3)
                    throw FixtureError("resource directory is cyclic or too deep");
                for (const auto& [_, child] : entries(relative))
                {
                    if (child & 0x80000000u)
                    {
                        const auto value = first_leaf(child & 0x7fffffffu, depth + 1);
                        if (value)
                            return value;
                    }
                    else
                    {
                        resources.slice(child, 16);
                        const auto rva = resources.u32(child), size = resources.u32(child + 4);
                        return file.slice(rva_offset(rva, size), size);
                    }
                }
                return {};
            };
            for (const auto& [type, child] : entries(0))
            {
                if (type != 16 || !(child & 0x80000000u))
                    continue;
                const auto leaf = first_leaf(child & 0x7fffffffu, 0);
                if (!leaf)
                    break;
                const View value(*leaf);
                const auto total = value.u16(0), length = value.u16(2);
                constexpr char16_t key[] = u"VS_VERSION_INFO";
                bool key_matches = value.size() >= 6 + sizeof(key);
                for (std::size_t i = 0; key_matches && i < std::size(key); ++i)
                    key_matches = value.u16(6 + i * 2) == key[i];
                if (total > value.size() || length < 52 || !key_matches)
                    throw FixtureError("malformed VS_VERSION_INFO");
                constexpr auto fixed_offset = (6 + sizeof(key) + 3) & ~std::size_t{3};
                if (fixed_offset > total || length > total - fixed_offset)
                    throw FixtureError("truncated VS_FIXEDFILEINFO");
                if (value.u32(fixed_offset) != 0xfeef04bdu)
                    throw FixtureError("invalid VS_FIXEDFILEINFO signature");
                const auto ms = value.u32(fixed_offset + 8), ls = value.u32(fixed_offset + 12);
                version = std::to_string(ms >> 16) + '.' + std::to_string(ms & 0xffff) + '.' +
                          std::to_string(ls >> 16) + '.' + std::to_string(ls & 0xffff);
                break;
            }
        }
        return Json{{"machine", machine}, {"timestamp", timestamp}, {"image_size", image_size}, {"file_size", data.size()}, {"checksum", checksum}, {"version", version}, {"sha256", sha256(data)}, {"pdb", identity}};
    }

    Json parse_pdb_identity(std::span<const std::uint8_t> data)
    {
        // Microsoft's PDB1::OpenValidate4 permits Info age >= image age while the
        // DBI age must equal image age (zero is its explicit old-PDB exception):
        // https://github.com/microsoft/microsoft-pdb/blob/master/PDB/dbi/pdb.cpp
        if (data.size() > max_download_bytes)
            throw FixtureError("PDB exceeds the 256 MiB fixture limit");
        const View file(data);
        constexpr std::array<std::uint8_t, 32> magic{
            'M', 'i', 'c', 'r', 'o', 's', 'o', 'f', 't', ' ', 'C', '/', 'C', '+', '+', ' ', 'M', 'S', 'F', ' ',
            '7', '.', '0', '0', '\r', '\n', 0x1a, 'D', 'S', 0, 0, 0};
        const auto signature = file.slice(0, magic.size());
        if (!std::equal(signature.begin(), signature.end(), magic.begin()))
            throw FixtureError("PDB is not a supported MSF 7.0 file");
        const auto block_size = file.u32(32), free_map = file.u32(36), block_count = file.u32(40);
        const auto directory_size = file.u32(44), map_block = file.u32(52);
        if ((block_size != 512 && block_size != 1024 && block_size != 2048 && block_size != 4096) ||
            (free_map != 1 && free_map != 2))
            throw FixtureError("invalid PDB superblock");
        if (static_cast<std::uint64_t>(block_count) * block_size != data.size())
            throw FixtureError("PDB block count does not match file size");
        const auto block = [&](std::uint32_t index)
        {
            if (index >= block_count)
                throw FixtureError("PDB references an invalid block");
            return file.slice(static_cast<std::size_t>(index) * block_size, block_size);
        };
        const auto directory_blocks = (static_cast<std::uint64_t>(directory_size) + block_size - 1) / block_size;
        if (directory_size < 12 || directory_size > data.size() || directory_blocks * 4 > block_size)
            throw FixtureError("invalid or unsupported PDB stream directory size");
        const View map(block(map_block));
        Bytes directory;
        directory.reserve(directory_size);
        for (std::size_t i = 0; i < directory_blocks; ++i)
        {
            const auto bytes = block(map.u32(i * 4));
            const auto count = std::min<std::size_t>(bytes.size(), directory_size - directory.size());
            directory.insert(directory.end(), bytes.begin(), bytes.begin() + count);
        }
        const View streams(directory);
        const auto stream_count = streams.u32(0);
        if (stream_count < 4 || stream_count > (directory.size() - 4) / 4)
            throw FixtureError("PDB has no info/DBI stream or an invalid stream count");
        std::size_t cursor = 4 + static_cast<std::size_t>(stream_count) * 4;
        Bytes info, dbi;
        for (std::size_t stream = 0; stream < stream_count; ++stream)
        {
            const auto size = streams.u32(4 + stream * 4);
            const std::uint64_t count = size == 0xffffffffu ? 0 : (static_cast<std::uint64_t>(size) + block_size - 1) / block_size;
            if (count > (directory.size() - cursor) / 4)
                throw FixtureError("PDB stream directory is truncated");
            if (stream == 1 || stream == 3)
            {
                if (size == 0xffffffffu || size < (stream == 1 ? 28u : 64u) || size > data.size())
                    throw FixtureError(stream == 1 ? "PDB info stream is absent or truncated" : "PDB DBI stream is absent or truncated");
                auto& bytes = stream == 1 ? info : dbi;
                bytes.reserve(size);
                for (std::size_t i = 0; i < count; ++i)
                {
                    const auto page = block(streams.u32(cursor + i * 4));
                    const auto length = std::min<std::size_t>(page.size(), size - bytes.size());
                    bytes.insert(bytes.end(), page.begin(), page.begin() + length);
                }
            }
            cursor += static_cast<std::size_t>(count) * 4;
        }
        const View info_view(info), dbi_view(dbi);
        if (dbi_view.u32(0) != 0xffffffffu)
            throw FixtureError("PDB has an unsupported legacy DBI header");
        return Json{{"guid", guid_hex(info_view.slice(12, 16))}, {"age", info_view.u32(8)}, {"dbi_age", dbi_view.u32(8)}, {"dbi_version", dbi_view.u32(4)}, {"sha256", sha256(data)}, {"file_size", data.size()}};
    }

    Json validate_pe(std::span<const std::uint8_t> data, const Json& expected)
    {
        if (!expected.is_object())
            throw FixtureError("PE pin must be an object");
        const auto actual = parse_pe(data);
        for (const auto* key : {"machine", "timestamp", "image_size", "file_size", "version", "sha256", "checksum"})
        {
            const auto found = expected.find(key);
            if (found != expected.end() && !found->is_null() && *found != actual.at(key))
                throw FixtureError(std::string("DLL ") + key + " mismatch: expected " + found->dump() + ", got " + actual.at(key).dump());
        }
        if (expected.contains("pdb"))
        {
            const auto identity = object_field(expected, "pdb");
            for (const auto* key : {"guid", "age", "name"})
                if (identity.contains(key) && identity.at(key) != actual.at("pdb").at(key))
                    throw FixtureError(std::string("DLL PDB ") + key + " mismatch");
        }
        return actual;
    }

    Json validate_pdb(std::span<const std::uint8_t> data, const Json& image_identity, std::string_view expected_hash)
    {
        const auto actual = parse_pdb_identity(data);
        const auto age = u32_field(image_identity, "age"), dbi_age = u32_field(actual, "dbi_age");
        if (string_field(actual, "guid") != string_field(image_identity, "guid") ||
            u32_field(actual, "age") < age || (dbi_age != 0 && dbi_age != age))
            throw FixtureError("PDB GUID/age does not match the DLL RSDS record");
        if (!expected_hash.empty() && string_field(actual, "sha256") != expected_hash)
            throw FixtureError("PDB SHA256 mismatch");
        return actual;
    }

    std::string dll_url(const Json& identity)
    {
        std::ostringstream key;
        key << std::hex << std::uppercase << std::setfill('0') << std::setw(8) << u32_field(identity, "timestamp")
            << std::nouppercase << u32_field(identity, "image_size");
        return std::string(symbol_server) + "/ntdll.dll/" + key.str() + "/ntdll.dll";
    }

    std::string pdb_url(const Json& identity)
    {
        const auto name = string_field(identity, "name"), guid = string_field(identity, "guid");
        static const std::regex safe_name("[A-Za-z0-9_.-]+\\.pdb", std::regex::icase), safe_guid("[A-F0-9]{32}");
        if (!std::regex_match(name, safe_name) || !std::regex_match(guid, safe_guid))
            throw FixtureError("unsafe PDB symbol-server identity");
        std::ostringstream age;
        age << std::hex << std::uppercase << u32_field(identity, "age");
        return std::string(symbol_server) + '/' + name + '/' + guid + age.str() + '/' + name;
    }

    Bytes read_file(const std::filesystem::path& path, std::size_t max_bytes)
    {
        const auto size = std::filesystem::file_size(path);
        if (size > max_bytes || size > std::numeric_limits<std::size_t>::max())
            throw FixtureError("file exceeds the configured size limit: " + path_string(path));
        std::ifstream input(path, std::ios::binary);
        if (!input)
            throw std::runtime_error("cannot open file: " + path_string(path));
        Bytes bytes(static_cast<std::size_t>(size));
        if (!bytes.empty())
            input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        if ((!bytes.empty() && input.gcount() != static_cast<std::streamsize>(bytes.size())) || input.peek() != EOF)
            throw FixtureError("file changed size or was truncated while reading: " + path_string(path));
        return bytes;
    }

    Json read_json(const std::filesystem::path& path)
    {
        const auto bytes = read_file(path);
        try
        {
            return Json::parse(bytes.begin(), bytes.end());
        }
        catch (const Json::exception& error)
        {
            throw FixtureError("invalid JSON in " + path_string(path) + ": " + error.what());
        }
    }

    Json atomic_write(const std::filesystem::path& path, std::span<const std::uint8_t> data, const FileValidator& validator)
    {
        const auto result = validator ? validator(data) : Json(nullptr);
        auto parent = path.parent_path();
        if (parent.empty())
            parent = ".";
        std::filesystem::create_directories(parent);
        std::array<std::uint8_t, 16> random{};
        check_status(BCryptGenRandom(nullptr, random.data(), static_cast<ULONG>(random.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG),
                     "BCryptGenRandom");
        const auto temporary = parent / (path.filename().native() + std::filesystem::path("." + hex_bytes(random) + ".part").native());
        struct Temporary
        {
                std::filesystem::path path;
                HANDLE file = INVALID_HANDLE_VALUE;
                ~Temporary()
                {
                    if (file != INVALID_HANDLE_VALUE)
                        CloseHandle(file);
                    std::error_code ignored;
                    std::filesystem::remove(path, ignored);
                }
        } output{temporary};
        output.file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (output.file == INVALID_HANDLE_VALUE)
            throw std::system_error(GetLastError(), std::system_category(), "create temporary fixture");
        std::size_t written = 0;
        while (written < data.size())
        {
            const auto count = static_cast<DWORD>(std::min<std::size_t>(data.size() - written, 1024 * 1024));
            DWORD actual = 0;
            if (!WriteFile(output.file, data.data() + written, count, &actual, nullptr) || actual != count)
                throw std::system_error(GetLastError(), std::system_category(), "write temporary fixture");
            written += actual;
        }
        if (!FlushFileBuffers(output.file))
            throw std::system_error(GetLastError(), std::system_category(), "flush temporary fixture");
        if (!CloseHandle(output.file))
            throw std::system_error(GetLastError(), std::system_category(), "close temporary fixture");
        output.file = INVALID_HANDLE_VALUE;
        if (!MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
            throw std::system_error(GetLastError(), std::system_category(), "replace validated fixture");
        return result;
    }

    void write_json(const std::filesystem::path& path, const Json& value)
    {
        const auto text = value.dump(2) + '\n';
        atomic_write(path, std::span(reinterpret_cast<const std::uint8_t*>(text.data()), text.size()));
    }

    Json ensure_file(const std::filesystem::path& path, std::string_view url, const FileValidator& validator,
                     bool allow_network, const DownloadFn& downloader)
    {
        if (std::filesystem::exists(path))
        {
            try
            {
                return validator(read_file(path));
            }
            catch (const FixtureError&)
            {
                if (!allow_network)
                    throw;
            }
        }
        const auto bytes = fetch_bytes(url, allow_network, downloader);
        return atomic_write(path, bytes, validator);
    }

    void validate_archive_config(const Json& archive)
    {
        if (!archive.is_object())
            throw FixtureError("archive configuration must be an object");
        static const std::regex blob("https://mcr\\.microsoft\\.com/v2/windows/nanoserver/blobs/sha256:([a-f0-9]{64})");
        const auto url = string_field(archive, "url");
        std::smatch match;
        if (!std::regex_match(url, match, blob) || string_field(archive, "sha256") != match[1].str())
            throw FixtureError("archive URL must be a Microsoft Nano Server blob with the pinned SHA256");
        const auto size = unsigned_field(archive, "file_size");
        if (!size || size > max_download_bytes)
            throw FixtureError("archive file_size must be within the 256 MiB download limit");
        if (string_field(archive, "format") != "tar.gz")
            throw FixtureError("only tar.gz fixture archives are supported");
        const auto member = string_field(archive, "member");
        if (member.empty() || member.front() == '/' || member.back() == '/' || member.find('\\') != std::string::npos ||
            member.find(':') != std::string::npos || member.find('\0') != std::string::npos)
            throw FixtureError("unsafe archive member path");
        std::size_t begin = 0;
        while (begin < member.size())
        {
            const auto end = member.find('/', begin);
            const auto part = member.substr(begin, end == std::string::npos ? end : end - begin);
            if (part.empty() || part == "." || part == "..")
                throw FixtureError("unsafe archive member path");
            if (end == std::string::npos)
                break;
            begin = end + 1;
        }
    }

    Json validate_archive(std::span<const std::uint8_t> data, const Json& archive)
    {
        if (data.size() != unsigned_field(archive, "file_size"))
            throw FixtureError("archive file_size mismatch");
        const auto digest = sha256(data);
        if (digest != string_field(archive, "sha256"))
            throw FixtureError("archive SHA256 mismatch");
        return Json{{"sha256", digest}, {"file_size", data.size()}};
    }

    Json ensure_image_file(const std::filesystem::path& path, const Json& expected, const Json& archive,
                           const std::filesystem::path& output_root, bool allow_network, const DownloadFn& downloader)
    {
        const FileValidator check = [&](std::span<const std::uint8_t> bytes)
        { return validate_pe(bytes, expected); };
        const bool has_archive = !archive.is_null() && !archive.empty();
        if (std::filesystem::exists(path))
        {
            try
            {
                return check(read_file(path));
            }
            catch (const FixtureError&)
            {
                if (!has_archive && !allow_network)
                    throw;
            }
        }
        if (!has_archive)
            return ensure_file(path, dll_url(expected), check, allow_network, downloader);
        validate_archive_config(archive);
        const auto archive_path = output_root.parent_path() / "archives" / (string_field(archive, "sha256") + ".tar.gz");
        ensure_file(archive_path, string_field(archive, "url"), [&](std::span<const std::uint8_t> bytes)
                    { return validate_archive(bytes, archive); }, allow_network, downloader);
        const auto payload = read_archive_member(archive_path, string_field(archive, "member"), max_dll_bytes, max_archive_unpacked_bytes);
        return atomic_write(path, payload, check);
    }

    Json process_fixture(const Json& entry, const std::filesystem::path& output_root, bool allow_network,
                         const std::optional<std::filesystem::path>& source_dll,
                         const std::optional<std::filesystem::path>& source_pdb, const DownloadFn& downloader)
    {
        const auto label = string_field(entry, "label");
        if (!valid_label(label))
            throw FixtureError("invalid fixture label");
        const auto folder = output_root / label;
        const auto dll_path = folder / "ntdll.dll", pdb_path = folder / "ntdll.pdb", previous_path = folder / "manifest.json";
        Json result{{"label", label}, {"target_os", entry.value("target_os", Json(nullptr))}, {"provenance", object_field(entry, "provenance")}, {"status", "missing"}};
        Json previous = std::filesystem::exists(previous_path) ? read_json(previous_path) : Json::object();
        auto previous_pe_hash = cached_pe_hash(previous);
        Json expected = entry.value("pe", Json(nullptr));
        if (source_dll)
        {
            const auto bytes = read_file(*source_dll, max_dll_bytes);
            const auto imported = validate_pe(bytes, expected.is_null() ? Json::object() : expected);
            if (expected.is_null())
            {
                expected = Json::object();
                for (const auto* key : {"machine", "timestamp", "image_size", "file_size", "version", "sha256"})
                    expected[key] = imported.at(key);
            }
            if (previous_pe_hash != string_field(imported, "sha256"))
            {
                previous = Json::object();
                previous_pe_hash.clear();
            }
            atomic_write(dll_path, bytes, [&](std::span<const std::uint8_t> value)
                         { return validate_pe(value, expected); });
            result["source_dll"] = path_string(std::filesystem::absolute(*source_dll));
        }
        if (expected.is_null())
        {
            result["reason"] = string_field(entry, "reason", "no pinned PE identity; import a DLL with --dll");
            write_json(previous_path, result);
            return result;
        }
        if (!expected.is_object())
            throw FixtureError("PE pin must be an object");
        Json effective = expected;
        if (string_field(effective, "sha256").empty() && !previous_pe_hash.empty())
            effective["sha256"] = previous_pe_hash;
        result["expected_pe"] = effective;
        auto previous_pdb_hash = cached_pdb_hash(previous);
        if (previous_pe_hash != string_field(effective, "sha256"))
            previous_pdb_hash.clear();
        auto expected_pdb_hash = string_field(entry, "pdb_sha256", previous_pdb_hash);
        if (expected_pdb_hash.empty())
            expected_pdb_hash = previous_pdb_hash;
        if (!expected_pdb_hash.empty())
            result["expected_pdb_sha256"] = expected_pdb_hash;
        const Json archive = entry.value("dll_archive", Json(nullptr));
        result["dll_url"] = archive.is_object() ? string_field(archive, "url") : dll_url(effective);
        if (!archive.is_null() && !archive.empty())
            result["dll_archive"] = archive;
        try
        {
            const auto image = ensure_image_file(dll_path, effective, archive, output_root, allow_network, downloader);
            result["pe"] = image;
            result["dll"] = path_string(std::filesystem::absolute(dll_path));
            result["pdb_url"] = pdb_url(image.at("pdb"));
            const FileValidator check = [&](std::span<const std::uint8_t> bytes)
            {
                return validate_pdb(bytes, image.at("pdb"), expected_pdb_hash);
            };
            if (source_pdb)
                atomic_write(pdb_path, read_file(*source_pdb), check);
            const auto symbols = ensure_file(pdb_path, string_field(result, "pdb_url"), check, allow_network, downloader);
            result["pdb"] = symbols;
            result["expected_pdb_sha256"] = symbols.at("sha256");
            result["pdb_file"] = path_string(std::filesystem::absolute(pdb_path));
            result["status"] = "ready";
        }
        catch (const std::exception& error)
        {
            const bool invalid = dynamic_cast<const FixtureError*>(&error) && !dynamic_cast<const NetworkDisabled*>(&error);
            result["status"] = invalid || (std::filesystem::exists(dll_path) && std::filesystem::exists(pdb_path)) ? "invalid" : "missing";
            result["reason"] = error.what();
        }
        write_json(previous_path, result);
        return result;
    }

    void refresh_client_pins(Json& manifest, std::span<const std::uint8_t> metadata)
    {
        Json index;
        try
        {
            const auto decoded = gzip_decompress(Bytes(metadata.begin(), metadata.end()));
            index = Json::parse(decoded.begin(), decoded.end());
        }
        catch (const std::exception& error)
        {
            throw FixtureError(std::string("invalid Winbindex gzip JSON: ") + error.what());
        }
        if (!index.is_object())
            throw FixtureError("Winbindex index must be an object");
        const auto metadata_hash = sha256(metadata);
        static const std::regex version_pattern("^([0-9]+)\\.([0-9]+)\\.([0-9]+)\\.([0-9]+)"), digest_pattern("[a-f0-9]{64}");
        struct Candidate
        {
                std::array<std::uint64_t, 4> version_tuple;
                std::string digest, version;
                Json record;
        };
        for (auto& entry : manifest.at("fixtures"))
        {
            const auto selector = object_field(entry, "winbindex_selector");
            if (selector.empty())
                continue;
            const auto windows_version = string_field(selector, "windows_version");
            const auto prefix = string_field(selector, "version_prefix");
            const auto selected_version = string_field(selector, "version");
            std::vector<Candidate> candidates;
            for (const auto& [digest, record] : index.items())
            {
                const auto info = object_field(record, "fileInfo");
                const auto windows = object_field(record, "windowsVersions");
                const auto raw_version = string_field(info, "version");
                std::smatch match;
                if (!std::regex_match(digest, digest_pattern) || !info.contains("machineType") ||
                    info.at("machineType") != 0x8664 || !info.contains("virtualSize") || info.at("virtualSize") == 0 ||
                    !windows.contains(windows_version) || !std::regex_search(raw_version, match, version_pattern))
                    continue;
                const auto version = match[0].str();
                if (!version.starts_with(prefix) || (!selected_version.empty() && version != selected_version))
                    continue;
                std::array<std::uint64_t, 4> tuple{};
                try
                {
                    for (std::size_t i = 0; i < tuple.size(); ++i)
                        tuple[i] = std::stoull(match[i + 1].str());
                }
                catch (const std::exception&)
                {
                    continue;
                }
                candidates.push_back({tuple, digest, version, record});
            }
            if (candidates.empty())
            {
                entry.erase("pe");
                entry["reason"] = "no Winbindex x64 record matches the explicit OS/build selector";
                continue;
            }
            const auto candidate = *std::min_element(candidates.begin(), candidates.end(), [](const auto& a, const auto& b)
                                                     { return a.version_tuple != b.version_tuple ? a.version_tuple < b.version_tuple : a.digest < b.digest; });
            const auto& info = candidate.record.at("fileInfo");
            const auto digest = string_field(info, "sha256", candidate.digest);
            if (!std::regex_match(digest, digest_pattern))
                throw FixtureError("invalid Winbindex SHA256");
            if (string_field(object_field(entry, "pe"), "sha256") != digest)
                entry.erase("pdb_sha256");
            entry["pe"] = Json{{"machine", u32_field(info, "machineType")}, {"timestamp", u32_field(info, "timestamp")}, {"image_size", u32_field(info, "virtualSize")}, {"file_size", unsigned_field(info, "size")}, {"version", candidate.version}, {"sha256", digest}};
            const auto windows = candidate.record.at("windowsVersions").at(windows_version);
            if (!windows.is_object() || windows.empty())
                throw FixtureError("Winbindex OS record has no update provenance");
            const auto update = windows.contains("BASE") ? std::string("BASE") : windows.begin().key();
            const auto origin = windows.at(update);
            Json provenance = object_field(entry, "provenance");
            provenance.update(Json{{"metadata_url", winbindex_url}, {"metadata_sha256", metadata_hash}, {"metadata_record_sha256", candidate.digest}, {"windows_version", windows_version}, {"update", update}, {"windows_version_info", origin.value("windowsVersionInfo", Json(nullptr))}, {"update_info", origin.value("updateInfo", Json(nullptr))}, {"source_paths", origin.value("sourcePaths", Json(nullptr))}});
            entry["provenance"] = provenance;
            entry.erase("reason");
        }
    }

    FetchResult process_manifest(const FetchOptions& options)
    {
        if (options.source_dll && options.labels.size() != 1)
            throw FixtureError("--dll requires exactly one --label");
        if (options.source_pdb && !options.source_dll)
            throw FixtureError("--pdb requires --dll");
        if ((!options.source_url.empty() || !options.os.empty()) && !options.source_dll)
            throw FixtureError("--source-url and --os require --dll");
        if (options.source_dll && (options.refresh_winbindex || options.winbindex_metadata))
            throw FixtureError("--dll cannot be combined with a Winbindex manifest refresh");
        if (options.output_root.empty())
            throw FixtureError("output_root must be provided");
        Json manifest = options.source_dll ? Json{{"schema_version", 1}, {"fixtures", Json::array()}} : read_json(options.manifest_path);
        if (!manifest.is_object() || manifest.value("schema_version", Json(nullptr)) != 1 ||
            !manifest.contains("fixtures") || !manifest.at("fixtures").is_array())
            throw FixtureError("unsupported fixture manifest schema");
        if (options.refresh_winbindex || options.winbindex_metadata)
        {
            const auto metadata = options.winbindex_metadata ? read_file(*options.winbindex_metadata) : fetch_bytes(winbindex_url, options.allow_network, options.download);
            refresh_client_pins(manifest, metadata);
            write_json(options.manifest_path, manifest);
        }
        Json fixtures = Json::array();
        if (options.source_dll)
        {
            fixtures.push_back(Json{{"label", options.labels.front()},
                                    {"target_os", options.os.empty() ? Json(nullptr) : Json(options.os)},
                                    {"provenance", Json{{"kind", "local_import"},
                                                        {"source_url", options.source_url.empty() ? Json(nullptr) : Json(options.source_url)},
                                                        {"os_claim", options.os.empty() ? Json(nullptr) : Json(options.os)},
                                                        {"os_coverage", false},
                                                        {"note", "OS provenance is user supplied, not inferred from PE version."}}}});
        }
        else
        {
            std::set<std::string> unknown(options.labels.begin(), options.labels.end());
            std::set<std::string> manifest_labels;
            for (const auto& entry : manifest.at("fixtures"))
            {
                const auto label = string_field(entry, "label");
                if (!valid_label(label) || !manifest_labels.insert(label).second)
                    throw FixtureError("invalid or duplicate fixture label");
                if (options.labels.empty() || unknown.contains(label))
                {
                    fixtures.push_back(entry);
                    unknown.erase(label);
                }
            }
            // The generated per-label pin permits offline revalidation of local imports.
            for (auto it = unknown.begin(); it != unknown.end();)
            {
                const auto label = *it;
                if (!valid_label(label))
                {
                    ++it;
                    continue;
                }
                const auto cached_path = options.output_root / label / "manifest.json";
                if (!std::filesystem::exists(cached_path))
                {
                    ++it;
                    continue;
                }
                const auto cached = read_json(cached_path);
                Json expected = object_field(cached, "pe");
                if (expected.empty())
                    expected = object_field(cached, "expected_pe");
                if (string_field(cached, "label") != label || expected.empty())
                {
                    ++it;
                    continue;
                }
                fixtures.push_back(Json{{"label", label}, {"target_os", cached.value("target_os", Json(nullptr))}, {"provenance", object_field(cached, "provenance")}, {"pe", expected}, {"dll_archive", cached.value("dll_archive", Json(nullptr))}, {"pdb_sha256", cached_pdb_hash(cached)}});
                it = unknown.erase(it);
            }
            if (!unknown.empty())
            {
                std::string message = "unknown fixture labels: ";
                for (const auto& label : unknown)
                    message += (message.back() == ' ' ? "" : ", ") + label;
                throw FixtureError(message);
            }
        }
        FetchResult result;
        result.successful = true;
        for (const auto& entry : fixtures)
        {
            const auto fixture = process_fixture(entry, options.output_root, options.allow_network,
                                                 options.source_dll, options.source_pdb, options.download);
            const auto status = string_field(fixture, "status");
            if (status != "ready" && !(options.allow_missing && status == "missing"))
                result.successful = false;
            result.fixtures.push_back(fixture);
        }
        const auto aggregate_path = options.output_root / "manifest.json";
        Json previous = std::filesystem::exists(aggregate_path) ? read_json(aggregate_path) : Json::object();
        std::map<std::string, Json> combined;
        if (previous.contains("fixtures"))
        {
            if (!previous.at("fixtures").is_array())
                throw FixtureError("invalid aggregate fixture list");
            for (const auto& entry : previous.at("fixtures"))
                combined[string_field(entry, "label")] = entry;
        }
        for (const auto& entry : result.fixtures)
            combined[string_field(entry, "label")] = entry;
        Json all = Json::array();
        for (const auto& [_, entry] : combined)
            all.push_back(entry);
        write_json(aggregate_path, Json{{"schema_version", 1}, {"generated_at_utc", utc_now()}, {"fixtures", all}});
        return result;
    }

} // namespace pdb_stuff
