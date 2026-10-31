#include <pdb_stuff/fixtures.h>
#include <pdb_stuff/io.h>
#include <symfind/compat.h>

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

namespace pdbStuff
{
    namespace
    {

        class View
        {
            public:
                explicit View(nonstd::span<const std::uint8_t> bytes) : m_bytes(bytes)
                {
                }
                nonstd::span<const std::uint8_t> Slice(std::size_t offset, std::size_t size) const
                {
                    if (offset > m_bytes.size() || size > m_bytes.size() - offset)
                    {
                        throw FixtureError("file range is outside the file");
                    }
                    return m_bytes.subspan(offset, size);
                }
                std::uint16_t U16(std::size_t offset) const
                {
                    return Number<std::uint16_t>(offset);
                }
                std::uint32_t U32(std::size_t offset) const
                {
                    return Number<std::uint32_t>(offset);
                }
                std::size_t Size() const
                {
                    return m_bytes.size();
                }

            private:
                template <class T> T Number(std::size_t offset) const
                {
                    const auto bytes = Slice(offset, sizeof(T));
                    T result = 0;
                    for (std::size_t i = 0; i < sizeof(T); ++i)
                    {
                        result |= static_cast<T>(bytes[i]) << (8 * i);
                    }
                    return result;
                }
                nonstd::span<const std::uint8_t> m_bytes;
        };

        std::string HexBytes(nonstd::span<const std::uint8_t> bytes, bool uppercase = false)
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

        std::string GuidHex(nonstd::span<const std::uint8_t> bytes)
        {
            if (bytes.size() != 16)
            {
                throw FixtureError("invalid GUID length");
            }
            std::array<std::uint8_t, 16> ordered{};
            constexpr std::array<std::size_t, 16> order{3, 2, 1,  0,  5,  4,  7,  6,
                                                        8, 9, 10, 11, 12, 13, 14, 15};
            for (std::size_t i = 0; i < ordered.size(); ++i)
            {
                ordered[i] = bytes[order[i]];
            }
            return HexBytes(ordered, true);
        }

        std::string StringField(const Json& value, std::string_view key, std::string fallback = {})
        {
            if (!value.is_object())
            {
                return fallback;
            }
            const auto found = value.find(std::string(key));
            if (found == value.end() || found->is_null())
            {
                return fallback;
            }
            if (!found->is_string())
            {
                throw FixtureError("manifest field " + std::string(key) + " must be a string");
            }
            return found->get<std::string>();
        }

        Json ObjectField(const Json& value, std::string_view key)
        {
            if (!value.is_object())
            {
                return Json::object();
            }
            const auto found = value.find(std::string(key));
            if (found == value.end() || found->is_null())
            {
                return Json::object();
            }
            if (!found->is_object())
            {
                throw FixtureError("manifest field " + std::string(key) + " must be an object");
            }
            return *found;
        }

        std::uint64_t UnsignedField(const Json& value, std::string_view key)
        {
            const auto found = value.find(std::string(key));
            if (found == value.end() || !found->is_number_integer() ||
                (!found->is_number_unsigned() && found->get<std::int64_t>() < 0))
            {
                throw FixtureError("manifest field " + std::string(key) +
                                   " must be an unsigned integer");
            }
            return found->get<std::uint64_t>();
        }

        std::uint32_t U32Field(const Json& value, std::string_view key)
        {
            const auto result = UnsignedField(value, key);
            if (result > std::numeric_limits<std::uint32_t>::max())
            {
                throw FixtureError("manifest integer is out of range: " + std::string(key));
            }
            return static_cast<std::uint32_t>(result);
        }

        std::string PathString(const std::filesystem::path& path)
        {
            return path.u8string();
        }

        void CheckStatus(NTSTATUS status, std::string_view operation)
        {
            if (status >= 0)
            {
                return;
            }
            std::ostringstream message;
            message << operation << " failed (NTSTATUS 0x" << std::hex
                    << static_cast<std::uint32_t>(status) << ')';
            throw FixtureError(message.str());
        }

        bool ValidLabel(std::string_view label)
        {
            static const std::regex pattern("[A-Za-z0-9][A-Za-z0-9_.-]*");
            return std::regex_match(label.begin(), label.end(), pattern) && label != "." &&
                   label != "..";
        }

        Bytes FetchBytes(std::string_view url, bool allowNetwork, const DownloadFn& downloader)
        {
            // The opt-in is enforced here as well as in the HTTP implementation. Tests may
            // inject transports, but an injected transport cannot bypass offline mode.
            if (!allowNetwork)
            {
                throw NetworkDisabled(
                    "network disabled; rerun with --allow-network to download missing files");
            }
            auto bytes = downloader ? downloader(url, true) : Download(url, true);
            if (bytes.size() > maxDownloadBytes)
            {
                throw FixtureError("download exceeds the 256 MiB fixture limit");
            }
            return bytes;
        }

        std::string CachedPeHash(const Json& previous)
        {
            auto digest = StringField(ObjectField(previous, "pe"), "sha256");
            return digest.empty() ? StringField(ObjectField(previous, "expected_pe"), "sha256")
                                  : digest;
        }

        std::string CachedPdbHash(const Json& previous)
        {
            auto digest = StringField(previous, "expected_pdb_sha256");
            return digest.empty() ? StringField(ObjectField(previous, "pdb"), "sha256") : digest;
        }

        std::string UtcNow()
        {
            SYSTEMTIME time{};
            GetSystemTime(&time);
            std::ostringstream result;
            result << std::setfill('0') << std::setw(4) << time.wYear << '-' << std::setw(2)
                   << time.wMonth << '-' << std::setw(2) << time.wDay << 'T' << std::setw(2)
                   << time.wHour << ':' << std::setw(2) << time.wMinute << ':' << std::setw(2)
                   << time.wSecond << '.' << std::setw(3) << time.wMilliseconds << "Z";
            return result.str();
        }

    } // namespace

    std::string Sha256(nonstd::span<const std::uint8_t> data)
    {
        if (data.size() > std::numeric_limits<ULONG>::max())
        {
            throw FixtureError("SHA256 input is too large");
        }
        struct HashHandles
        {
                Bytes object;
                BCRYPT_ALG_HANDLE provider = nullptr;
                BCRYPT_HASH_HANDLE hash = nullptr;
                ~HashHandles()
                {
                    if (hash)
                    {
                        BCryptDestroyHash(hash);
                    }
                    if (provider)
                    {
                        BCryptCloseAlgorithmProvider(provider, 0);
                    }
                }
        } handles;
        CheckStatus(
            BCryptOpenAlgorithmProvider(&handles.provider, BCRYPT_SHA256_ALGORITHM, nullptr, 0),
            "BCryptOpenAlgorithmProvider");
        ULONG objectSize = 0, returned = 0;
        CheckStatus(BCryptGetProperty(handles.provider, BCRYPT_OBJECT_LENGTH,
                                      reinterpret_cast<PUCHAR>(&objectSize), sizeof(objectSize),
                                      &returned, 0),
                    "BCryptGetProperty");
        if (returned != sizeof(objectSize) || objectSize > 1024 * 1024)
        {
            throw FixtureError("invalid BCrypt SHA256 object size");
        }
        handles.object.resize(objectSize);
        CheckStatus(BCryptCreateHash(handles.provider, &handles.hash, handles.object.data(),
                                     objectSize, nullptr, 0, 0),
                    "BCryptCreateHash");
        if (!data.empty())
        {
            CheckStatus(BCryptHashData(handles.hash, const_cast<PUCHAR>(data.data()),
                                       static_cast<ULONG>(data.size()), 0),
                        "BCryptHashData");
        }
        std::array<std::uint8_t, 32> digest{};
        CheckStatus(
            BCryptFinishHash(handles.hash, digest.data(), static_cast<ULONG>(digest.size()), 0),
            "BCryptFinishHash");
        return HexBytes(digest);
    }

    Json ParsePe(nonstd::span<const std::uint8_t> data)
    {
        if (data.size() > maxDownloadBytes)
        {
            throw FixtureError("PE exceeds the 256 MiB fixture limit");
        }
        const View file(data);
        const auto mz = file.Slice(0, 2);
        if (mz[0] != 'M' || mz[1] != 'Z')
        {
            throw FixtureError("not a PE file: missing MZ signature");
        }
        const auto pe = static_cast<std::size_t>(file.U32(0x3c));
        const auto signature = file.Slice(pe, 4);
        if (signature[0] != 'P' || signature[1] != 'E' || signature[2] || signature[3])
        {
            throw FixtureError("not a PE file: missing PE signature");
        }
        const auto machine = file.U16(pe + 4);
        const auto sectionCount = file.U16(pe + 6);
        const auto timestamp = file.U32(pe + 8);
        const auto optionalSize = file.U16(pe + 20);
        const auto optionalOffset = pe + 24;
        const View optional(file.Slice(optionalOffset, optionalSize));
        if (machine != 0x8664 || optional.U16(0) != 0x20b)
        {
            throw FixtureError("the current fixture corpus requires x64 PE32+ (machine 0x8664)");
        }
        const auto imageSize = optional.U32(56);
        const auto headersSize = optional.U32(60);
        const auto checksum = optional.U32(64);
        if (optional.U32(108) < 7 || optionalSize < 112 + 7 * 8)
        {
            throw FixtureError("PE has no debug directory");
        }
        const auto resourceRva = optional.U32(112 + 2 * 8);
        const auto resourceSize = optional.U32(112 + 2 * 8 + 4);
        const auto debugRva = optional.U32(112 + 6 * 8);
        const auto debugSize = optional.U32(112 + 6 * 8 + 4);
        struct Section
        {
                std::uint32_t address, rawSize, rawOffset;
        };
        std::vector<Section> sections;
        sections.reserve(sectionCount);
        for (std::size_t i = 0; i < sectionCount; ++i)
        {
            const auto offset = optionalOffset + optionalSize + i * 40;
            file.Slice(offset, 40);
            sections.push_back(
                {file.U32(offset + 12), file.U32(offset + 16), file.U32(offset + 20)});
        }
        const auto rvaOffset = [&](std::uint32_t rva, std::size_t length) -> std::size_t
        {
            if (rva < headersSize && length <= static_cast<std::size_t>(headersSize) - rva)
            {
                file.Slice(rva, length);
                return rva;
            }
            for (const auto& section : sections)
            {
                if (rva < section.address)
                {
                    continue;
                }
                const auto relative = static_cast<std::size_t>(rva - section.address);
                if (relative <= section.rawSize && length <= section.rawSize - relative)
                {
                    const auto offset = static_cast<std::size_t>(section.rawOffset) + relative;
                    file.Slice(offset, length);
                    return offset;
                }
            }
            throw FixtureError("PE RVA does not point to file-backed data");
        };
        if (!debugRva || !debugSize || debugSize % 28)
        {
            throw FixtureError("missing or malformed PE debug directory");
        }
        const auto debugOffset = rvaOffset(debugRva, debugSize);
        Json identity;
        for (std::size_t relative = 0; relative < debugSize; relative += 28)
        {
            const auto offset = debugOffset + relative;
            if (file.U32(offset + 12) != 2)
            {
                continue;
            }
            const auto size = file.U32(offset + 16);
            const auto address = file.U32(offset + 20);
            const auto pointer = file.U32(offset + 24);
            const auto record = file.Slice(pointer ? pointer : rvaOffset(address, size), size);
            if (record.size() < 4 || !std::equal(record.begin(), record.begin() + 4, "RSDS"))
            {
                continue;
            }
            if (record.size() < 25)
            {
                throw FixtureError("truncated RSDS debug record");
            }
            const auto end = std::find(record.begin() + 24, record.end(), 0);
            if (end == record.end())
            {
                throw FixtureError("RSDS PDB filename has no terminator");
            }
            std::string name(record.begin() + 24, end);
            if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, name.data(),
                                     static_cast<int>(name.size()), nullptr, 0))
            {
                throw FixtureError("RSDS PDB filename is not UTF-8");
            }
            std::replace(name.begin(), name.end(), '\\', '/');
            if (const auto slash = name.rfind('/'); slash != std::string::npos)
            {
                name.erase(0, slash + 1);
            }
            static const std::regex pdbName("[A-Za-z0-9_.-]+\\.pdb", std::regex::icase);
            if (!std::regex_match(name, pdbName))
            {
                throw FixtureError("unsafe or unsupported RSDS PDB filename");
            }
            const View rsds(record);
            const Json current{
                {"name", name}, {"guid", GuidHex(rsds.Slice(4, 16))}, {"age", rsds.U32(20)}};
            if (!identity.is_null() && identity != current)
            {
                throw FixtureError("PE contains conflicting RSDS records");
            }
            identity = current;
        }
        if (identity.is_null())
        {
            throw FixtureError("PE has no RSDS PDB identity");
        }

        Json version = nullptr;
        if (resourceRva && resourceSize)
        {
            const auto root = rvaOffset(resourceRva, resourceSize);
            const View resources(file.Slice(root, resourceSize));
            const auto entries = [&](std::size_t relative)
            {
                resources.Slice(relative, 16);
                const auto count = static_cast<std::size_t>(resources.U16(relative + 12)) +
                                   resources.U16(relative + 14);
                resources.Slice(relative + 16, count * 8);
                std::vector<std::pair<std::uint32_t, std::uint32_t>> result;
                result.reserve(count);
                for (std::size_t i = 0; i < count; ++i)
                {
                    result.emplace_back(resources.U32(relative + 16 + i * 8),
                                        resources.U32(relative + 20 + i * 8));
                }
                return result;
            };
            std::function<std::optional<nonstd::span<const std::uint8_t>>(std::size_t, unsigned)>
                firstLeaf;
            firstLeaf = [&](std::size_t relative,
                            unsigned depth) -> std::optional<nonstd::span<const std::uint8_t>>
            {
                if (depth > 3)
                {
                    throw FixtureError("resource directory is cyclic or too deep");
                }
                for (const auto& [_, child] : entries(relative))
                {
                    if (child & 0x80000000u)
                    {
                        const auto value = firstLeaf(child & 0x7fffffffu, depth + 1);
                        if (value)
                        {
                            return value;
                        }
                    }
                    else
                    {
                        resources.Slice(child, 16);
                        const auto rva = resources.U32(child), size = resources.U32(child + 4);
                        return file.Slice(rvaOffset(rva, size), size);
                    }
                }
                return {};
            };
            for (const auto& [type, child] : entries(0))
            {
                if (type != 16 || !(child & 0x80000000u))
                {
                    continue;
                }
                const auto leaf = firstLeaf(child & 0x7fffffffu, 0);
                if (!leaf)
                {
                    break;
                }
                const View value(*leaf);
                const auto total = value.U16(0), length = value.U16(2);
                constexpr char16_t key[] = u"VS_VERSION_INFO";
                bool keyMatches = value.Size() >= 6 + sizeof(key);
                for (std::size_t i = 0; keyMatches && i < std::size(key); ++i)
                {
                    keyMatches = value.U16(6 + i * 2) == key[i];
                }
                if (total > value.Size() || length < 52 || !keyMatches)
                {
                    throw FixtureError("malformed VS_VERSION_INFO");
                }
                constexpr auto fixedOffset = (6 + sizeof(key) + 3) & ~std::size_t{3};
                if (fixedOffset > total || length > total - fixedOffset)
                {
                    throw FixtureError("truncated VS_FIXEDFILEINFO");
                }
                if (value.U32(fixedOffset) != 0xfeef04bdu)
                {
                    throw FixtureError("invalid VS_FIXEDFILEINFO signature");
                }
                const auto ms = value.U32(fixedOffset + 8), ls = value.U32(fixedOffset + 12);
                version = std::to_string(ms >> 16) + '.' + std::to_string(ms & 0xffff) + '.' +
                          std::to_string(ls >> 16) + '.' + std::to_string(ls & 0xffff);
                break;
            }
        }
        return Json{{"machine", machine},       {"timestamp", timestamp}, {"image_size", imageSize},
                    {"file_size", data.size()}, {"checksum", checksum},   {"version", version},
                    {"sha256", Sha256(data)},   {"pdb", identity}};
    }

    Json ParsePdbIdentity(nonstd::span<const std::uint8_t> data)
    {
        // Microsoft's PDB1::OpenValidate4 permits Info age >= image age while the
        // DBI age must equal image age (zero is its explicit old-PDB exception):
        // https://github.com/microsoft/microsoft-pdb/blob/master/PDB/dbi/pdb.cpp
        if (data.size() > maxDownloadBytes)
        {
            throw FixtureError("PDB exceeds the 256 MiB fixture limit");
        }
        const View file(data);
        constexpr std::array<std::uint8_t, 32> magic{
            'M', 'i', 'c', 'r', 'o', 's', 'o', 'f', 't',  ' ',  'C',  '/', 'C', '+', '+', ' ',
            'M', 'S', 'F', ' ', '7', '.', '0', '0', '\r', '\n', 0x1a, 'D', 'S', 0,   0,   0};
        const auto signature = file.Slice(0, magic.size());
        if (!std::equal(signature.begin(), signature.end(), magic.begin()))
        {
            throw FixtureError("PDB is not a supported MSF 7.0 file");
        }
        const auto blockSize = file.U32(32), freeMap = file.U32(36), blockCount = file.U32(40);
        const auto directorySize = file.U32(44), mapBlock = file.U32(52);
        if ((blockSize != 512 && blockSize != 1024 && blockSize != 2048 && blockSize != 4096) ||
            (freeMap != 1 && freeMap != 2))
        {
            throw FixtureError("invalid PDB superblock");
        }
        if (static_cast<std::uint64_t>(blockCount) * blockSize != data.size())
        {
            throw FixtureError("PDB block count does not match file size");
        }
        const auto block = [&](std::uint32_t index)
        {
            if (index >= blockCount)
            {
                throw FixtureError("PDB references an invalid block");
            }
            return file.Slice(static_cast<std::size_t>(index) * blockSize, blockSize);
        };
        const auto directoryBlocks =
            (static_cast<std::uint64_t>(directorySize) + blockSize - 1) / blockSize;
        if (directorySize < 12 || directorySize > data.size() || directoryBlocks * 4 > blockSize)
        {
            throw FixtureError("invalid or unsupported PDB stream directory size");
        }
        const View map(block(mapBlock));
        Bytes directory;
        directory.reserve(directorySize);
        for (std::size_t i = 0; i < directoryBlocks; ++i)
        {
            const auto bytes = block(map.U32(i * 4));
            const auto count =
                std::min<std::size_t>(bytes.size(), directorySize - directory.size());
            directory.insert(directory.end(), bytes.begin(), bytes.begin() + count);
        }
        const View streams(directory);
        const auto streamCount = streams.U32(0);
        if (streamCount < 4 || streamCount > (directory.size() - 4) / 4)
        {
            throw FixtureError("PDB has no info/DBI stream or an invalid stream count");
        }
        std::size_t cursor = 4 + static_cast<std::size_t>(streamCount) * 4;
        Bytes info, dbi;
        for (std::size_t stream = 0; stream < streamCount; ++stream)
        {
            const auto size = streams.U32(4 + stream * 4);
            const std::uint64_t count =
                size == 0xffffffffu
                    ? 0
                    : (static_cast<std::uint64_t>(size) + blockSize - 1) / blockSize;
            if (count > (directory.size() - cursor) / 4)
            {
                throw FixtureError("PDB stream directory is truncated");
            }
            if (stream == 1 || stream == 3)
            {
                if (size == 0xffffffffu || size < (stream == 1 ? 28u : 64u) || size > data.size())
                {
                    throw FixtureError(stream == 1 ? "PDB info stream is absent or truncated"
                                                   : "PDB DBI stream is absent or truncated");
                }
                auto& bytes = stream == 1 ? info : dbi;
                bytes.reserve(size);
                for (std::size_t i = 0; i < count; ++i)
                {
                    const auto page = block(streams.U32(cursor + i * 4));
                    const auto length = std::min<std::size_t>(page.size(), size - bytes.size());
                    bytes.insert(bytes.end(), page.begin(), page.begin() + length);
                }
            }
            cursor += static_cast<std::size_t>(count) * 4;
        }
        const View infoView(info), dbiView(dbi);
        if (dbiView.U32(0) != 0xffffffffu)
        {
            throw FixtureError("PDB has an unsupported legacy DBI header");
        }
        return Json{{"guid", GuidHex(infoView.Slice(12, 16))},
                    {"age", infoView.U32(8)},
                    {"dbi_age", dbiView.U32(8)},
                    {"dbi_version", dbiView.U32(4)},
                    {"sha256", Sha256(data)},
                    {"file_size", data.size()}};
    }

    Json ValidatePe(nonstd::span<const std::uint8_t> data, const Json& expected)
    {
        if (!expected.is_object())
        {
            throw FixtureError("PE pin must be an object");
        }
        const auto actual = ParsePe(data);
        for (const auto* key :
             {"machine", "timestamp", "image_size", "file_size", "version", "sha256", "checksum"})
        {
            const auto found = expected.find(key);
            if (found != expected.end() && !found->is_null() && *found != actual.at(key))
            {
                throw FixtureError(std::string("DLL ") + key + " mismatch: expected " +
                                   found->dump() + ", got " + actual.at(key).dump());
            }
        }
        if (expected.contains("pdb"))
        {
            const auto identity = ObjectField(expected, "pdb");
            for (const auto* key : {"guid", "age", "name"})
            {
                if (identity.contains(key) && identity.at(key) != actual.at("pdb").at(key))
                {
                    throw FixtureError(std::string("DLL PDB ") + key + " mismatch");
                }
            }
        }
        return actual;
    }

    Json ValidatePdb(nonstd::span<const std::uint8_t> data, const Json& imageIdentity,
                     std::string_view expectedHash)
    {
        const auto actual = ParsePdbIdentity(data);
        const auto age = U32Field(imageIdentity, "age"), dbiAge = U32Field(actual, "dbi_age");
        if (StringField(actual, "guid") != StringField(imageIdentity, "guid") ||
            U32Field(actual, "age") < age || (dbiAge != 0 && dbiAge != age))
        {
            throw FixtureError("PDB GUID/age does not match the DLL RSDS record");
        }
        if (!expectedHash.empty() && StringField(actual, "sha256") != expectedHash)
        {
            throw FixtureError("PDB SHA256 mismatch");
        }
        return actual;
    }

    std::string DllUrl(const Json& identity)
    {
        std::ostringstream key;
        key << std::hex << std::uppercase << std::setfill('0') << std::setw(8)
            << U32Field(identity, "timestamp") << std::nouppercase
            << U32Field(identity, "image_size");
        return std::string(symbolServer) + "/ntdll.dll/" + key.str() + "/ntdll.dll";
    }

    std::string PdbUrl(const Json& identity)
    {
        const auto name = StringField(identity, "name"), guid = StringField(identity, "guid");
        static const std::regex safeName("[A-Za-z0-9_.-]+\\.pdb", std::regex::icase),
            safeGuid("[A-F0-9]{32}");
        if (!std::regex_match(name, safeName) || !std::regex_match(guid, safeGuid))
        {
            throw FixtureError("unsafe PDB symbol-server identity");
        }
        std::ostringstream age;
        age << std::hex << std::uppercase << U32Field(identity, "age");
        return std::string(symbolServer) + '/' + name + '/' + guid + age.str() + '/' + name;
    }

    Bytes ReadFile(const std::filesystem::path& path, std::size_t maxBytes)
    {
        const auto size = std::filesystem::file_size(path);
        if (size > maxBytes || size > std::numeric_limits<std::size_t>::max())
        {
            throw FixtureError("file exceeds the configured size limit: " + PathString(path));
        }
        std::ifstream input(path, std::ios::binary);
        if (!input)
        {
            throw std::runtime_error("cannot open file: " + PathString(path));
        }
        Bytes bytes(static_cast<std::size_t>(size));
        if (!bytes.empty())
        {
            input.read(reinterpret_cast<char*>(bytes.data()),
                       static_cast<std::streamsize>(bytes.size()));
        }
        if ((!bytes.empty() && input.gcount() != static_cast<std::streamsize>(bytes.size())) ||
            input.peek() != EOF)
        {
            throw FixtureError("file changed size or was truncated while reading: " +
                               PathString(path));
        }
        return bytes;
    }

    Json ReadJson(const std::filesystem::path& path)
    {
        const auto bytes = ReadFile(path);
        try
        {
            return Json::parse(bytes.begin(), bytes.end());
        }
        catch (const Json::exception& error)
        {
            throw FixtureError("invalid JSON in " + PathString(path) + ": " + error.what());
        }
    }

    Json AtomicWrite(const std::filesystem::path& path, nonstd::span<const std::uint8_t> data,
                     const FileValidator& validator)
    {
        const auto result = validator ? validator(data) : Json(nullptr);
        auto parent = path.parent_path();
        if (parent.empty())
        {
            parent = ".";
        }
        std::filesystem::create_directories(parent);
        std::array<std::uint8_t, 16> random{};
        CheckStatus(BCryptGenRandom(nullptr, random.data(), static_cast<ULONG>(random.size()),
                                    BCRYPT_USE_SYSTEM_PREFERRED_RNG),
                    "BCryptGenRandom");
        const auto temporary =
            parent / (path.filename().native() +
                      std::filesystem::path("." + HexBytes(random) + ".part").native());
        struct Temporary
        {
                std::filesystem::path path;
                HANDLE file = INVALID_HANDLE_VALUE;
                ~Temporary()
                {
                    if (file != INVALID_HANDLE_VALUE)
                    {
                        CloseHandle(file);
                    }
                    std::error_code ignored;
                    std::filesystem::remove(path, ignored);
                }
        } output{temporary};
        output.file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                                  FILE_ATTRIBUTE_NORMAL, nullptr);
        if (output.file == INVALID_HANDLE_VALUE)
        {
            throw std::system_error(GetLastError(), std::system_category(),
                                    "create temporary fixture");
        }
        std::size_t written = 0;
        while (written < data.size())
        {
            const auto count =
                static_cast<DWORD>(std::min<std::size_t>(data.size() - written, 1024 * 1024));
            DWORD actual = 0;
            if (!WriteFile(output.file, data.data() + written, count, &actual, nullptr) ||
                actual != count)
            {
                throw std::system_error(GetLastError(), std::system_category(),
                                        "write temporary fixture");
            }
            written += actual;
        }
        if (!FlushFileBuffers(output.file))
        {
            throw std::system_error(GetLastError(), std::system_category(),
                                    "flush temporary fixture");
        }
        if (!CloseHandle(output.file))
        {
            throw std::system_error(GetLastError(), std::system_category(),
                                    "close temporary fixture");
        }
        output.file = INVALID_HANDLE_VALUE;
        if (!MoveFileExW(temporary.c_str(), path.c_str(),
                         MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        {
            throw std::system_error(GetLastError(), std::system_category(),
                                    "replace validated fixture");
        }
        return result;
    }

    void WriteJson(const std::filesystem::path& path, const Json& value)
    {
        const auto text = value.dump(2) + '\n';
        AtomicWrite(path,
                    nonstd::span(reinterpret_cast<const std::uint8_t*>(text.data()), text.size()));
    }

    Json EnsureFile(const std::filesystem::path& path, std::string_view url,
                    const FileValidator& validator, bool allowNetwork, const DownloadFn& downloader)
    {
        if (std::filesystem::exists(path))
        {
            try
            {
                return validator(ReadFile(path));
            }
            catch (const FixtureError&)
            {
                if (!allowNetwork)
                {
                    throw;
                }
            }
        }
        const auto bytes = FetchBytes(url, allowNetwork, downloader);
        return AtomicWrite(path, bytes, validator);
    }

    void ValidateArchiveConfig(const Json& archive)
    {
        if (!archive.is_object())
        {
            throw FixtureError("archive configuration must be an object");
        }
        static const std::regex blob(
            "https://mcr\\.microsoft\\.com/v2/windows/nanoserver/blobs/sha256:([a-f0-9]{64})");
        const auto url = StringField(archive, "url");
        std::smatch match;
        if (!std::regex_match(url, match, blob) || StringField(archive, "sha256") != match[1].str())
        {
            throw FixtureError(
                "archive URL must be a Microsoft Nano Server blob with the pinned SHA256");
        }
        const auto size = UnsignedField(archive, "file_size");
        if (!size || size > maxDownloadBytes)
        {
            throw FixtureError("archive file_size must be within the 256 MiB download limit");
        }
        if (StringField(archive, "format") != "tar.gz")
        {
            throw FixtureError("only tar.gz fixture archives are supported");
        }
        const auto member = StringField(archive, "member");
        if (member.empty() || member.front() == '/' || member.back() == '/' ||
            member.find('\\') != std::string::npos || member.find(':') != std::string::npos ||
            member.find('\0') != std::string::npos)
        {
            throw FixtureError("unsafe archive member path");
        }
        std::size_t begin = 0;
        while (begin < member.size())
        {
            const auto end = member.find('/', begin);
            const auto part = member.substr(begin, end == std::string::npos ? end : end - begin);
            if (part.empty() || part == "." || part == "..")
            {
                throw FixtureError("unsafe archive member path");
            }
            if (end == std::string::npos)
            {
                break;
            }
            begin = end + 1;
        }
    }

    Json ValidateArchive(nonstd::span<const std::uint8_t> data, const Json& archive)
    {
        if (data.size() != UnsignedField(archive, "file_size"))
        {
            throw FixtureError("archive file_size mismatch");
        }
        const auto digest = Sha256(data);
        if (digest != StringField(archive, "sha256"))
        {
            throw FixtureError("archive SHA256 mismatch");
        }
        return Json{{"sha256", digest}, {"file_size", data.size()}};
    }

    Json EnsureImageFile(const std::filesystem::path& path, const Json& expected,
                         const Json& archive, const std::filesystem::path& outputRoot,
                         bool allowNetwork, const DownloadFn& downloader)
    {
        const FileValidator check = [&](nonstd::span<const std::uint8_t> bytes)
        {
            return ValidatePe(bytes, expected);
        };
        const bool hasArchive = !archive.is_null() && !archive.empty();
        if (std::filesystem::exists(path))
        {
            try
            {
                return check(ReadFile(path));
            }
            catch (const FixtureError&)
            {
                if (!hasArchive && !allowNetwork)
                {
                    throw;
                }
            }
        }
        if (!hasArchive)
        {
            return EnsureFile(path, DllUrl(expected), check, allowNetwork, downloader);
        }
        ValidateArchiveConfig(archive);
        const auto archivePath =
            outputRoot.parent_path() / "archives" / (StringField(archive, "sha256") + ".tar.gz");
        EnsureFile(
            archivePath, StringField(archive, "url"),
            [&](nonstd::span<const std::uint8_t> bytes)
            {
                return ValidateArchive(bytes, archive);
            },
            allowNetwork, downloader);
        const auto payload = ReadArchiveMember(archivePath, StringField(archive, "member"),
                                               maxDllBytes, maxArchiveUnpackedBytes);
        return AtomicWrite(path, payload, check);
    }

    Json ProcessFixture(const Json& entry, const std::filesystem::path& outputRoot,
                        bool allowNetwork, const std::optional<std::filesystem::path>& sourceDll,
                        const std::optional<std::filesystem::path>& sourcePdb,
                        const DownloadFn& downloader)
    {
        const auto label = StringField(entry, "label");
        if (!ValidLabel(label))
        {
            throw FixtureError("invalid fixture label");
        }
        const auto folder = outputRoot / label;
        const auto dllPath = folder / "ntdll.dll", pdbPath = folder / "ntdll.pdb",
                   previousPath = folder / "manifest.json";
        Json result{{"label", label},
                    {"target_os", entry.value("target_os", Json(nullptr))},
                    {"provenance", ObjectField(entry, "provenance")},
                    {"status", "missing"}};
        Json previous =
            std::filesystem::exists(previousPath) ? ReadJson(previousPath) : Json::object();
        auto previousPeHash = CachedPeHash(previous);
        Json expected = entry.value("pe", Json(nullptr));
        if (sourceDll)
        {
            const auto bytes = ReadFile(*sourceDll, maxDllBytes);
            const auto imported = ValidatePe(bytes, expected.is_null() ? Json::object() : expected);
            if (expected.is_null())
            {
                expected = Json::object();
                for (const auto* key :
                     {"machine", "timestamp", "image_size", "file_size", "version", "sha256"})
                {
                    expected[key] = imported.at(key);
                }
            }
            if (previousPeHash != StringField(imported, "sha256"))
            {
                previous = Json::object();
                previousPeHash.clear();
            }
            AtomicWrite(dllPath, bytes,
                        [&](nonstd::span<const std::uint8_t> value)
                        {
                            return ValidatePe(value, expected);
                        });
            result["source_dll"] = PathString(std::filesystem::absolute(*sourceDll));
        }
        if (expected.is_null())
        {
            result["reason"] =
                StringField(entry, "reason", "no pinned PE identity; import a DLL with --dll");
            WriteJson(previousPath, result);
            return result;
        }
        if (!expected.is_object())
        {
            throw FixtureError("PE pin must be an object");
        }
        Json effective = expected;
        if (StringField(effective, "sha256").empty() && !previousPeHash.empty())
        {
            effective["sha256"] = previousPeHash;
        }
        result["expected_pe"] = effective;
        auto previousPdbHash = CachedPdbHash(previous);
        if (previousPeHash != StringField(effective, "sha256"))
        {
            previousPdbHash.clear();
        }
        auto expectedPdbHash = StringField(entry, "pdb_sha256", previousPdbHash);
        if (expectedPdbHash.empty())
        {
            expectedPdbHash = previousPdbHash;
        }
        if (!expectedPdbHash.empty())
        {
            result["expected_pdb_sha256"] = expectedPdbHash;
        }
        const Json archive = entry.value("dll_archive", Json(nullptr));
        result["dll_url"] = archive.is_object() ? StringField(archive, "url") : DllUrl(effective);
        if (!archive.is_null() && !archive.empty())
        {
            result["dll_archive"] = archive;
        }
        const auto recordError = [&](const std::exception& error, bool invalid)
        {
            result["status"] =
                invalid || (std::filesystem::exists(dllPath) && std::filesystem::exists(pdbPath))
                    ? "invalid"
                    : "missing";
            result["reason"] = error.what();
        };
        try
        {
            const auto image =
                EnsureImageFile(dllPath, effective, archive, outputRoot, allowNetwork, downloader);
            result["pe"] = image;
            result["dll"] = PathString(std::filesystem::absolute(dllPath));
            result["pdb_url"] = PdbUrl(image.at("pdb"));
            const FileValidator check = [&](nonstd::span<const std::uint8_t> bytes)
            {
                return ValidatePdb(bytes, image.at("pdb"), expectedPdbHash);
            };
            if (sourcePdb)
            {
                AtomicWrite(pdbPath, ReadFile(*sourcePdb), check);
            }
            const auto symbols = EnsureFile(pdbPath, StringField(result, "pdb_url"), check,
                                            allowNetwork, downloader);
            result["pdb"] = symbols;
            result["expected_pdb_sha256"] = symbols.at("sha256");
            result["pdb_file"] = PathString(std::filesystem::absolute(pdbPath));
            result["status"] = "ready";
        }
        catch (const NetworkDisabled& error)
        {
            recordError(error, false);
        }
        catch (const FixtureError& error)
        {
            recordError(error, true);
        }
        catch (const std::exception& error)
        {
            recordError(error, false);
        }
        WriteJson(previousPath, result);
        return result;
    }

    void RefreshClientPins(Json& manifest, nonstd::span<const std::uint8_t> metadata)
    {
        Json index;
        try
        {
            const auto decoded = GzipDecompress(Bytes(metadata.begin(), metadata.end()));
            index = Json::parse(decoded.begin(), decoded.end());
        }
        catch (const std::exception& error)
        {
            throw FixtureError(std::string("invalid Winbindex gzip JSON: ") + error.what());
        }
        if (!index.is_object())
        {
            throw FixtureError("Winbindex index must be an object");
        }
        const auto metadataHash = Sha256(metadata);
        static const std::regex versionPattern("^([0-9]+)\\.([0-9]+)\\.([0-9]+)\\.([0-9]+)"),
            digestPattern("[a-f0-9]{64}");
        struct Candidate
        {
                std::array<std::uint64_t, 4> versionTuple;
                std::string digest, version;
                Json record;
        };
        for (auto& entry : manifest.at("fixtures"))
        {
            const auto selector = ObjectField(entry, "winbindex_selector");
            if (selector.empty())
            {
                continue;
            }
            const auto windowsVersion = StringField(selector, "windows_version");
            const auto prefix = StringField(selector, "version_prefix");
            const auto selectedVersion = StringField(selector, "version");
            std::vector<Candidate> candidates;
            for (const auto& [digest, record] : index.items())
            {
                const auto info = ObjectField(record, "fileInfo");
                const auto windows = ObjectField(record, "windowsVersions");
                const auto rawVersion = StringField(info, "version");
                std::smatch match;
                if (!std::regex_match(digest, digestPattern) || !info.contains("machineType") ||
                    info.at("machineType") != 0x8664 || !info.contains("virtualSize") ||
                    info.at("virtualSize") == 0 || !windows.contains(windowsVersion) ||
                    !std::regex_search(rawVersion, match, versionPattern))
                {
                    continue;
                }
                const auto version = match[0].str();
                if (!symfind::StartsWith(version, prefix) ||
                    (!selectedVersion.empty() && version != selectedVersion))
                {
                    continue;
                }
                std::array<std::uint64_t, 4> tuple{};
                try
                {
                    for (std::size_t i = 0; i < tuple.size(); ++i)
                    {
                        tuple[i] = std::stoull(match[i + 1].str());
                    }
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
            const auto candidate =
                *std::min_element(candidates.begin(), candidates.end(),
                                  [](const auto& a, const auto& b)
                                  {
                                      return a.versionTuple != b.versionTuple
                                                 ? a.versionTuple < b.versionTuple
                                                 : a.digest < b.digest;
                                  });
            const auto& info = candidate.record.at("fileInfo");
            const auto digest = StringField(info, "sha256", candidate.digest);
            if (!std::regex_match(digest, digestPattern))
            {
                throw FixtureError("invalid Winbindex SHA256");
            }
            if (StringField(ObjectField(entry, "pe"), "sha256") != digest)
            {
                entry.erase("pdb_sha256");
            }
            entry["pe"] = Json{{"machine", U32Field(info, "machineType")},
                               {"timestamp", U32Field(info, "timestamp")},
                               {"image_size", U32Field(info, "virtualSize")},
                               {"file_size", UnsignedField(info, "size")},
                               {"version", candidate.version},
                               {"sha256", digest}};
            const auto windows = candidate.record.at("windowsVersions").at(windowsVersion);
            if (!windows.is_object() || windows.empty())
            {
                throw FixtureError("Winbindex OS record has no update provenance");
            }
            const auto update =
                windows.contains("BASE") ? std::string("BASE") : windows.begin().key();
            const auto origin = windows.at(update);
            Json provenance = ObjectField(entry, "provenance");
            provenance.update(
                Json{{"metadata_url", winbindexUrl},
                     {"metadata_sha256", metadataHash},
                     {"metadata_record_sha256", candidate.digest},
                     {"windows_version", windowsVersion},
                     {"update", update},
                     {"windows_version_info", origin.value("windowsVersionInfo", Json(nullptr))},
                     {"update_info", origin.value("updateInfo", Json(nullptr))},
                     {"source_paths", origin.value("sourcePaths", Json(nullptr))}});
            entry["provenance"] = provenance;
            entry.erase("reason");
        }
    }

    FetchResult ProcessManifest(const FetchOptions& options)
    {
        if (options.sourceDll && options.labels.size() != 1)
        {
            throw FixtureError("--dll requires exactly one --label");
        }
        if (options.sourcePdb && !options.sourceDll)
        {
            throw FixtureError("--pdb requires --dll");
        }
        if ((!options.sourceUrl.empty() || !options.os.empty()) && !options.sourceDll)
        {
            throw FixtureError("--source-url and --os require --dll");
        }
        if (options.sourceDll && (options.refreshWinbindex || options.winbindexMetadata))
        {
            throw FixtureError("--dll cannot be combined with a Winbindex manifest refresh");
        }
        if (options.outputRoot.empty())
        {
            throw FixtureError("output_root must be provided");
        }
        Json manifest = options.sourceDll ? Json{{"schema_version", 1}, {"fixtures", Json::array()}}
                                          : ReadJson(options.manifestPath);
        if (!manifest.is_object() || manifest.value("schema_version", Json(nullptr)) != 1 ||
            !manifest.contains("fixtures") || !manifest.at("fixtures").is_array())
        {
            throw FixtureError("unsupported fixture manifest schema");
        }
        if (options.refreshWinbindex || options.winbindexMetadata)
        {
            const auto metadata =
                options.winbindexMetadata
                    ? ReadFile(*options.winbindexMetadata)
                    : FetchBytes(winbindexUrl, options.allowNetwork, options.download);
            RefreshClientPins(manifest, metadata);
            WriteJson(options.manifestPath, manifest);
        }
        Json fixtures = Json::array();
        if (options.sourceDll)
        {
            fixtures.push_back(Json{
                {"label", options.labels.front()},
                {"target_os", options.os.empty() ? Json(nullptr) : Json(options.os)},
                {"provenance",
                 Json{{"kind", "local_import"},
                      {"source_url",
                       options.sourceUrl.empty() ? Json(nullptr) : Json(options.sourceUrl)},
                      {"os_claim", options.os.empty() ? Json(nullptr) : Json(options.os)},
                      {"os_coverage", false},
                      {"note", "OS provenance is user supplied, not inferred from PE version."}}}});
        }
        else
        {
            std::set<std::string> unknown(options.labels.begin(), options.labels.end());
            std::set<std::string> manifestLabels;
            for (const auto& entry : manifest.at("fixtures"))
            {
                const auto label = StringField(entry, "label");
                if (!ValidLabel(label) || !manifestLabels.insert(label).second)
                {
                    throw FixtureError("invalid or duplicate fixture label");
                }
                if (options.labels.empty() || unknown.find(label) != unknown.end())
                {
                    fixtures.push_back(entry);
                    unknown.erase(label);
                }
            }
            // The generated per-label pin permits offline revalidation of local imports.
            for (auto it = unknown.begin(); it != unknown.end();)
            {
                const auto label = *it;
                if (!ValidLabel(label))
                {
                    ++it;
                    continue;
                }
                const auto cachedPath = options.outputRoot / label / "manifest.json";
                if (!std::filesystem::exists(cachedPath))
                {
                    ++it;
                    continue;
                }
                const auto cached = ReadJson(cachedPath);
                Json expected = ObjectField(cached, "pe");
                if (expected.empty())
                {
                    expected = ObjectField(cached, "expected_pe");
                }
                if (StringField(cached, "label") != label || expected.empty())
                {
                    ++it;
                    continue;
                }
                fixtures.push_back(Json{{"label", label},
                                        {"target_os", cached.value("target_os", Json(nullptr))},
                                        {"provenance", ObjectField(cached, "provenance")},
                                        {"pe", expected},
                                        {"dll_archive", cached.value("dll_archive", Json(nullptr))},
                                        {"pdb_sha256", CachedPdbHash(cached)}});
                it = unknown.erase(it);
            }
            if (!unknown.empty())
            {
                std::string message = "unknown fixture labels: ";
                for (const auto& label : unknown)
                {
                    message += (message.back() == ' ' ? "" : ", ") + label;
                }
                throw FixtureError(message);
            }
        }
        FetchResult result;
        result.successful = true;
        for (const auto& entry : fixtures)
        {
            const auto fixture =
                ProcessFixture(entry, options.outputRoot, options.allowNetwork, options.sourceDll,
                               options.sourcePdb, options.download);
            const auto status = StringField(fixture, "status");
            if (status != "ready" && !(options.allowMissing && status == "missing"))
            {
                result.successful = false;
            }
            result.fixtures.push_back(fixture);
        }
        const auto aggregatePath = options.outputRoot / "manifest.json";
        Json previous =
            std::filesystem::exists(aggregatePath) ? ReadJson(aggregatePath) : Json::object();
        std::map<std::string, Json> combined;
        if (previous.contains("fixtures"))
        {
            if (!previous.at("fixtures").is_array())
            {
                throw FixtureError("invalid aggregate fixture list");
            }
            for (const auto& entry : previous.at("fixtures"))
            {
                combined[StringField(entry, "label")] = entry;
            }
        }
        for (const auto& entry : result.fixtures)
        {
            combined[StringField(entry, "label")] = entry;
        }
        Json all = Json::array();
        for (const auto& [_, entry] : combined)
        {
            all.push_back(entry);
        }
        WriteJson(aggregatePath,
                  Json{{"schema_version", 1}, {"generated_at_utc", UtcNow()}, {"fixtures", all}});
        return result;
    }

} // namespace pdbStuff
