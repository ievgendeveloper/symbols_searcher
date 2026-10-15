#include "pdb_stuff/diagnostics.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <msdelta.h>
#include <windows.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <limits>
#include <string>

namespace pdb_stuff
{
    namespace
    {
        constexpr size_t max_delta_bytes = 256 * 1024 * 1024;
        constexpr size_t max_image_bytes = 32 * 1024 * 1024;

        [[noreturn]] void system_error(std::string_view operation)
        {
            throw FixtureError(std::string(operation) + " failed (Windows error " +
                               std::to_string(GetLastError()) + ")");
        }

        class MsDelta
        {
            public:
                using InfoFn = BOOL(WINAPI*)(DELTA_INPUT, LPDELTA_HEADER_INFO);
                using ApplyFn = BOOL(WINAPI*)(DELTA_FLAG_TYPE, DELTA_INPUT, DELTA_INPUT, LPDELTA_OUTPUT);
                using FreeFn = BOOL(WINAPI*)(LPVOID);

                MsDelta()
                {
                    std::array<wchar_t, MAX_PATH + 1> directory{};
                    const UINT length = GetSystemDirectoryW(directory.data(), static_cast<UINT>(directory.size()));
                    if (length == 0 || length >= directory.size())
                    {
                        system_error("GetSystemDirectoryW");
                    }
                    const std::wstring path = std::wstring(directory.data(), length) + L"\\msdelta.dll";
                    module_ = LoadLibraryExW(path.c_str(), nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
                    if (!module_)
                    {
                        system_error("Loading system msdelta.dll");
                    }
                    info = reinterpret_cast<InfoFn>(GetProcAddress(module_, "GetDeltaInfoB"));
                    apply = reinterpret_cast<ApplyFn>(GetProcAddress(module_, "ApplyDeltaB"));
                    free = reinterpret_cast<FreeFn>(GetProcAddress(module_, "DeltaFree"));
                    if (!info || !apply || !free)
                    {
                        FreeLibrary(module_);
                        module_ = nullptr;
                        throw FixtureError("System msdelta.dll lacks the required PA30 operations");
                    }
                }

                ~MsDelta()
                {
                    if (module_)
                        FreeLibrary(module_);
                }
                MsDelta(const MsDelta&) = delete;
                MsDelta& operator=(const MsDelta&) = delete;
                InfoFn info = nullptr;
                ApplyFn apply = nullptr;
                FreeFn free = nullptr;

            private:
                HMODULE module_ = nullptr;
        };

        std::span<const uint8_t> delta_payload(std::span<const uint8_t> bytes)
        {
            if (bytes.size() > max_delta_bytes)
            {
                throw FixtureError("Delta input exceeds the size limit");
            }
            constexpr std::array<uint8_t, 4> magic{'P', 'A', '3', '0'};
            if (bytes.size() >= magic.size() && std::equal(magic.begin(), magic.end(), bytes.begin()))
            {
                return bytes;
            }
            if (bytes.size() >= 8 && std::equal(magic.begin(), magic.end(), bytes.begin() + 4))
            {
                return bytes.subspan(4);
            }
            throw FixtureError("Delta is neither PA30 nor CRC-prefixed PA30");
        }

        DELTA_INPUT delta_input(std::span<const uint8_t> bytes)
        {
            DELTA_INPUT result{};
            result.lpStart = const_cast<uint8_t*>(bytes.data());
            result.uSize = bytes.size();
            result.Editable = FALSE;
            return result;
        }

        DELTA_HEADER_INFO get_info(const MsDelta& delta, std::span<const uint8_t> payload)
        {
            DELTA_HEADER_INFO result{};
            if (!delta.info(delta_input(payload), &result))
            {
                system_error("GetDeltaInfoB");
            }
            if (result.TargetHash.HashSize > sizeof(result.TargetHash.HashValue))
            {
                throw FixtureError("Delta target hash exceeds its header buffer");
            }
            if (result.TargetSize > max_image_bytes)
            {
                throw FixtureError("Delta target exceeds the image size limit");
            }
            return result;
        }

        std::string hex_bytes(const unsigned char* bytes, size_t size)
        {
            constexpr char digits[] = "0123456789abcdef";
            std::string result(size * 2, '\0');
            for (size_t i = 0; i < size; ++i)
            {
                result[2 * i] = digits[bytes[i] >> 4];
                result[2 * i + 1] = digits[bytes[i] & 15];
            }
            return result;
        }

        std::string iso_time(FILETIME filetime)
        {
            SYSTEMTIME utc{};
            if (!FileTimeToSystemTime(&filetime, &utc))
            {
                system_error("FileTimeToSystemTime");
            }
            std::array<char, 40> buffer{};
            std::snprintf(buffer.data(), buffer.size(), "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
                          utc.wYear, utc.wMonth, utc.wDay, utc.wHour, utc.wMinute,
                          utc.wSecond, utc.wMilliseconds);
            return buffer.data();
        }

        void validate_pin(std::string_view pin)
        {
            if (!pin.empty() && (pin.size() != 64 || !std::all_of(pin.begin(), pin.end(), [](unsigned char c)
                                                                  { return std::isxdigit(c) != 0; })))
            {
                throw FixtureError("Expected delta target SHA256 must contain 64 hexadecimal characters");
            }
        }
    } // namespace

    Json inspect_delta(std::span<const uint8_t> patch, const Json& winbindex)
    {
        const auto payload = delta_payload(patch);
        const MsDelta delta;
        const auto header = get_info(delta, payload);
        const auto digest = hex_bytes(header.TargetHash.HashValue, header.TargetHash.HashSize);
        const uint64_t filetime = (static_cast<uint64_t>(header.TargetFileTime.dwHighDateTime) << 32) |
                                  header.TargetFileTime.dwLowDateTime;
        Json matches = Json::array();
        // CALG_MD5 is 0x8003; metadata MD5 matching is meaningful only then.
        if (header.TargetHashAlgId == CALG_MD5 && winbindex.is_object())
        {
            for (const auto& [key, entry] : winbindex.items())
            {
                if (entry.is_object() && entry.contains("fileInfo") && entry["fileInfo"].is_object() &&
                    entry["fileInfo"].value("md5", std::string{}) == digest)
                {
                    matches.push_back(Json{{"sha256", key}, {"fileInfo", entry["fileInfo"]}});
                }
            }
        }
        return Json{{"target_size", header.TargetSize}, {"target_time", iso_time(header.TargetFileTime)}, {"target_filetime", filetime}, {"algorithm", header.TargetHashAlgId}, {"hash", digest}, {"crc_prefixed", payload.size() != patch.size()}, {"matches", std::move(matches)}};
    }

    Bytes apply_delta(std::span<const uint8_t> source, std::span<const uint8_t> patch,
                      std::string_view expected_sha256)
    {
        validate_pin(expected_sha256);
        if (source.size() > max_image_bytes)
        {
            throw FixtureError("Delta source exceeds the image size limit");
        }
        const auto payload = delta_payload(patch);
        const MsDelta delta;
        const auto header = get_info(delta, payload);
        DELTA_OUTPUT output{};
        if (!delta.apply(DELTA_FLAG_NONE, delta_input(source), delta_input(payload), &output))
        {
            system_error("ApplyDeltaB");
        }
        struct Guard
        {
                const MsDelta& delta;
                LPVOID pointer;
                ~Guard()
                {
                    if (pointer)
                        delta.free(pointer);
                }
        } guard{delta, output.lpStart};
        if (output.uSize != header.TargetSize || output.uSize > max_image_bytes ||
            (output.uSize && !output.lpStart))
        {
            throw FixtureError("Applied delta output does not match its bounded target size");
        }
        Bytes bytes;
        if (output.uSize)
        {
            const auto* begin = static_cast<const uint8_t*>(output.lpStart);
            bytes.assign(begin, begin + output.uSize);
        }
        if (!expected_sha256.empty())
        {
            std::string pin(expected_sha256);
            std::transform(pin.begin(), pin.end(), pin.begin(), [](unsigned char c)
                           { return static_cast<char>(std::tolower(c)); });
            if (sha256(bytes) != pin)
            {
                throw FixtureError("Applied delta target SHA256 mismatch");
            }
        }
        return bytes;
    }
} // namespace pdb_stuff
