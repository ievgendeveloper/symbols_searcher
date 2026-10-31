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

namespace pdbStuff
{
    namespace
    {
        constexpr size_t maxDeltaBytes = 256 * 1024 * 1024;
        constexpr size_t maxImageBytes = 32 * 1024 * 1024;

        [[noreturn]] void SystemError(std::string_view operation)
        {
            throw FixtureError(std::string(operation) + " failed (Windows error " +
                               std::to_string(GetLastError()) + ")");
        }

        class MsDelta
        {
            public:
                using InfoFn = BOOL(WINAPI*)(DELTA_INPUT, LPDELTA_HEADER_INFO);
                using ApplyFn = BOOL(WINAPI*)(DELTA_FLAG_TYPE, DELTA_INPUT, DELTA_INPUT,
                                              LPDELTA_OUTPUT);
                using FreeFn = BOOL(WINAPI*)(LPVOID);

                MsDelta()
                {
                    std::array<wchar_t, MAX_PATH + 1> directory{};
                    const UINT length =
                        GetSystemDirectoryW(directory.data(), static_cast<UINT>(directory.size()));
                    if (length == 0 || length >= directory.size())
                    {
                        SystemError("GetSystemDirectoryW");
                    }
                    const std::wstring path =
                        std::wstring(directory.data(), length) + L"\\msdelta.dll";
                    m_module = LoadLibraryExW(path.c_str(), nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
                    if (!m_module)
                    {
                        SystemError("Loading system msdelta.dll");
                    }
                    info = reinterpret_cast<InfoFn>(GetProcAddress(m_module, "GetDeltaInfoB"));
                    apply = reinterpret_cast<ApplyFn>(GetProcAddress(m_module, "ApplyDeltaB"));
                    free = reinterpret_cast<FreeFn>(GetProcAddress(m_module, "DeltaFree"));
                    if (!info || !apply || !free)
                    {
                        FreeLibrary(m_module);
                        m_module = nullptr;
                        throw FixtureError("System msdelta.dll lacks the required PA30 operations");
                    }
                }

                ~MsDelta()
                {
                    if (m_module)
                    {
                        FreeLibrary(m_module);
                    }
                }
                MsDelta(const MsDelta&) = delete;
                MsDelta& operator=(const MsDelta&) = delete;
                InfoFn info = nullptr;
                ApplyFn apply = nullptr;
                FreeFn free = nullptr;

            private:
                HMODULE m_module = nullptr;
        };

        nonstd::span<const uint8_t> DeltaPayload(nonstd::span<const uint8_t> bytes)
        {
            if (bytes.size() > maxDeltaBytes)
            {
                throw FixtureError("Delta input exceeds the size limit");
            }
            constexpr std::array<uint8_t, 4> magic{'P', 'A', '3', '0'};
            if (bytes.size() >= magic.size() &&
                std::equal(magic.begin(), magic.end(), bytes.begin()))
            {
                return bytes;
            }
            if (bytes.size() >= 8 && std::equal(magic.begin(), magic.end(), bytes.begin() + 4))
            {
                return bytes.subspan(4);
            }
            throw FixtureError("Delta is neither PA30 nor CRC-prefixed PA30");
        }

        DELTA_INPUT DeltaInput(nonstd::span<const uint8_t> bytes)
        {
            DELTA_INPUT result{};
            result.lpStart = const_cast<uint8_t*>(bytes.data());
            result.uSize = bytes.size();
            result.Editable = FALSE;
            return result;
        }

        DELTA_HEADER_INFO GetInfo(const MsDelta& delta, nonstd::span<const uint8_t> payload)
        {
            DELTA_HEADER_INFO result{};
            if (!delta.info(DeltaInput(payload), &result))
            {
                SystemError("GetDeltaInfoB");
            }
            if (result.TargetHash.HashSize > sizeof(result.TargetHash.HashValue))
            {
                throw FixtureError("Delta target hash exceeds its header buffer");
            }
            if (result.TargetSize > maxImageBytes)
            {
                throw FixtureError("Delta target exceeds the image size limit");
            }
            return result;
        }

        std::string HexBytes(const unsigned char* bytes, size_t size)
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

        std::string IsoTime(FILETIME filetime)
        {
            SYSTEMTIME utc{};
            if (!FileTimeToSystemTime(&filetime, &utc))
            {
                SystemError("FileTimeToSystemTime");
            }
            std::array<char, 40> buffer{};
            std::snprintf(buffer.data(), buffer.size(), "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
                          utc.wYear, utc.wMonth, utc.wDay, utc.wHour, utc.wMinute, utc.wSecond,
                          utc.wMilliseconds);
            return buffer.data();
        }

        void ValidatePin(std::string_view pin)
        {
            if (!pin.empty() && (pin.size() != 64 || !std::all_of(pin.begin(), pin.end(),
                                                                  [](unsigned char c)
                                                                  {
                                                                      return std::isxdigit(c) != 0;
                                                                  })))
            {
                throw FixtureError(
                    "Expected delta target SHA256 must contain 64 hexadecimal characters");
            }
        }
    } // namespace

    Json InspectDelta(nonstd::span<const uint8_t> patch, const Json& winbindex)
    {
        const auto payload = DeltaPayload(patch);
        const MsDelta delta;
        const auto header = GetInfo(delta, payload);
        const auto digest = HexBytes(header.TargetHash.HashValue, header.TargetHash.HashSize);
        const uint64_t filetime =
            (static_cast<uint64_t>(header.TargetFileTime.dwHighDateTime) << 32) |
            header.TargetFileTime.dwLowDateTime;
        Json matches = Json::array();
        // CALG_MD5 is 0x8003; metadata MD5 matching is meaningful only then.
        if (header.TargetHashAlgId == CALG_MD5 && winbindex.is_object())
        {
            for (const auto& [key, entry] : winbindex.items())
            {
                if (entry.is_object() && entry.contains("fileInfo") &&
                    entry["fileInfo"].is_object() &&
                    entry["fileInfo"].value("md5", std::string{}) == digest)
                {
                    matches.push_back(Json{{"sha256", key}, {"fileInfo", entry["fileInfo"]}});
                }
            }
        }
        return Json{{"target_size", header.TargetSize},
                    {"target_time", IsoTime(header.TargetFileTime)},
                    {"target_filetime", filetime},
                    {"algorithm", header.TargetHashAlgId},
                    {"hash", digest},
                    {"crc_prefixed", payload.size() != patch.size()},
                    {"matches", std::move(matches)}};
    }

    Bytes ApplyDeltaPatch(nonstd::span<const uint8_t> source, nonstd::span<const uint8_t> patch,
                          std::string_view expectedSha256)
    {
        ValidatePin(expectedSha256);
        if (source.size() > maxImageBytes)
        {
            throw FixtureError("Delta source exceeds the image size limit");
        }
        const auto payload = DeltaPayload(patch);
        const MsDelta delta;
        const auto header = GetInfo(delta, payload);
        DELTA_OUTPUT output{};
        if (!delta.apply(DELTA_FLAG_NONE, DeltaInput(source), DeltaInput(payload), &output))
        {
            SystemError("ApplyDeltaB");
        }
        struct Guard
        {
                const MsDelta& delta;
                LPVOID pointer;
                ~Guard()
                {
                    if (pointer)
                    {
                        delta.free(pointer);
                    }
                }
        } guard{delta, output.lpStart};
        if (output.uSize != header.TargetSize || output.uSize > maxImageBytes ||
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
        if (!expectedSha256.empty())
        {
            std::string pin(expectedSha256);
            std::transform(pin.begin(), pin.end(), pin.begin(),
                           [](unsigned char c)
                           {
                               return static_cast<char>(std::tolower(c));
                           });
            if (Sha256(bytes) != pin)
            {
                throw FixtureError("Applied delta target SHA256 mismatch");
            }
        }
        return bytes;
    }
} // namespace pdbStuff
