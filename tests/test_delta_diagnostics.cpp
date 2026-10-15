#include "pdb_stuff/diagnostics.h"

#include <gtest/gtest.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <msdelta.h>
#include <windows.h>

#include <array>
#include <string>

namespace
{
    using namespace pdb_stuff;

    struct DeltaFixture
    {
            Bytes source{'o', 'r', 'i', 'g', 'i', 'n', 'a', 'l'};
            Bytes target{'r', 'e', 'c', 'o', 'n', 's', 't', 'r', 'u', 'c', 't', 'e', 'd'};
            Bytes patch;

            DeltaFixture()
            {
                std::array<wchar_t, MAX_PATH + 1> directory{};
                const auto length = GetSystemDirectoryW(directory.data(), static_cast<UINT>(directory.size()));
                if (length == 0 || length >= directory.size())
                    throw std::runtime_error("No Windows system directory");
                const auto path = std::wstring(directory.data(), length) + L"\\msdelta.dll";
                HMODULE module = LoadLibraryExW(path.c_str(), nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
                if (!module)
                    throw std::runtime_error("Cannot load installed system msdelta for native fixture creation");
                struct ModuleGuard
                {
                        HMODULE module;
                        ~ModuleGuard() { FreeLibrary(module); }
                } module_guard{module};
                const auto create = reinterpret_cast<decltype(&CreateDeltaB)>(GetProcAddress(module, "CreateDeltaB"));
                const auto free = reinterpret_cast<decltype(&DeltaFree)>(GetProcAddress(module, "DeltaFree"));
                if (!create || !free)
                    throw std::runtime_error("System msdelta lacks native test fixture creation functions");
                DELTA_INPUT source_input{}, target_input{}, empty{};
                source_input.lpStart = source.data();
                source_input.uSize = source.size();
                target_input.lpStart = target.data();
                target_input.uSize = target.size();
                FILETIME time{0, 0};
                DELTA_OUTPUT result{};
                if (!create(DELTA_FILE_TYPE_RAW, DELTA_FLAG_NONE, DELTA_FLAG_NONE,
                            source_input, target_input, empty, empty, empty, &time, CALG_MD5, &result))
                {
                    throw std::runtime_error("CreateDeltaB failed for synthetic native test data: " +
                                             std::to_string(GetLastError()));
                }
                struct OutputGuard
                {
                        decltype(&DeltaFree) free;
                        LPVOID memory;
                        ~OutputGuard()
                        {
                            if (memory)
                                free(memory);
                        }
                } output_guard{free, result.lpStart};
                if (!result.lpStart || result.uSize == 0 || result.uSize > 1024 * 1024)
                {
                    throw std::runtime_error("CreateDeltaB returned an invalid test patch");
                }
                const auto* data = static_cast<const uint8_t*>(result.lpStart);
                patch.assign(data, data + result.uSize);
            }
    };

    TEST(DeltaDiagnostics, ReconstructsRawAndCrcPrefixedPa30AsData)
    {
        const DeltaFixture fixture;
        EXPECT_EQ(apply_delta(fixture.source, fixture.patch, sha256(fixture.target)), fixture.target);
        // Windows servicing adds a four-byte CRC before PA30. Prefix handling
        // cannot be confused with loading the reconstructed target as a DLL.
        Bytes prefixed{0, 0, 0, 0};
        prefixed.insert(prefixed.end(), fixture.patch.begin(), fixture.patch.end());
        EXPECT_EQ(apply_delta(fixture.source, prefixed, sha256(fixture.target)), fixture.target);
        EXPECT_EQ(inspect_delta(prefixed).at("crc_prefixed"), true);
        EXPECT_EQ(inspect_delta(fixture.patch).at("crc_prefixed"), false);
    }

    TEST(DeltaDiagnostics, InspectionMatchesOnlyTheTargetMd5)
    {
        const DeltaFixture fixture;
        const auto info = inspect_delta(fixture.patch);
        EXPECT_EQ(info.at("target_size"), fixture.target.size());
        EXPECT_EQ(info.at("algorithm"), CALG_MD5);
        EXPECT_EQ(info.at("hash").get<std::string>().size(), 32);
        const Json metadata{{"expected", {{"fileInfo", {{"md5", info.at("hash")}}}}},
                            {"unrelated", {{"fileInfo", {{"md5", std::string(32, '0')}}}}}};
        const auto matched = inspect_delta(fixture.patch, metadata).at("matches");
        ASSERT_EQ(matched.size(), 1);
        EXPECT_EQ(matched.at(0).at("sha256"), "expected");
    }

    TEST(DeltaDiagnostics, IncorrectTargetPinNeverReturnsReconstructedBytes)
    {
        const DeltaFixture fixture;
        EXPECT_THROW((void)apply_delta(fixture.source, fixture.patch, std::string(64, '0')), FixtureError);
        EXPECT_THROW((void)apply_delta(fixture.source, fixture.patch, "malformed"), FixtureError);
        EXPECT_EQ(apply_delta(fixture.source, fixture.patch, sha256(fixture.target)), fixture.target);
    }

    TEST(DeltaDiagnostics, MalformedOrTruncatedPatchesAreRejected)
    {
        EXPECT_THROW((void)inspect_delta(Bytes{'P', 'A', '3'}), FixtureError);
        EXPECT_THROW((void)apply_delta({}, Bytes{'x', 'P', 'A', '3', '0'}), FixtureError);
        const DeltaFixture fixture;
        auto truncated = fixture.patch;
        truncated.resize(4);
        EXPECT_THROW((void)inspect_delta(truncated), FixtureError);
        EXPECT_THROW((void)apply_delta(fixture.source, truncated), FixtureError);
    }
} // namespace
