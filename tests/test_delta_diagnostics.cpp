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
    using namespace pdbStuff;

    struct DeltaFixture
    {
            Bytes sourceBytes{'o', 'r', 'i', 'g', 'i', 'n', 'a', 'l'};
            Bytes targetBytes{'r', 'e', 'c', 'o', 'n', 's', 't', 'r', 'u', 'c', 't', 'e', 'd'};
            Bytes patchBytes;

            DeltaFixture()
            {
                std::array<wchar_t, MAX_PATH + 1> systemDirectoryBuffer{};
                const auto systemDirectoryLength = GetSystemDirectoryW(
                    systemDirectoryBuffer.data(), static_cast<UINT>(systemDirectoryBuffer.size()));
                if (systemDirectoryLength == 0 ||
                    systemDirectoryLength >= systemDirectoryBuffer.size())
                {
                    throw std::runtime_error("No Windows system directory");
                }
                const auto deltaLibraryPath =
                    std::wstring(systemDirectoryBuffer.data(), systemDirectoryLength) +
                    L"\\msdelta.dll";
                HMODULE deltaLibrary =
                    LoadLibraryExW(deltaLibraryPath.c_str(), nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
                if (!deltaLibrary)
                {
                    throw std::runtime_error(
                        "Cannot load installed system msdelta for native fixture creation");
                }
                struct ModuleGuard
                {
                        HMODULE deltaLibrary;
                        ~ModuleGuard()
                        {
                            FreeLibrary(deltaLibrary);
                        }
                } moduleGuard{deltaLibrary};
                const auto createDelta = reinterpret_cast<decltype(&CreateDeltaB)>(
                    GetProcAddress(deltaLibrary, "CreateDeltaB"));
                const auto freeDelta = reinterpret_cast<decltype(&DeltaFree)>(
                    GetProcAddress(deltaLibrary, "DeltaFree"));
                if (!createDelta || !freeDelta)
                {
                    throw std::runtime_error(
                        "System msdelta lacks native test fixture creation functions");
                }
                DELTA_INPUT sourceInput{}, targetInput{}, emptyInput{};
                sourceInput.lpStart = sourceBytes.data();
                sourceInput.uSize = sourceBytes.size();
                targetInput.lpStart = targetBytes.data();
                targetInput.uSize = targetBytes.size();
                FILETIME targetFileTime{0, 0};
                DELTA_OUTPUT deltaOutput{};
                if (!createDelta(DELTA_FILE_TYPE_RAW, DELTA_FLAG_NONE, DELTA_FLAG_NONE, sourceInput,
                                 targetInput, emptyInput, emptyInput, emptyInput, &targetFileTime,
                                 CALG_MD5, &deltaOutput))
                {
                    throw std::runtime_error(
                        "CreateDeltaB failed for synthetic native test data: " +
                        std::to_string(GetLastError()));
                }
                struct OutputGuard
                {
                        decltype(&DeltaFree) freeDelta;
                        LPVOID patchMemory;
                        ~OutputGuard()
                        {
                            if (patchMemory)
                            {
                                freeDelta(patchMemory);
                            }
                        }
                } outputGuard{freeDelta, deltaOutput.lpStart};
                if (!deltaOutput.lpStart || deltaOutput.uSize == 0 ||
                    deltaOutput.uSize > 1024 * 1024)
                {
                    throw std::runtime_error("CreateDeltaB returned an invalid test patch");
                }
                const auto* patchBegin = static_cast<const uint8_t*>(deltaOutput.lpStart);
                patchBytes.assign(patchBegin, patchBegin + deltaOutput.uSize);
            }
    };

    TEST(DeltaDiagnostics, ReconstructsRawAndCrcPrefixedPa30AsData)
    {
        const DeltaFixture fixture;
        EXPECT_EQ(
            ApplyDeltaPatch(fixture.sourceBytes, fixture.patchBytes, Sha256(fixture.targetBytes)),
            fixture.targetBytes);
        // Windows servicing adds a four-byte CRC before PA30. Prefix handling
        // cannot be confused with loading the reconstructed target as a DLL.
        Bytes crcPrefixedPatch{0, 0, 0, 0};
        crcPrefixedPatch.insert(crcPrefixedPatch.end(), fixture.patchBytes.begin(),
                                fixture.patchBytes.end());
        EXPECT_EQ(
            ApplyDeltaPatch(fixture.sourceBytes, crcPrefixedPatch, Sha256(fixture.targetBytes)),
            fixture.targetBytes);
        EXPECT_EQ(InspectDelta(crcPrefixedPatch).at("crc_prefixed"), true);
        EXPECT_EQ(InspectDelta(fixture.patchBytes).at("crc_prefixed"), false);
    }

    TEST(DeltaDiagnostics, InspectionMatchesOnlyTheTargetMd5)
    {
        const DeltaFixture fixture;
        const auto deltaMetadata = InspectDelta(fixture.patchBytes);
        EXPECT_EQ(deltaMetadata.at("target_size"), fixture.targetBytes.size());
        EXPECT_EQ(deltaMetadata.at("algorithm"), CALG_MD5);
        EXPECT_EQ(deltaMetadata.at("hash").get<std::string>().size(), 32);
        const Json candidateMetadata{
            {"expected", {{"fileInfo", {{"md5", deltaMetadata.at("hash")}}}}},
            {"unrelated", {{"fileInfo", {{"md5", std::string(32, '0')}}}}}};
        const auto matchingEntries =
            InspectDelta(fixture.patchBytes, candidateMetadata).at("matches");
        ASSERT_EQ(matchingEntries.size(), 1);
        EXPECT_EQ(matchingEntries.at(0).at("sha256"), "expected");
    }

    TEST(DeltaDiagnostics, IncorrectTargetPinNeverReturnsReconstructedBytes)
    {
        const DeltaFixture fixture;
        EXPECT_THROW(
            (void)ApplyDeltaPatch(fixture.sourceBytes, fixture.patchBytes, std::string(64, '0')),
            FixtureError);
        EXPECT_THROW((void)ApplyDeltaPatch(fixture.sourceBytes, fixture.patchBytes, "malformed"),
                     FixtureError);
        EXPECT_EQ(
            ApplyDeltaPatch(fixture.sourceBytes, fixture.patchBytes, Sha256(fixture.targetBytes)),
            fixture.targetBytes);
    }

    TEST(DeltaDiagnostics, MalformedOrTruncatedPatchesAreRejected)
    {
        EXPECT_THROW((void)InspectDelta(Bytes{'P', 'A', '3'}), FixtureError);
        EXPECT_THROW((void)ApplyDeltaPatch({}, Bytes{'x', 'P', 'A', '3', '0'}), FixtureError);
        const DeltaFixture fixture;
        auto truncatedPatch = fixture.patchBytes;
        truncatedPatch.resize(4);
        EXPECT_THROW((void)InspectDelta(truncatedPatch), FixtureError);
        EXPECT_THROW((void)ApplyDeltaPatch(fixture.sourceBytes, truncatedPatch), FixtureError);
    }
} // namespace
