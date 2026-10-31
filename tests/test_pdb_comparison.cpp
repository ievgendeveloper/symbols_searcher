#include "ntdll_symbol_rules.h"
#include "pdb_symbols.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <gtest/gtest.h>
#include <spdlog/spdlog.h>

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <stdexcept>

namespace
{
    template <class ValueType>
    void Put(std::vector<uint8_t>& peImageBytes, size_t fieldOffset, const ValueType& fieldValue)
    {
        std::memcpy(peImageBytes.data() + fieldOffset, &fieldValue, sizeof(fieldValue));
    }

    // A tiny on-disk PE with a debug directory in one file-backed section.
    std::vector<uint8_t> SamplePe()
    {
        std::vector<uint8_t> peImageBytes(0x400);
        IMAGE_DOS_HEADER dosHeader{};
        dosHeader.e_magic = IMAGE_DOS_SIGNATURE;
        dosHeader.e_lfanew = 0x40;
        Put(peImageBytes, 0, dosHeader);
        Put(peImageBytes, 0x40, DWORD{IMAGE_NT_SIGNATURE});
        IMAGE_FILE_HEADER coffHeader{};
        coffHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
        coffHeader.NumberOfSections = 1;
        coffHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
        Put(peImageBytes, 0x44, coffHeader);
        IMAGE_OPTIONAL_HEADER64 optionalHeader{};
        optionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        optionalHeader.SizeOfImage = 0x2000;
        optionalHeader.SizeOfHeaders = 0x200;
        optionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG] = {0x1000,
                                                                     sizeof(IMAGE_DEBUG_DIRECTORY)};
        Put(peImageBytes, 0x58, optionalHeader);
        IMAGE_SECTION_HEADER sectionHeader{};
        sectionHeader.VirtualAddress = 0x1000;
        sectionHeader.SizeOfRawData = 0x200;
        sectionHeader.PointerToRawData = 0x200;
        Put(peImageBytes, 0x58 + sizeof(optionalHeader), sectionHeader);
        IMAGE_DEBUG_DIRECTORY debugDirectory{};
        debugDirectory.Type = IMAGE_DEBUG_TYPE_CODEVIEW;
        debugDirectory.SizeOfData = 34;
        debugDirectory.AddressOfRawData = 0x1040;
        debugDirectory.PointerToRawData = 0x240;
        Put(peImageBytes, 0x200, debugDirectory);
        std::memcpy(peImageBytes.data() + 0x240, reinterpret_cast<void const*>("RSDS"), 4);
        const GUID pdbGuid{
            0x12345678, 0xABCD, 0xEF12, {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}};
        Put(peImageBytes, 0x244, pdbGuid);
        Put(peImageBytes, 0x254, uint32_t{2});
        std::memcpy(peImageBytes.data() + 0x258, reinterpret_cast<void const*>("ntdll.pdb"), 10);
        return peImageBytes;
    }

    std::string EnvironmentValue(const char* variableName)
    {
        // _dupenv_s avoids borrowed environment pointers on the MSVC CRT.
        char* rawEnvironmentValue = nullptr;
        size_t bufferSize = 0;
        if (::_dupenv_s(&rawEnvironmentValue, &bufferSize, variableName) != 0)
        {
            throw std::runtime_error("Could not read environment variable");
        }

        const std::string environmentText = rawEnvironmentValue ? rawEnvironmentValue : "";
        std::free(rawEnvironmentValue);
        return environmentText;
    }

    class TemporaryPair
    {
        public:
            TemporaryPair()
            {
                for (unsigned attempt = 0; attempt < 100; ++attempt)
                {
                    temporaryDirectory =
                        std::filesystem::temp_directory_path() /
                        ("symfind-pdb-test-" + std::to_string(GetCurrentProcessId()) + "-" +
                         std::to_string(GetTickCount64()) + "-" + std::to_string(attempt));
                    if (std::filesystem::create_directory(temporaryDirectory))
                    {
                        return;
                    }
                }
                throw std::runtime_error("Could not create temporary PDB test directory");
            }

            ~TemporaryPair()
            {
                std::error_code cleanupError;
                std::filesystem::remove_all(temporaryDirectory, cleanupError);
            }

            std::filesystem::path temporaryDirectory;
    };
} // namespace

TEST(PdbIdentity, ReadsRsdsGuidAgeAndFileBackedDebugDirectory)
{
    const auto peIdentity = symfind::validation::ReadPeIdentity(SamplePe());
    EXPECT_EQ(peIdentity.Key(), "12345678ABCDEF120123456789ABCDEF2");
    EXPECT_EQ(peIdentity.pdbName, "ntdll.pdb");
    EXPECT_EQ(peIdentity.imageSize, 0x2000u);
    EXPECT_EQ(peIdentity.machine, IMAGE_FILE_MACHINE_AMD64);
}

TEST(PdbIdentity, RejectsTruncatedCodeViewRecord)
{
    auto peImageBytes = SamplePe();
    peImageBytes.resize(0x250);
    EXPECT_THROW(static_cast<void>(symfind::validation::ReadPeIdentity(peImageBytes)),
                 std::runtime_error);
}

TEST(PdbIdentity, RejectsDebugDirectoryOutsideRawSection)
{
    auto peImageBytes = SamplePe();
    // The virtual RVA cannot be interpreted as a file offset.
    Put(peImageBytes,
        0x58 + offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory) +
            IMAGE_DIRECTORY_ENTRY_DEBUG * sizeof(IMAGE_DATA_DIRECTORY),
        IMAGE_DATA_DIRECTORY{0x1200, sizeof(IMAGE_DEBUG_DIRECTORY)});
    EXPECT_THROW(static_cast<void>(symfind::validation::ReadPeIdentity(peImageBytes)),
                 std::runtime_error);
}

TEST(PdbIdentity, RejectsUnterminatedPdbName)
{
    auto peImageBytes = SamplePe();
    peImageBytes[0x261] = 'x';
    EXPECT_THROW(static_cast<void>(symfind::validation::ReadPeIdentity(peImageBytes)),
                 std::runtime_error);
}

TEST(PdbSymbols, RejectsInvalidExplicitPdb)
{
    TemporaryPair temporaryPair;
    const auto dllPath = temporaryPair.temporaryDirectory / "ntdll.dll";
    const auto pdbPath = temporaryPair.temporaryDirectory / "ntdll.pdb";
    const auto peImageBytes = SamplePe();
    {
        std::ofstream imageStream(dllPath, std::ios::binary);
        imageStream.write(reinterpret_cast<const char*>(peImageBytes.data()),
                          static_cast<std::streamsize>(peImageBytes.size()));
        ASSERT_TRUE(imageStream.good());
        std::ofstream pdbStream(pdbPath, std::ios::binary);
        pdbStream << "This is not a PDB";
        ASSERT_TRUE(pdbStream.good());
    }
    const std::array symbolNames = {std::string_view{"LdrpInitialize"}};
    EXPECT_THROW(
        static_cast<void>(symfind::validation::ReadPdbSymbols(dllPath, pdbPath, symbolNames)),
        std::runtime_error);
}

TEST(PdbComparison, WrongFirstCandidateFailsEvenWhenPdbRvaIsAmongCandidates)
{
    const auto comparison =
        symfind::validation::CompareSymbol("LdrpInitialize", {0x2000}, {0x1000}, {0x1000, 0x2000});
    EXPECT_EQ(comparison.status, symfind::validation::ComparisonStatus::Mismatch);
    EXPECT_TRUE(comparison.Ambiguous());
    EXPECT_EQ(comparison.candidateRvas.size(), 2u);
}

TEST(PdbComparison, CorrectFirstCandidateRetainsAmbiguity)
{
    const auto comparison =
        symfind::validation::CompareSymbol("LdrpInitialize", {0x1000}, {0x1000}, {0x1000, 0x2000});
    EXPECT_EQ(comparison.status, symfind::validation::ComparisonStatus::Match);
    EXPECT_TRUE(comparison.Ambiguous());
}

TEST(PdbComparison, MissingPdbNameCannotPassUsingDslCandidate)
{
    const auto comparison =
        symfind::validation::CompareSymbol("LdrpLoadDll", {}, {0x2000}, {0x2000});
    EXPECT_EQ(comparison.status, symfind::validation::ComparisonStatus::MissingPdbSymbol);
}

TEST(PdbComparison, NoDslCandidateIsReportedSeparately)
{
    const auto comparison = symfind::validation::CompareSymbol("LdrpLoadDll", {0x2000}, {}, {});
    EXPECT_EQ(comparison.status, symfind::validation::ComparisonStatus::NoMatch);
}

TEST(PdbComparison, ConfiguredNtdllSymbolsMatchExactPdbRvas)
{
    const auto dllPath = EnvironmentValue("SYMFIND_NTDLL_DLL");
    const auto pdbPath = EnvironmentValue("SYMFIND_NTDLL_PDB");
    auto corpusDirectory = EnvironmentValue("SYMFIND_NTDLL_CORPUS");
    if (dllPath.empty() && pdbPath.empty() && corpusDirectory.empty())
    {
        corpusDirectory = EnvironmentValue("SYMFIND_DEFAULT_NTDLL_CORPUS");
    }
    if (dllPath.empty() && pdbPath.empty() && corpusDirectory.empty())
    {
        GTEST_SKIP() << "PDB validation is not configured. Set SYMFIND_NTDLL_DLL + "
                        "SYMFIND_NTDLL_PDB, or SYMFIND_NTDLL_CORPUS.";
    }
    ASSERT_TRUE(corpusDirectory.empty() || (dllPath.empty() && pdbPath.empty()))
        << "Choose either an explicit DLL/PDB pair or a corpus directory";
    ASSERT_TRUE(!corpusDirectory.empty() || (!dllPath.empty() && !pdbPath.empty()))
        << "Both SYMFIND_NTDLL_DLL and SYMFIND_NTDLL_PDB are required";
    struct QuietAnalysisLog
    {
            spdlog::level::level_enum previousLogLevel = spdlog::get_level();
            QuietAnalysisLog()
            {
                spdlog::set_level(spdlog::level::off);
            }
            ~QuietAnalysisLog()
            {
                spdlog::set_level(previousLogLevel);
            }
    } quietAnalysisLog;

    std::vector<std::pair<std::filesystem::path, std::filesystem::path>> imageSymbolPairs;

    ASSERT_NO_THROW({
        if (corpusDirectory.empty())
        {
            imageSymbolPairs.emplace_back(dllPath, pdbPath);
        }
        else
        {
            imageSymbolPairs = symfind::validation::FindCorpusPairs(corpusDirectory);
        }
    });
    ASSERT_FALSE(imageSymbolPairs.empty());

    for (const auto& [image_path, symbols_path] : imageSymbolPairs)
    {
        SCOPED_TRACE(image_path.string());
        symfind::validation::ComparisonReport comparisonReport;
        // Once opted in, invalid pairs, missing PDB names and mismatches fail.
        ASSERT_NO_THROW(comparisonReport =
                            symfind::validation::CompareNtdllSymbols(image_path, symbols_path));
        ASSERT_EQ(comparisonReport.symbols.size(), symfind::validation::ntdllSymbolRules.size());
        for (const auto& comparison : comparisonReport.symbols)
        {
            EXPECT_EQ(comparison.status, symfind::validation::ComparisonStatus::Match)
                << symfind::validation::Describe(comparison);
        }
    }

    // A loadable PDB for a different RSDS identity must never serve as an oracle.
    TemporaryPair mismatchedPair;
    const auto mismatchedDllPath = mismatchedPair.temporaryDirectory / "ntdll.dll";
    auto peImageBytes = SamplePe();
    const auto expectedPdbIdentity =
        symfind::validation::ReadPeIdentity(imageSymbolPairs.front().first);
    std::memcpy(peImageBytes.data() + 0x244, expectedPdbIdentity.guid.data(),
                expectedPdbIdentity.guid.size());
    peImageBytes[0x244] ^= 1; // Guaranteed different GUID; retain the real PDB age.
    Put(peImageBytes, 0x254, expectedPdbIdentity.age);
    Put(peImageBytes, 0x58 + offsetof(IMAGE_OPTIONAL_HEADER64, SizeOfImage),
        expectedPdbIdentity.imageSize);
    {
        std::ofstream imageStream(mismatchedDllPath, std::ios::binary);
        imageStream.write(reinterpret_cast<const char*>(peImageBytes.data()), peImageBytes.size());
        ASSERT_TRUE(imageStream.good());
    }
    const std::array symbolNames = {std::string_view{"LdrpInitialize"}};
    try
    {
        static_cast<void>(symfind::validation::ReadPdbSymbols(
            mismatchedDllPath, imageSymbolPairs.front().second, symbolNames));
        FAIL() << "Accepted a PDB with a different GUID";
    }
    catch (const std::runtime_error& error)
    {
        EXPECT_NE(std::string(error.what()).find("GUID+age"), std::string::npos) << error.what();
    }
}
