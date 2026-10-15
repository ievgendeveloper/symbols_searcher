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
    template <class T>
    void put(std::vector<uint8_t>& bytes, size_t offset, const T& value)
    {
        std::memcpy(bytes.data() + offset, &value, sizeof(value));
    }

    // A tiny on-disk PE with a debug directory in one file-backed section.
    std::vector<uint8_t> sample_pe()
    {
        std::vector<uint8_t> bytes(0x400);
        IMAGE_DOS_HEADER dos{};
        dos.e_magic = IMAGE_DOS_SIGNATURE;
        dos.e_lfanew = 0x40;
        put(bytes, 0, dos);
        put(bytes, 0x40, DWORD{IMAGE_NT_SIGNATURE});
        IMAGE_FILE_HEADER file{};
        file.Machine = IMAGE_FILE_MACHINE_AMD64;
        file.NumberOfSections = 1;
        file.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
        put(bytes, 0x44, file);
        IMAGE_OPTIONAL_HEADER64 optional{};
        optional.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        optional.SizeOfImage = 0x2000;
        optional.SizeOfHeaders = 0x200;
        optional.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG] = {0x1000, sizeof(IMAGE_DEBUG_DIRECTORY)};
        put(bytes, 0x58, optional);
        IMAGE_SECTION_HEADER section{};
        section.VirtualAddress = 0x1000;
        section.SizeOfRawData = 0x200;
        section.PointerToRawData = 0x200;
        put(bytes, 0x58 + sizeof(optional), section);
        IMAGE_DEBUG_DIRECTORY debug{};
        debug.Type = IMAGE_DEBUG_TYPE_CODEVIEW;
        debug.SizeOfData = 34;
        debug.AddressOfRawData = 0x1040;
        debug.PointerToRawData = 0x240;
        put(bytes, 0x200, debug);
        std::memcpy(bytes.data() + 0x240, reinterpret_cast<void const*>("RSDS"), 4);
        const GUID guid{0x12345678, 0xABCD, 0xEF12, {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}};
        put(bytes, 0x244, guid);
        put(bytes, 0x254, uint32_t{2});
        std::memcpy(bytes.data() + 0x258, reinterpret_cast<void const*>("ntdll.pdb"), 10);
        return bytes;
    }

    std::string environment_value(const char* name)
    {
        // _dupenv_s avoids borrowed environment pointers on the MSVC CRT.
        char* value = nullptr;
        size_t size = 0;
        if (::_dupenv_s(&value, &size, name) != 0)
        {
            throw std::runtime_error("Could not read environment variable");
        }

        const std::string result = value ? value : "";
        std::free(value);
        return result;
    }

    class TemporaryPair
    {
        public:
            TemporaryPair()
            {
                for (unsigned attempt = 0; attempt < 100; ++attempt)
                {
                    directory = std::filesystem::temp_directory_path() /
                                ("symfind-pdb-test-" + std::to_string(GetCurrentProcessId()) + "-" +
                                 std::to_string(GetTickCount64()) + "-" + std::to_string(attempt));
                    if (std::filesystem::create_directory(directory))
                        return;
                }
                throw std::runtime_error("Could not create temporary PDB test directory");
            }

            ~TemporaryPair()
            {
                std::error_code ignored;
                std::filesystem::remove_all(directory, ignored);
            }

            std::filesystem::path directory;
    };
} // namespace

TEST(PdbIdentity, ReadsRsdsGuidAgeAndFileBackedDebugDirectory)
{
    const auto identity = symfind::validation::read_pe_identity(sample_pe());
    EXPECT_EQ(identity.key(), "12345678ABCDEF120123456789ABCDEF2");
    EXPECT_EQ(identity.pdb_name, "ntdll.pdb");
    EXPECT_EQ(identity.image_size, 0x2000u);
    EXPECT_EQ(identity.machine, IMAGE_FILE_MACHINE_AMD64);
}

TEST(PdbIdentity, RejectsTruncatedCodeViewRecord)
{
    auto bytes = sample_pe();
    bytes.resize(0x250);
    EXPECT_THROW(static_cast<void>(symfind::validation::read_pe_identity(bytes)), std::runtime_error);
}

TEST(PdbIdentity, RejectsDebugDirectoryOutsideRawSection)
{
    auto bytes = sample_pe();
    // The virtual RVA cannot be interpreted as a file offset.
    put(bytes, 0x58 + offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory) + IMAGE_DIRECTORY_ENTRY_DEBUG * sizeof(IMAGE_DATA_DIRECTORY),
        IMAGE_DATA_DIRECTORY{0x1200, sizeof(IMAGE_DEBUG_DIRECTORY)});
    EXPECT_THROW(static_cast<void>(symfind::validation::read_pe_identity(bytes)), std::runtime_error);
}

TEST(PdbIdentity, RejectsUnterminatedPdbName)
{
    auto bytes = sample_pe();
    bytes[0x261] = 'x';
    EXPECT_THROW(static_cast<void>(symfind::validation::read_pe_identity(bytes)), std::runtime_error);
}

TEST(PdbSymbols, RejectsInvalidExplicitPdb)
{
    TemporaryPair temporary;
    const auto dll = temporary.directory / "ntdll.dll";
    const auto pdb = temporary.directory / "ntdll.pdb";
    const auto bytes = sample_pe();
    {
        std::ofstream image(dll, std::ios::binary);
        image.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        ASSERT_TRUE(image.good());
        std::ofstream symbols(pdb, std::ios::binary);
        symbols << "This is not a PDB";
        ASSERT_TRUE(symbols.good());
    }
    const std::array names = {std::string_view{"LdrpInitialize"}};
    EXPECT_THROW(static_cast<void>(symfind::validation::read_pdb_symbols(dll, pdb, names)), std::runtime_error);
}

TEST(PdbComparison, WrongFirstCandidateFailsEvenWhenPdbRvaIsAmongCandidates)
{
    using namespace symfind::validation;
    const auto row = compare_symbol("LdrpInitialize", {0x2000}, {0x1000}, {0x1000, 0x2000});
    EXPECT_EQ(row.status, ComparisonStatus::Mismatch);
    EXPECT_TRUE(row.ambiguous());
    EXPECT_EQ(row.candidate_rvas.size(), 2u);
}

TEST(PdbComparison, CorrectFirstCandidateRetainsAmbiguity)
{
    using namespace symfind::validation;
    const auto row = compare_symbol("LdrpInitialize", {0x1000}, {0x1000}, {0x1000, 0x2000});
    EXPECT_EQ(row.status, ComparisonStatus::Match);
    EXPECT_TRUE(row.ambiguous());
}

TEST(PdbComparison, MissingPdbNameCannotPassUsingDslCandidate)
{
    using namespace symfind::validation;
    const auto row = compare_symbol("LdrpLoadDll", {}, {0x2000}, {0x2000});
    EXPECT_EQ(row.status, ComparisonStatus::MissingPdbSymbol);
}

TEST(PdbComparison, NoDslCandidateIsReportedSeparately)
{
    using namespace symfind::validation;
    const auto row = compare_symbol("LdrpLoadDll", {0x2000}, {}, {});
    EXPECT_EQ(row.status, ComparisonStatus::NoMatch);
}

TEST(PdbComparison, ConfiguredNtdllSymbolsMatchExactPdbRvas)
{
    using namespace symfind::validation;
    const auto dll = environment_value("SYMFIND_NTDLL_DLL");
    const auto pdb = environment_value("SYMFIND_NTDLL_PDB");
    auto corpus = environment_value("SYMFIND_NTDLL_CORPUS");
    if (dll.empty() && pdb.empty() && corpus.empty())
        corpus = environment_value("SYMFIND_DEFAULT_NTDLL_CORPUS");
    if (dll.empty() && pdb.empty() && corpus.empty())
        GTEST_SKIP() << "PDB validation is not configured. Set SYMFIND_NTDLL_DLL + "
                        "SYMFIND_NTDLL_PDB, or SYMFIND_NTDLL_CORPUS.";
    ASSERT_TRUE(corpus.empty() || (dll.empty() && pdb.empty()))
        << "Choose either an explicit DLL/PDB pair or a corpus directory";
    ASSERT_TRUE(!corpus.empty() || (!dll.empty() && !pdb.empty()))
        << "Both SYMFIND_NTDLL_DLL and SYMFIND_NTDLL_PDB are required";
    struct QuietAnalysisLog
    {
            spdlog::level::level_enum previous = spdlog::get_level();
            QuietAnalysisLog()
            {
                spdlog::set_level(spdlog::level::off);
            }
            ~QuietAnalysisLog()
            {
                spdlog::set_level(previous);
            }
    } quiet_log;

    std::vector<std::pair<std::filesystem::path, std::filesystem::path>> pairs;

    ASSERT_NO_THROW({
        if (corpus.empty())
            pairs.emplace_back(dll, pdb);
        else
            pairs = find_corpus_pairs(corpus);
    });
    ASSERT_FALSE(pairs.empty());

    for (const auto& [image, symbols] : pairs)
    {
        SCOPED_TRACE(image.string());
        ComparisonReport report;
        // Once opted in, invalid pairs, missing PDB names and mismatches fail.
        ASSERT_NO_THROW(report = compare_ntdll_symbols(image, symbols));
        ASSERT_EQ(report.symbols.size(), ntdll_symbol_rules.size());
        for (const auto& comparison : report.symbols)
            EXPECT_EQ(comparison.status, ComparisonStatus::Match) << describe(comparison);
    }

    // A loadable PDB for a different RSDS identity must never serve as an oracle.
    TemporaryPair mismatched;
    const auto wrong_dll = mismatched.directory / "ntdll.dll";
    auto bytes = sample_pe();
    const auto actual_identity = read_pe_identity(pairs.front().first);
    std::memcpy(bytes.data() + 0x244, actual_identity.guid.data(), actual_identity.guid.size());
    bytes[0x244] ^= 1; // Guaranteed different GUID; retain the real PDB age.
    put(bytes, 0x254, actual_identity.age);
    put(bytes, 0x58 + offsetof(IMAGE_OPTIONAL_HEADER64, SizeOfImage), actual_identity.image_size);
    {
        std::ofstream image(wrong_dll, std::ios::binary);
        image.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        ASSERT_TRUE(image.good());
    }
    const std::array names = {std::string_view{"LdrpInitialize"}};
    try
    {
        static_cast<void>(read_pdb_symbols(wrong_dll, pairs.front().second, names));
        FAIL() << "Accepted a PDB with a different GUID";
    }
    catch (const std::runtime_error& error)
    {
        EXPECT_NE(std::string(error.what()).find("GUID+age"), std::string::npos) << error.what();
    }
}
