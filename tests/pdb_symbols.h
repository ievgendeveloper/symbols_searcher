#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <iosfwd>
#include <map>
#include <nonstd/span.hpp>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace symfind::validation
{
    struct PdbIdentity
    {
            std::array<uint8_t, 16> guid{};
            uint32_t age = 0;
            uint32_t imageSize = 0;
            uint16_t machine = 0;
            std::string pdbName;

            [[nodiscard]] std::string Key() const;
    };

    // Reads the DLL's RSDS record without consulting symfind's analysis or PDBs.
    // Malformed, unsupported or missing metadata throws std::runtime_error.
    [[nodiscard]] PdbIdentity ReadPeIdentity(nonstd::span<const uint8_t> imageBytes);
    [[nodiscard]] PdbIdentity ReadPeIdentity(const std::filesystem::path& dllPath);

    struct PdbSymbols
    {
            PdbIdentity identity;
            std::map<std::string, std::vector<uint64_t>> rvas;
    };

    // Loads the DLL as symbol-handler data with exactly this local PDB, staged
    // alone under its RSDS basename. Requires SymPdb and matching GUID+DBI age,
    // and serializes all DbgHelp calls. No symbol-server fallback or execution.
    [[nodiscard]] PdbSymbols ReadPdbSymbols(const std::filesystem::path& dllPath,
                                            const std::filesystem::path& pdbPath,
                                            nonstd::span<const std::string_view> symbolNames);

    enum class ComparisonStatus
    {
        Match,
        Mismatch,
        MissingPdbSymbol,
        NoMatch
    };
    [[nodiscard]] std::string_view StatusName(ComparisonStatus comparisonStatus);

    struct SymbolComparison
    {
            std::string symbol;
            std::vector<uint64_t> pdbRvas;
            std::vector<uint64_t> selectedRvas;
            std::vector<uint64_t> candidateRvas;
            ComparisonStatus status = ComparisonStatus::MissingPdbSymbol;

            [[nodiscard]] bool Ambiguous() const;
    };

    [[nodiscard]] SymbolComparison CompareSymbol(std::string_view symbolName,
                                                 std::vector<uint64_t> pdbRvas,
                                                 std::vector<uint64_t> selectedRvas,
                                                 std::vector<uint64_t> candidateRvas);

    struct ComparisonReport
    {
            std::filesystem::path dll;
            std::filesystem::path pdb;
            PdbIdentity identity;
            std::vector<SymbolComparison> symbols;

            [[nodiscard]] bool Successful() const;
    };

    [[nodiscard]] ComparisonReport CompareNtdllSymbols(const std::filesystem::path& dllPath,
                                                       const std::filesystem::path& pdbPath);
    [[nodiscard]] std::vector<std::pair<std::filesystem::path, std::filesystem::path>>
        FindCorpusPairs(const std::filesystem::path& corpusDirectory);

    [[nodiscard]] std::string Describe(const SymbolComparison& symbolComparison);
    void WriteCsvHeader(std::ostream& csvOutput);
    void WriteCsvReport(std::ostream& csvOutput, const ComparisonReport& comparisonReport);
    void WriteCsvError(std::ostream& csvOutput, const std::filesystem::path& dllPath,
                       const std::filesystem::path& pdbPath, std::string_view errorMessage);
} // namespace symfind::validation
