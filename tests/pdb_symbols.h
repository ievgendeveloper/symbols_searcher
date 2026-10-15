#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <iosfwd>
#include <map>
#include <span>
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
            uint32_t image_size = 0;
            uint16_t machine = 0;
            std::string pdb_name;

            [[nodiscard]] std::string key() const;
    };

    // Reads the DLL's RSDS record without consulting symfind's analysis or PDBs.
    // Malformed, unsupported or missing metadata throws std::runtime_error.
    [[nodiscard]] PdbIdentity read_pe_identity(std::span<const uint8_t> bytes);
    [[nodiscard]] PdbIdentity read_pe_identity(const std::filesystem::path& dll);

    struct PdbSymbols
    {
            PdbIdentity identity;
            std::map<std::string, std::vector<uint64_t>> rvas;
    };

    // Loads the DLL as symbol-handler data with exactly this local PDB, staged
    // alone under its RSDS basename. Requires SymPdb and matching GUID+DBI age,
    // and serializes all DbgHelp calls. No symbol-server fallback or execution.
    [[nodiscard]] PdbSymbols read_pdb_symbols(
        const std::filesystem::path& dll,
        const std::filesystem::path& pdb,
        std::span<const std::string_view> names);

    enum class ComparisonStatus
    {
        Match,
        Mismatch,
        MissingPdbSymbol,
        NoMatch
    };
    [[nodiscard]] std::string_view status_name(ComparisonStatus status);

    struct SymbolComparison
    {
            std::string symbol;
            std::vector<uint64_t> pdb_rvas;
            std::vector<uint64_t> selected_rvas;
            std::vector<uint64_t> candidate_rvas;
            ComparisonStatus status = ComparisonStatus::MissingPdbSymbol;

            [[nodiscard]] bool ambiguous() const;
    };

    [[nodiscard]] SymbolComparison compare_symbol(
        std::string_view symbol,
        std::vector<uint64_t> pdb_rvas,
        std::vector<uint64_t> selected_rvas,
        std::vector<uint64_t> candidate_rvas);

    struct ComparisonReport
    {
            std::filesystem::path dll;
            std::filesystem::path pdb;
            PdbIdentity identity;
            std::vector<SymbolComparison> symbols;

            [[nodiscard]] bool successful() const;
    };

    [[nodiscard]] ComparisonReport compare_ntdll_symbols(
        const std::filesystem::path& dll, const std::filesystem::path& pdb);
    [[nodiscard]] std::vector<std::pair<std::filesystem::path, std::filesystem::path>>
        find_corpus_pairs(const std::filesystem::path& directory);

    [[nodiscard]] std::string describe(const SymbolComparison& comparison);
    void write_csv_header(std::ostream& output);
    void write_csv_report(std::ostream& output, const ComparisonReport& report);
    void write_csv_error(std::ostream& output, const std::filesystem::path& dll,
                         const std::filesystem::path& pdb, std::string_view error);
} // namespace symfind::validation
