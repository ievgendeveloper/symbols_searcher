#include "pdb_symbols.h"

#include <spdlog/spdlog.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace
{
    void Usage()
    {
        std::cerr
            << "Usage:\n"
            << "  symfind_compare_symbols --dll PATH --pdb PATH [--csv FILE]\n"
            << "  symfind_compare_symbols --corpus DIRECTORY [--csv FILE]\n"
            << "Corpus: ntdll.dll and its RSDS-named PDB together in each version directory.\n"
            << "Exit codes: 0 all matched, 1 comparison failed, 2 input/PDB error.\n";
    }
} // namespace

int main(int argc, char* argv[])
{
    // Keep stdout a machine-readable CSV stream.
    spdlog::set_level(spdlog::level::off);
    try
    {
        std::filesystem::path dll, pdb, corpus, csv;
        for (int i = 1; i < argc; ++i)
        {
            const std::string option = argv[i];
            if (option == "--help" || option == "-h")
            {
                Usage();
                return 0;
            }
            if (i + 1 == argc)
            {
                throw std::runtime_error("Missing value for " + option);
            }
            const std::filesystem::path value = argv[++i];
            if (option == "--dll" && dll.empty())
            {
                dll = value;
            }
            else if (option == "--pdb" && pdb.empty())
            {
                pdb = value;
            }
            else if (option == "--corpus" && corpus.empty())
            {
                corpus = value;
            }
            else if (option == "--csv" && csv.empty())
            {
                csv = value;
            }
            else
            {
                throw std::runtime_error("Unknown or duplicate option: " + option);
            }
        }
        if ((!corpus.empty() && (!dll.empty() || !pdb.empty())) ||
            (corpus.empty() && (dll.empty() || pdb.empty())))
        {
            Usage();
            return 2;
        }

        std::vector<std::pair<std::filesystem::path, std::filesystem::path>> pairs;
        if (corpus.empty())
        {
            pairs.emplace_back(dll, pdb);
        }
        else
        {
            pairs = symfind::validation::FindCorpusPairs(corpus);
        }
        // Reject output paths that could overwrite an input file.
        if (!csv.empty())
        {
            const auto outputPath = std::filesystem::absolute(csv).lexically_normal();
            for (const auto& [image, symbols] : pairs)
            {
                for (const auto& input : {image, symbols})
                {
                    if (outputPath == std::filesystem::absolute(input).lexically_normal() ||
                        (std::filesystem::exists(csv) && std::filesystem::exists(input) &&
                         std::filesystem::equivalent(csv, input)))
                    {
                        throw std::runtime_error("CSV output would overwrite a DLL or PDB input");
                    }
                }
            }
        }
        std::ofstream csvFile;
        if (!csv.empty())
        {
            if (!csv.parent_path().empty())
            {
                std::filesystem::create_directories(csv.parent_path());
            }
            csvFile.open(csv, std::ios::trunc);
            if (!csvFile)
            {
                throw std::runtime_error("Cannot open CSV output: " + csv.string());
            }
        }
        auto& output = csv.empty() ? std::cout : csvFile;
        symfind::validation::WriteCsvHeader(output);
        int exitCode = 0;
        for (const auto& [image, symbols] : pairs)
        {
            try
            {
                const auto report = symfind::validation::CompareNtdllSymbols(image, symbols);
                symfind::validation::WriteCsvReport(output, report);
                for (const auto& comparison : report.symbols)
                {
                    std::cerr << image.string() << ": " << symfind::validation::Describe(comparison)
                              << '\n';
                }
                if (!report.Successful() && exitCode == 0)
                {
                    exitCode = 1;
                }
            }
            catch (const std::exception& error)
            {
                std::cerr << image.string() << ": validation error: " << error.what() << '\n';
                symfind::validation::WriteCsvError(output, image, symbols, error.what());
                exitCode = 2;
            }
        }
        output.flush();
        if (!output)
        {
            throw std::runtime_error("Could not write complete CSV report");
        }
        return exitCode;
    }
    catch (const std::exception& error)
    {
        std::cerr << "Error: " << error.what() << '\n';
        return 2;
    }
}
