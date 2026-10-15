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
    void usage()
    {
        std::cerr << "Usage:\n"
                  << "  symfind_compare_symbols --dll PATH --pdb PATH [--csv FILE]\n"
                  << "  symfind_compare_symbols --corpus DIRECTORY [--csv FILE]\n"
                  << "Corpus: ntdll.dll and its RSDS-named PDB together in each version directory.\n"
                  << "Exit codes: 0 all matched, 1 comparison failed, 2 input/PDB error.\n";
    }
} // namespace

int main(int argc, char* argv[])
{
    using namespace symfind::validation;
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
                usage();
                return 0;
            }
            if (i + 1 == argc)
                throw std::runtime_error("Missing value for " + option);
            const std::filesystem::path value = argv[++i];
            if (option == "--dll" && dll.empty())
                dll = value;
            else if (option == "--pdb" && pdb.empty())
                pdb = value;
            else if (option == "--corpus" && corpus.empty())
                corpus = value;
            else if (option == "--csv" && csv.empty())
                csv = value;
            else
                throw std::runtime_error("Unknown or duplicate option: " + option);
        }
        if ((!corpus.empty() && (!dll.empty() || !pdb.empty())) ||
            (corpus.empty() && (dll.empty() || pdb.empty())))
        {
            usage();
            return 2;
        }

        std::vector<std::pair<std::filesystem::path, std::filesystem::path>> pairs;
        if (corpus.empty())
            pairs.emplace_back(dll, pdb);
        else
            pairs = find_corpus_pairs(corpus);
        // Reject output paths that could overwrite an input file.
        if (!csv.empty())
        {
            const auto output_path = std::filesystem::absolute(csv).lexically_normal();
            for (const auto& [image, symbols] : pairs)
            {
                for (const auto& input : {image, symbols})
                {
                    if (output_path == std::filesystem::absolute(input).lexically_normal() ||
                        (std::filesystem::exists(csv) && std::filesystem::exists(input) &&
                         std::filesystem::equivalent(csv, input)))
                        throw std::runtime_error("CSV output would overwrite a DLL or PDB input");
                }
            }
        }
        std::ofstream csv_file;
        if (!csv.empty())
        {
            if (!csv.parent_path().empty())
                std::filesystem::create_directories(csv.parent_path());
            csv_file.open(csv, std::ios::trunc);
            if (!csv_file)
                throw std::runtime_error("Cannot open CSV output: " + csv.string());
        }
        auto& output = csv.empty() ? std::cout : csv_file;
        write_csv_header(output);
        int exit_code = 0;
        for (const auto& [image, symbols] : pairs)
        {
            try
            {
                const auto report = compare_ntdll_symbols(image, symbols);
                write_csv_report(output, report);
                for (const auto& comparison : report.symbols)
                    std::cerr << image.string() << ": " << describe(comparison) << '\n';
                if (!report.successful() && exit_code == 0)
                    exit_code = 1;
            }
            catch (const std::exception& error)
            {
                std::cerr << image.string() << ": validation error: " << error.what() << '\n';
                write_csv_error(output, image, symbols, error.what());
                exit_code = 2;
            }
        }
        output.flush();
        if (!output)
            throw std::runtime_error("Could not write complete CSV report");
        return exit_code;
    }
    catch (const std::exception& error)
    {
        std::cerr << "Error: " << error.what() << '\n';
        return 2;
    }
}
