#include "pdb_stuff/corpus.h"

#include <cstdlib>
#include <iostream>
#include <string_view>

namespace
{
    std::string environment_value(const char* name)
    {
        char* value = nullptr;
        size_t size = 0;
        if (_dupenv_s(&value, &size, name) != 0)
            throw pdb_stuff::FixtureError("Could not read environment variable");
        const std::string result = value ? value : "";
        std::free(value);
        return result;
    }

    void usage()
    {
        std::cout << "Usage: symfind_corpus_manager MODE [options]\n"
                     "  --ensure            Validate cache; stage and publish missing fixtures\n"
                     "  --prepare-tests     Ensure default corpus unless test environment overrides it\n"
                     "  --verify-network    Download all pinned fixtures into a new isolated run\n"
                     "  --manifest FILE     Pinned manifest (default: pdb_stuff/ntdll_fixtures.json)\n"
                     "  --corpus DIRECTORY  Persistent corpus (default: pdb_stuff/corpus)\n"
                     "  --checks DIRECTORY  Fresh runs (default: pdb_stuff/reproducibility-check)\n"
                     "  --allow-network     Allow downloads; missing data otherwise fails offline\n"
                     "Existing cached files are never replaced by this utility.\n";
    }

    bool use_explicit_test_fixture(const std::filesystem::path& default_corpus)
    {
        if (!environment_value("SYMFIND_NTDLL_DLL").empty() ||
            !environment_value("SYMFIND_NTDLL_PDB").empty())
            return true;
        const auto custom_corpus = environment_value("SYMFIND_NTDLL_CORPUS");
        if (custom_corpus.empty())
            return false;
        std::error_code error;
        if (std::filesystem::equivalent(custom_corpus, default_corpus, error))
            return false;
        // Resolve existing parents even if the corpus itself is absent.
        return std::filesystem::weakly_canonical(custom_corpus) !=
               std::filesystem::weakly_canonical(default_corpus);
    }
} // namespace

int main(int argc, char** argv)
{
    const std::filesystem::path source = SYMFIND_SOURCE_DIR;
    std::filesystem::path manifest = source / "pdb_stuff/ntdll_fixtures.json";
    std::filesystem::path corpus = source / "pdb_stuff/corpus";
    std::filesystem::path checks = source / "pdb_stuff/reproducibility-check";
    std::string mode;
    bool allow_network = false;
    try
    {
        for (int i = 1; i < argc; ++i)
        {
            const std::string_view option = argv[i];
            if (option == "--help" || option == "-h")
            {
                usage();
                return 0;
            }
            if (option == "--ensure" || option == "--prepare-tests" || option == "--verify-network")
            {
                if (!mode.empty())
                    throw pdb_stuff::FixtureError("Choose exactly one mode");
                mode = option;
            }
            else if (option == "--allow-network")
                allow_network = true;
            else if (option == "--manifest" || option == "--corpus" || option == "--checks")
            {
                if (++i >= argc)
                    throw pdb_stuff::FixtureError("Missing value for " + std::string(option));
                if (option == "--manifest")
                    manifest = argv[i];
                else if (option == "--corpus")
                    corpus = argv[i];
                else
                    checks = argv[i];
            }
            else
                throw pdb_stuff::FixtureError("Unknown option: " + std::string(option));
        }
        if (mode.empty())
            throw pdb_stuff::FixtureError("A mode is required");
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << '\n';
        usage();
        return 2;
    }

    try
    {
        if (mode == "--prepare-tests" && use_explicit_test_fixture(corpus))
        {
            std::cout << "Explicit test fixture configured; default corpus preparation is unnecessary.\n";
            return 0;
        }
        const auto result = mode == "--verify-network"
                                ? pdb_stuff::verify_fresh_corpus(manifest, checks, corpus, allow_network)
                                : pdb_stuff::ensure_corpus(manifest, corpus, allow_network);
        for (const auto& fixture : result.fixtures)
        {
            std::cout << fixture.at("label").get<std::string>() << ": "
                      << fixture.at("status").get<std::string>();
            if (fixture.contains("reason"))
                std::cout << " - " << fixture.at("reason").get<std::string>();
            std::cout << '\n';
        }
        if (!result.report_manifest.empty())
            std::cout << "Report: " << result.report_manifest.string() << '\n';
        if (!result.successful)
        {
            if (!result.reason.empty())
                std::cerr << result.reason << '\n';
            std::cerr << "Corpus verification failed; existing corpus files were preserved.\n";
            return 1;
        }
        std::cout << (mode == "--verify-network" ? "Fresh network corpus verified.\n"
                      : result.provisioned       ? "Missing fixtures prepared and published.\n"
                                                 : "Cached corpus verified; no downloads or file changes.\n");
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << "symfind_corpus_manager: " << error.what() << '\n';
        return 1;
    }
}
