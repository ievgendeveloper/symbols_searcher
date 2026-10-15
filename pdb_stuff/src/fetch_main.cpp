#include "pdb_stuff/fixtures.h"

#include <iostream>
#include <string_view>

namespace
{
    void usage()
    {
        std::cout << "Usage: symfind_fetch_ntdll [options]\n"
                     "  --manifest FILE        Pinned corpus manifest (default: pdb_stuff/ntdll_fixtures.json)\n"
                     "  --out DIRECTORY        Corpus directory (default: pdb_stuff/corpus)\n"
                     "  --label NAME           Select a fixture; repeat for several\n"
                     "  --allow-network        Explicitly enable Microsoft/Winbindex downloads\n"
                     "  --dll FILE --label NAME [--pdb FILE]   Import a local x64 pair\n"
                     "  --source-url URL --os TEXT             Record import provenance\n"
                     "  --refresh-winbindex    Refresh manifest client pins from Winbindex\n"
                     "  --winbindex-metadata FILE              Refresh from local gzip JSON\n"
                     "  --allow-missing        Permit absent fixtures, never invalid files\n"
                     "Exit codes: 0 selected fixtures ready, 1 validation/fetch error, 2 argument error.\n";
    }
} // namespace

int main(int argc, char** argv)
{
    using namespace pdb_stuff;
    FetchOptions options;
    const std::filesystem::path root = SYMFIND_SOURCE_DIR;
    options.manifest_path = root / "pdb_stuff/ntdll_fixtures.json";
    options.output_root = root / "pdb_stuff/corpus";
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
            if (option == "--allow-network")
            {
                options.allow_network = true;
                continue;
            }
            if (option == "--allow-missing")
            {
                options.allow_missing = true;
                continue;
            }
            if (option == "--refresh-winbindex")
            {
                options.refresh_winbindex = true;
                continue;
            }
            if (i + 1 >= argc)
                throw FixtureError("missing value for " + std::string(option));
            const std::string value = argv[++i];
            if (option == "--manifest")
                options.manifest_path = value;
            else if (option == "--out")
                options.output_root = value;
            else if (option == "--label")
                options.labels.push_back(value);
            else if (option == "--dll" && !options.source_dll)
                options.source_dll = value;
            else if (option == "--pdb" && !options.source_pdb)
                options.source_pdb = value;
            else if (option == "--source-url")
                options.source_url = value;
            else if (option == "--os")
                options.os = value;
            else if (option == "--winbindex-metadata" && !options.winbindex_metadata)
                options.winbindex_metadata = value;
            else
                throw FixtureError("unknown or duplicate option: " + std::string(option));
        }
    }
    catch (const std::exception& error)
    {
        std::cerr << "Error: " << error.what() << '\n';
        usage();
        return 2;
    }
    try
    {
        const auto result = process_manifest(options);
        for (const auto& fixture : result.fixtures)
        {
            std::cout << fixture.at("label").get<std::string>() << ": "
                      << fixture.at("status").get<std::string>();
            if (fixture.contains("pe") && fixture.at("pe").contains("version") &&
                fixture.at("pe").at("version").is_string())
                std::cout << " (" << fixture.at("pe").at("version").get<std::string>() << ')';
            if (fixture.contains("reason"))
                std::cout << " - " << fixture.at("reason").get<std::string>();
            std::cout << '\n';
        }
        return result.successful ? 0 : 1;
    }
    catch (const std::exception& error)
    {
        std::cerr << "symfind_fetch_ntdll: " << error.what() << '\n';
        return 1;
    }
}
