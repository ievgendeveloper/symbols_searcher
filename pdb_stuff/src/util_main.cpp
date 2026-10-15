#include "pdb_stuff/diagnostics.h"
#include "pdb_stuff/fixtures.h"
#include "pdb_stuff/io.h"

#include <iostream>
#include <string_view>

namespace
{
    void usage()
    {
        std::cout << "Usage:\n"
                     "  symfind_pdb_util --pe FILE\n"
                     "  symfind_pdb_util --pdb FILE\n"
                     "  symfind_pdb_util --inspect-delta FILE [--winbindex-metadata GZIP_JSON]\n"
                     "  symfind_pdb_util --apply-delta FILE --source FILE --out FILE --sha256 HASH\n"
                     "PE/PDB diagnostics print JSON; delta output is written only after SHA256 validation.\n";
    }
} // namespace

int main(int argc, char** argv)
{
    using namespace pdb_stuff;
    try
    {
        std::string mode;
        std::filesystem::path input, source, output, metadata;
        std::string expected_hash;
        for (int i = 1; i < argc; ++i)
        {
            const std::string_view option = argv[i];
            if (option == "--help" || option == "-h")
            {
                usage();
                return 0;
            }
            if (i + 1 >= argc)
                throw FixtureError("missing value for " + std::string(option));
            const std::string value = argv[++i];
            if ((option == "--pe" || option == "--pdb" || option == "--inspect-delta" ||
                 option == "--apply-delta") &&
                mode.empty())
            {
                mode = option;
                input = value;
            }
            else if (option == "--source" && source.empty())
                source = value;
            else if (option == "--out" && output.empty())
                output = value;
            else if (option == "--sha256" && expected_hash.empty())
                expected_hash = value;
            else if (option == "--winbindex-metadata" && metadata.empty())
                metadata = value;
            else
                throw FixtureError("unknown or duplicate option: " + std::string(option));
        }
        if (mode.empty())
        {
            usage();
            return 2;
        }
        if (mode == "--pe" || mode == "--pdb")
        {
            if (!source.empty() || !output.empty() || !expected_hash.empty() || !metadata.empty())
                throw FixtureError("PE/PDB inspection does not accept delta options");
            const auto data = read_file(input);
            const auto result = mode == "--pe" ? parse_pe(data) : parse_pdb_identity(data);
            std::cout << result.dump(2) << '\n';
        }
        else if (mode == "--inspect-delta")
        {
            if (!source.empty() || !output.empty() || !expected_hash.empty())
                throw FixtureError("delta inspection does not accept output/source/hash");
            Json index;
            if (!metadata.empty())
            {
                const auto json_bytes = gzip_decompress(read_file(metadata));
                index = Json::parse(json_bytes.begin(), json_bytes.end());
            }
            std::cout << inspect_delta(read_file(input), index).dump(2) << '\n';
        }
        else
        {
            if (source.empty() || output.empty() || expected_hash.empty() || !metadata.empty())
                throw FixtureError("delta application requires --source, --out and --sha256");
            const auto dest = std::filesystem::absolute(output).lexically_normal();
            for (const auto& path : {source, input})
            {
                if (dest == std::filesystem::absolute(path).lexically_normal() ||
                    (std::filesystem::exists(output) && std::filesystem::equivalent(output, path)))
                    throw FixtureError("output would overwrite a source or delta file");
            }
            const auto data = apply_delta(read_file(source), read_file(input), expected_hash);
            atomic_write(output, data);
            std::cout << Json{{"output", std::filesystem::absolute(output).string()},
                              {"file_size", data.size()},
                              {"sha256", sha256(data)}}
                             .dump(2)
                      << '\n';
        }
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << "symfind_pdb_util: " << error.what() << '\n';
        return 1;
    }
}
