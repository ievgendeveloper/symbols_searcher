#include <symfind/symfind.h>
#include <spdlog/spdlog.h>

#include <cstdio>

int main(int argc, char* argv[])
{
    spdlog::set_level(spdlog::level::info);

    if (argc < 2)
    {
        std::printf("Usage: %s <path_to_ntdll.dll>\n", argv[0]);
        std::printf("\nExample DSL rules this tool can process:\n\n");

        std::printf("  # Find LdrpInitialize\n");
        std::printf("  find function in \"ntdll\" where\n");
        std::printf("      called_by \"LdrInitializeThunk\"\n");
        std::printf("      not exported\n");
        std::printf("      take first\n\n");

        std::printf("  # Find LdrpLoadDll\n");
        std::printf("  find function in \"ntdll\" where\n");
        std::printf("      called_by \"LdrLoadDll\"\n");
        std::printf("      not exported\n");
        std::printf("      calls \"RtlGetCurrentServiceSessionId\"\n\n");

        std::printf("  # Find RtlDecompressBufferProcs\n");
        std::printf("  find global in \"ntdll\" where\n");
        std::printf("      referenced_by \"RtlDecompressBuffer\"\n");
        std::printf("      take first\n");

        return 1;
    }

    const char* pe_path = argv[1];

    // Step 1: Load the PE module
    SPDLOG_INFO("Loading PE module: {}", pe_path);
    auto module = symfind::PeModule::from_file(pe_path);
    if (!module)
    {
        SPDLOG_ERROR("Failed to load PE module");
        return 1;
    }

    // Step 2: Run analysis
    SPDLOG_INFO("Running analysis...");
    auto db = symfind::AnalysisDb::analyze(*module);

    // Step 3: Define a DSL rule
    const char* dsl_rule = R"(
        find function in "ntdll" where
            called_by "LdrLoadDll"
            not exported
            calls "RtlGetCurrentServiceSessionId"
    )";

    // Step 4: Parse the rule
    SPDLOG_INFO("Parsing DSL rule...");
    auto rule = symfind::dsl::DslParser::parse(dsl_rule);
    if (!rule)
    {
        SPDLOG_ERROR("Failed to parse DSL rule");
        return 1;
    }

    // Step 5: Match
    SPDLOG_INFO("Searching for matching symbols...");
    auto results = symfind::dsl::DslMatcher::match(db, *rule);

    if (results.empty())
    {
        SPDLOG_WARN("No matches found");
    }
    else
    {
        for (const auto& result : results)
        {
            std::printf("FOUND: %s at RVA 0x%llX\n",
                        result.name.c_str(),
                        static_cast<unsigned long long>(result.rva));
        }
    }

    return 0;
}