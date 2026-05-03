#include "spdlog/spdlog.h"
#include "symfind/dsl_matcher.h"
#include "symfind/function_finder.h"

#include <gtest/gtest.h>

TEST(CollectGlobals, AggregatesXrefsFromFunctions)
{
    using namespace symfind;

    // Build two fake functions with overlapping data refs
    AnalyzedFunction f1;
    f1.rva = 0x1000;
    f1.data_refs = {
        Xref{0x1010, 0xB000, 0x1000, XrefType::DataRef},
        Xref{0x1020, 0xC000, 0x1000, XrefType::DataRead},
    };

    AnalyzedFunction f2;
    f2.rva = 0x2000;
    f2.data_refs = {
        Xref{0x2030, 0xB000, 0x2000, XrefType::DataWrite},
    };

    AnalyzedFunction f3;
    f3.rva = 0x3000; // No data refs

    std::vector<AnalyzedFunction> funcs = {f1, f2, f3};

    auto globals = collect_globals(funcs);

    // Two distinct globals: 0xB000 and 0xC000
    ASSERT_EQ(globals.size(), 2u);

    // Sorted by RVA
    EXPECT_EQ(globals[0].rva, 0xB000u);
    EXPECT_EQ(globals[1].rva, 0xC000u);

    // 0xB000 should have 2 refs (from f1 and f2)
    EXPECT_EQ(globals[0].refs.size(), 2u);

    // 0xC000 should have 1 ref (from f1 only)
    EXPECT_EQ(globals[1].refs.size(), 1u);
    EXPECT_EQ(globals[1].refs[0].from_func, 0x1000u);
    EXPECT_EQ(globals[1].refs[0].type, XrefType::DataRead);
}

TEST(CollectGlobals, EmptyInputProducesEmptyOutput)
{
    using namespace symfind;
    std::vector<AnalyzedFunction> empty;
    auto globals = collect_globals(empty);
    EXPECT_TRUE(globals.empty());
}

TEST(CollectGlobals, FunctionsWithoutDataRefsAreIgnored)
{
    using namespace symfind;
    AnalyzedFunction f;
    f.rva = 0x1000;
    // f.data_refs is empty
    std::vector<AnalyzedFunction> funcs = {f};
    auto globals = collect_globals(funcs);
    EXPECT_TRUE(globals.empty());
}

TEST(AnalysisIntegration, FindRtlDecompressBufferProcsInRealNtdll)
{
    using namespace symfind;
    using namespace symfind::dsl;

    auto module = PeModule::from_file(R"(C:\Windows\System32\ntdll.dll)");
    ASSERT_TRUE(module.has_value());

    auto db = AnalysisDb::analyze(*module);
    EXPECT_GT(db.globals().size(), 0u)
        << "Module should have at least some globals";

    auto rule = DslParser::parse(R"(
        find global in "ntdll" where
            referenced_by "RtlDecompressBuffer";
            take first;
    )");
    ASSERT_TRUE(rule.has_value());

    auto results = DslMatcher::match(db, *rule);
    ASSERT_GE(results.size(), 1u)
        << "Expected to find RtlDecompressBufferProcs via referenced_by";

    spdlog::info("Found candidate at RVA 0x{:X}", results[0].rva);

    // Sanity check: it should land in a non-executable section (.rdata or .data)
    bool in_data_section = false;
    for (const auto& sec : module->sections())
    {
        if (results[0].rva >= sec.virtual_address &&
            results[0].rva < sec.virtual_address + sec.virtual_size)
        {
            in_data_section = !sec.executable;
            break;
        }
    }
    EXPECT_TRUE(in_data_section)
        << "RtlDecompressBufferProcs should live in a data section";
}