#include "ntdll_symbol_rules.h"
#include "spdlog/spdlog.h"
#include "symfind/dsl_matcher.h"
#include "symfind/function_finder.h"

#include <gtest/gtest.h>

TEST(CollectGlobals, AggregatesXrefsFromFunctions)
{
    // Build two fake functions with overlapping data refs
    symfind::AnalyzedFunction functionWithTwoDataReferences;
    functionWithTwoDataReferences.rva = 0x1000;
    functionWithTwoDataReferences.dataRefs = {
        symfind::Xref{0x1010, 0xB000, 0x1000, symfind::XrefType::DataRef},
        symfind::Xref{0x1020, 0xC000, 0x1000, symfind::XrefType::DataRead},
    };

    symfind::AnalyzedFunction functionWithSharedDataReference;
    functionWithSharedDataReference.rva = 0x2000;
    functionWithSharedDataReference.dataRefs = {
        symfind::Xref{0x2030, 0xB000, 0x2000, symfind::XrefType::DataWrite},
    };

    symfind::AnalyzedFunction functionWithoutDataReferences;
    functionWithoutDataReferences.rva = 0x3000; // No data refs

    std::vector<symfind::AnalyzedFunction> analyzedFunctions = {functionWithTwoDataReferences,
                                                                functionWithSharedDataReference,
                                                                functionWithoutDataReferences};

    auto collectedGlobals = symfind::CollectGlobals(analyzedFunctions);

    // Two distinct globals: 0xB000 and 0xC000
    ASSERT_EQ(collectedGlobals.size(), 2u);

    // Sorted by RVA
    EXPECT_EQ(collectedGlobals[0].rva, 0xB000u);
    EXPECT_EQ(collectedGlobals[1].rva, 0xC000u);

    // 0xB000 should have 2 refs from both referencing functions
    EXPECT_EQ(collectedGlobals[0].refs.size(), 2u);

    // 0xC000 should have 1 ref from the function with two data references only
    EXPECT_EQ(collectedGlobals[1].refs.size(), 1u);
    EXPECT_EQ(collectedGlobals[1].refs[0].fromFunc, 0x1000u);
    EXPECT_EQ(collectedGlobals[1].refs[0].type, symfind::XrefType::DataRead);
}

TEST(CollectGlobals, EmptyInputProducesEmptyOutput)
{
    std::vector<symfind::AnalyzedFunction> emptyFunctions;
    auto collectedGlobals = symfind::CollectGlobals(emptyFunctions);
    EXPECT_TRUE(collectedGlobals.empty());
}

TEST(CollectGlobals, FunctionsWithoutDataRefsAreIgnored)
{
    symfind::AnalyzedFunction functionWithoutDataReferences;
    functionWithoutDataReferences.rva = 0x1000;
    // function_without_data_references.dataRefs is empty
    std::vector<symfind::AnalyzedFunction> analyzedFunctions = {functionWithoutDataReferences};
    auto collectedGlobals = symfind::CollectGlobals(analyzedFunctions);
    EXPECT_TRUE(collectedGlobals.empty());
}

TEST(AnalysisIntegration, FindRtlDecompressBufferProcsInRealNtdll)
{
    auto ntdllModule = symfind::PeModule::FromFile(R"(C:\Windows\System32\ntdll.dll)");
    ASSERT_TRUE(ntdllModule.has_value());

    auto analysisDatabase = symfind::AnalysisDb::Analyze(*ntdllModule);
    EXPECT_GT(analysisDatabase.Globals().size(), 0u) << "Module should have at least some globals";

    auto symbolRule = symfind::dsl::DslParser::Parse(
        symfind::validation::NtdllRuleFor("RtlDecompressBufferProcs"));
    ASSERT_TRUE(symbolRule.has_value());

    auto matchedSymbols = symfind::dsl::DslMatcher::Match(analysisDatabase, *symbolRule);
    ASSERT_GE(matchedSymbols.size(), 1u)
        << "Expected to find RtlDecompressBufferProcs via referenced_by";

    SPDLOG_INFO("Found candidate at RVA 0x{:X}", matchedSymbols[0].rva);

    // Sanity check: it should land in a non-executable section (.rdata or .data)
    bool candidateIsInDataSection = false;
    for (const auto& section : ntdllModule->Sections())
    {
        if (matchedSymbols[0].rva >= section.virtualAddress &&
            matchedSymbols[0].rva < section.virtualAddress + section.virtualSize)
        {
            candidateIsInDataSection = !section.executable;
            break;
        }
    }
    EXPECT_TRUE(candidateIsInDataSection)
        << "RtlDecompressBufferProcs should live in a data section";
}
