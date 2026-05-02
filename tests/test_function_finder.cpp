#include "spdlog/spdlog.h"

#include <gtest/gtest.h>

#include "symfind/analysis_db.h"
#include "symfind/dsl_matcher.h"
#include "symfind/dsl_parser.h"
#include "symfind/function_finder.h"

TEST(FunctionFinder, Search_functions_by_exceptions_parsing_in_ntdll)
{
    auto module = symfind::PeModule::from_file(R"(C:\Windows\System32\ntdll.dll)");
    ASSERT_TRUE(module.has_value());

    std::vector<symfind::Function> functions;
    symfind::FunctionFinder::from_exception_directory(*module, functions);

    EXPECT_GT(functions.size(), 10);
}

TEST(FunctionFinder, Search_functions_by_disassembling_code_sections)
{
    auto module = symfind::PeModule::from_file(R"(C:\Windows\System32\ntdll.dll)");
    ASSERT_TRUE(module.has_value());

    std::vector<symfind::Function> functions;
    const symfind::Disassembler disassembler;
    symfind::FunctionFinder::from_call_targets(*module, disassembler, functions);

    EXPECT_GT(functions.size(), 10);
}

TEST(AnalysisIntegration, FindLdrpInitializeInRealNtdll)
{
    auto module = symfind::PeModule::from_file(R"(C:\Windows\System32\ntdll.dll)");
    ASSERT_TRUE(module.has_value());

    auto db = symfind::AnalysisDb::analyze(*module);
    EXPECT_GT(db.functions().size(), 100u);

    // LdrInitializeThunk should have at least one callee
    const auto* thunk = db.function_by_name("LdrInitializeThunk");
    ASSERT_NE(thunk, nullptr);
    EXPECT_GT(thunk->callees.size(), 0u);

    // Run our DSL rule
    auto rule = symfind::dsl::DslParser::parse(R"(
        find function in "ntdll" where
            called_by "LdrInitializeThunk";
            not exported;
            take first;
    )");
    ASSERT_TRUE(rule.has_value());

    auto results = symfind::dsl::DslMatcher::match(db, *rule);
    ASSERT_GE(results.size(), 1u);

    // The match should be inside .text
    spdlog::info("Found LdrpInitialize candidate at RVA 0x{:X}", results[0].rva);
}