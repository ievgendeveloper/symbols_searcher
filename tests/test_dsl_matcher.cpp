#include "ntdll_symbol_rules.h"
#include "symfind/analysis_db.h"
#include "symfind/dsl_matcher.h"
#include "symfind/dsl_parser.h"
#include <gtest/gtest.h>

#include <array>
#include <string>
#include <string_view>
#include <utility>

/// Helper: build a minimal AnalysisDb manually for testing
/// without needing a real PE file.
class MockAnalysisDb
{
    public:
        /// Synthetic graph for predicate tests, rather than one Windows build.
        static symfind::AnalysisDb BuildNtdllMock(std::string moduleName = "ntdll.dll")
        {
            // --- Functions ---

            // LdrInitializeThunk (exported)
            symfind::AnalyzedFunction initializeThunk;
            initializeThunk.rva = 0x1000;
            initializeThunk.name = "LdrInitializeThunk";
            initializeThunk.exported = true;
            initializeThunk.callCount = 3;
            initializeThunk.callees = {0x2000, 0x3000,
                                       0x4000}; // LdrpInit, ZwContinue, RtlRaiseStatus

            // LdrpInitialize (NOT exported)
            symfind::AnalyzedFunction initializeFunction;
            initializeFunction.rva = 0x2000;
            initializeFunction.name = "sub_2000";
            initializeFunction.exported = false;
            initializeFunction.callers = {0x1000};

            // ZwContinue (exported)
            symfind::AnalyzedFunction continueFunction;
            continueFunction.rva = 0x3000;
            continueFunction.name = "ZwContinue";
            continueFunction.exported = true;
            continueFunction.callers = {0x1000};

            // RtlRaiseStatus (exported)
            symfind::AnalyzedFunction raiseStatusFunction;
            raiseStatusFunction.rva = 0x4000;
            raiseStatusFunction.name = "RtlRaiseStatus";
            raiseStatusFunction.exported = true;
            raiseStatusFunction.callers = {0x1000};

            // LdrLoadDll (exported)
            symfind::AnalyzedFunction loadDllExport;
            loadDllExport.rva = 0x5000;
            loadDllExport.name = "LdrLoadDll";
            loadDllExport.exported = true;
            loadDllExport.callCount = 5;
            loadDllExport.callees = {0x6000, 0x7000, 0x8000, 0xC000};

            // LdrpLoadDll (NOT exported, calls RtlGetCurrentServiceSessionId)
            symfind::AnalyzedFunction loadDllFunction;
            loadDllFunction.rva = 0x6000;
            loadDllFunction.name = "sub_6000";
            loadDllFunction.exported = false;
            loadDllFunction.callers = {0x5000};
            loadDllFunction.callees = {0x9000}; // RtlGetCurrentServiceSessionId
            loadDllFunction.callCount = 8;
            loadDllFunction.stackFrameSize = 0x180;
            loadDllFunction.hasLoop = true;

            // LdrpLogInternal (NOT exported, no interesting calls)
            symfind::AnalyzedFunction loggingHelper;
            loggingHelper.rva = 0x7000;
            loggingHelper.name = "sub_7000";
            loggingHelper.exported = false;
            loggingHelper.callers = {0x5000};
            loggingHelper.stackFrameSize = 0x158;
            loggingHelper.callCount = 3;

            // LdrpReleaseDllPath (NOT exported)
            symfind::AnalyzedFunction releaseDllPathHelper;
            releaseDllPathHelper.rva = 0x8000;
            releaseDllPathHelper.name = "sub_8000";
            releaseDllPathHelper.exported = false;
            releaseDllPathHelper.callers = {0x5000};
            releaseDllPathHelper.stackFrameSize = 0x50;
            releaseDllPathHelper.callCount = 7;

            // Large-stack logging helper must not match the loader rule.
            symfind::AnalyzedFunction largeStackLoggingHelper;
            largeStackLoggingHelper.rva = 0xC000;
            largeStackLoggingHelper.name = "sub_C000";
            largeStackLoggingHelper.callers = {0x5000};
            largeStackLoggingHelper.stackFrameSize = 0x4E0;
            largeStackLoggingHelper.callCount = 12;

            // RtlGetCurrentServiceSessionId (exported)
            symfind::AnalyzedFunction currentServiceSessionFunction;
            currentServiceSessionFunction.rva = 0x9000;
            currentServiceSessionFunction.name = "RtlGetCurrentServiceSessionId";
            currentServiceSessionFunction.exported = true;
            currentServiceSessionFunction.callers = {0x6000};

            // RtlDecompressBuffer (exported, references a global)
            symfind::AnalyzedFunction decompressBufferFunction;
            decompressBufferFunction.rva = 0xA000;
            decompressBufferFunction.name = "RtlDecompressBuffer";
            decompressBufferFunction.exported = true;
            decompressBufferFunction.dataRefs = {
                symfind::Xref{0xA010, 0xB000, 0xA000, symfind::XrefType::DataRef},
            };

            // --- Globals ---
            symfind::Global decompressProceduresGlobal;
            decompressProceduresGlobal.rva = 0xB000;
            decompressProceduresGlobal.refs = {
                symfind::Xref{0xA010, 0xB000, 0xA000, symfind::XrefType::DataRef},
            };

            symfind::AnalysisDb::Builder databaseBuilder;
            databaseBuilder.moduleName = std::move(moduleName);
            databaseBuilder.functions = {
                initializeThunk,
                initializeFunction,
                continueFunction,
                raiseStatusFunction,
                loadDllExport,
                loadDllFunction,
                loggingHelper,
                releaseDllPathHelper,
                currentServiceSessionFunction,
                decompressBufferFunction,
                largeStackLoggingHelper,
            };
            databaseBuilder.globals = {decompressProceduresGlobal};

            return databaseBuilder.Build();
        }
};

// ─── Test: find LdrpInitialize ───

TEST(DslMatcher, RejectsModuleMismatchForFunctionsAndGlobals)
{
    const auto analysisDatabase = MockAnalysisDb::BuildNtdllMock();
    for (const auto& symbolRule : symfind::validation::ntdllSymbolRules)
    {
        SCOPED_TRACE(std::string(symbolRule.symbol));
        auto parsedRule = symfind::dsl::DslParser::Parse(symbolRule.script);
        ASSERT_TRUE(parsedRule.has_value());
        parsedRule->moduleName = "kernel32.dll";
        EXPECT_TRUE(symfind::dsl::DslMatcher::Match(analysisDatabase, *parsedRule).empty());
    }
}

TEST(DslMatcher, EmptyRuleOrDatabaseModuleCannotActAsWildcard)
{
    for (const std::string databaseModuleName : {"ntdll.dll", ""})
    {
        SCOPED_TRACE(databaseModuleName);
        const auto analysisDatabase = MockAnalysisDb::BuildNtdllMock(databaseModuleName);
        for (const std::string requestedModuleName : {"ntdll.dll", ""})
        {
            if (!databaseModuleName.empty() && !requestedModuleName.empty())
            {
                continue;
            }
            SCOPED_TRACE(requestedModuleName);
            auto parsedRule =
                symfind::dsl::DslParser::Parse(R"(find function in "" where exported;)");
            ASSERT_TRUE(parsedRule.has_value());
            parsedRule->moduleName = requestedModuleName;
            EXPECT_TRUE(symfind::dsl::DslMatcher::Match(analysisDatabase, *parsedRule).empty());
        }
    }
}

TEST(DslMatcher, ModuleComparisonOnlyFoldsAsciiLetters)
{
    const auto analysisDatabase = MockAnalysisDb::BuildNtdllMock("mod-\xc3\x84.dll");
    auto parsedRule =
        symfind::dsl::DslParser::Parse(symfind::validation::NtdllRuleFor("LdrpInitialize"));
    ASSERT_TRUE(parsedRule.has_value());
    parsedRule->moduleName = "MOD-\xc3\x84.DLL";
    EXPECT_EQ(symfind::dsl::DslMatcher::Match(analysisDatabase, *parsedRule).size(), 1);
    parsedRule->moduleName = "mod-\xc3\xa4.dll";
    EXPECT_TRUE(symfind::dsl::DslMatcher::Match(analysisDatabase, *parsedRule).empty());
}

TEST(DslMatcher, ModuleNamesMatchAsciiCaseBasenamesAndOptionalDllSuffix)
{
    const std::array<std::pair<std::string_view, std::string_view>, 8> moduleNameCases{{
        {"NtDlL.DlL", "nTdLl"},
        {"ntdll", "NTDLL.DLL"},
        {R"(C:\Windows\System32\NTDLL.dll)", "ntdll"},
        {"/samples/NTDLL.DLL", "ntdll.dll"},
        {"ntdll.dll", R"(D:\fixtures\NTdLl)"},
        {"ntdll", "/fixtures/ntdll.DLL"},
        {"DRIVER.SYS", "driver.sys"},
        {"PROGRAM.EXE", "program.exe"},
    }};
    for (const auto& moduleNames : moduleNameCases)
    {
        SCOPED_TRACE(std::string(moduleNames.first));
        SCOPED_TRACE(std::string(moduleNames.second));
        const auto analysisDatabase =
            MockAnalysisDb::BuildNtdllMock(std::string(moduleNames.first));
        for (const auto& symbolRule : symfind::validation::ntdllSymbolRules)
        {
            auto parsedRule = symfind::dsl::DslParser::Parse(symbolRule.script);
            ASSERT_TRUE(parsedRule.has_value());
            parsedRule->moduleName = moduleNames.second;
            EXPECT_EQ(symfind::dsl::DslMatcher::Match(analysisDatabase, *parsedRule).size(), 1);
        }
    }
}

TEST(DslMatcher, ModuleNamesPreserveExplicitExtensionsAndRejectPartialNames)
{
    const std::array<std::pair<std::string_view, std::string_view>, 11> moduleNameCases{{
        {"ntdll.dll", "ntdll.exe"},
        {"ntdll.dll", "ntdll.sys"},
        {"ntdll.sys", "ntdll"},
        {"ntdll.exe", "ntdll"},
        {"ntdll.exe", "ntdll.exe.dll"},
        {"ntdll.dll", "ntdll.dll.backup"},
        {"ntdll.dll", "prefix-ntdll"},
        {"ntdll.dll", "ntdll-extra"},
        {"ntdll.dll", "ntdll.dll "},
        {"ntdll.dll", R"(C:\Windows\System32\)"},
        {"/samples/", "ntdll"},
    }};
    for (const auto& moduleNames : moduleNameCases)
    {
        SCOPED_TRACE(std::string(moduleNames.first));
        SCOPED_TRACE(std::string(moduleNames.second));
        const auto analysisDatabase =
            MockAnalysisDb::BuildNtdllMock(std::string(moduleNames.first));
        for (const auto& symbolRule : symfind::validation::ntdllSymbolRules)
        {
            auto parsedRule = symfind::dsl::DslParser::Parse(symbolRule.script);
            ASSERT_TRUE(parsedRule.has_value());
            parsedRule->moduleName = moduleNames.second;
            EXPECT_TRUE(symfind::dsl::DslMatcher::Match(analysisDatabase, *parsedRule).empty());
        }
    }
}

TEST(DslMatcher, FindLdrpInitialize)
{
    auto analysisDatabase = MockAnalysisDb::BuildNtdllMock();

    auto parsedRule =
        symfind::dsl::DslParser::Parse(symfind::validation::NtdllRuleFor("LdrpInitialize"));
    ASSERT_TRUE(parsedRule.has_value());

    auto matchedSymbols = symfind::dsl::DslMatcher::Match(analysisDatabase, *parsedRule);
    ASSERT_EQ(matchedSymbols.size(), 1u);
    EXPECT_EQ(matchedSymbols[0].rva, 0x2000u);
}

// ─── Test: find LdrpLoadDll ───

TEST(DslMatcher, FindLdrpLoadDll)
{
    auto analysisDatabase = MockAnalysisDb::BuildNtdllMock();

    auto parsedRule =
        symfind::dsl::DslParser::Parse(symfind::validation::NtdllRuleFor("LdrpLoadDll"));
    ASSERT_TRUE(parsedRule.has_value());

    auto matchedSymbols = symfind::dsl::DslMatcher::Match(analysisDatabase, *parsedRule);
    ASSERT_EQ(matchedSymbols.size(), 1u);
    EXPECT_EQ(matchedSymbols[0].rva, 0x6000u);
}

// ─── Test: find RtlDecompressBufferProcs global ───

TEST(DslMatcher, FindDecompressBufferGlobal)
{
    auto analysisDatabase = MockAnalysisDb::BuildNtdllMock();

    auto parsedRule = symfind::dsl::DslParser::Parse(
        symfind::validation::NtdllRuleFor("RtlDecompressBufferProcs"));
    ASSERT_TRUE(parsedRule.has_value());

    auto matchedSymbols = symfind::dsl::DslMatcher::Match(analysisDatabase, *parsedRule);
    ASSERT_EQ(matchedSymbols.size(), 1u);
    EXPECT_EQ(matchedSymbols[0].rva, 0xB000u);
}

TEST(DslMatcher, DiagnoseDecompressBuffer)
{
    auto analysisDatabase = MockAnalysisDb::BuildNtdllMock();

    // is global in database ?
    const auto* decompressProceduresGlobal = analysisDatabase.GlobalAt(0xB000);
    ASSERT_NE(decompressProceduresGlobal, nullptr) << "Global at 0xB000 not in DB";
    EXPECT_EQ(decompressProceduresGlobal->refs.size(), 1u);

    // is function present and could be found by name?
    const auto* decompressBufferFunction = analysisDatabase.FunctionByName("RtlDecompressBuffer");
    ASSERT_NE(decompressBufferFunction, nullptr) << "RtlDecompressBuffer not found by name";
    EXPECT_EQ(decompressBufferFunction->rva, 0xA000u);

    // does xref have correct fromFunc?
    EXPECT_EQ(decompressProceduresGlobal->refs[0].fromFunc, decompressBufferFunction->rva);
}

// ─── Test: no match when criteria don't fit ───

TEST(DslMatcher, NoMatchWhenExportedRequired)
{
    auto analysisDatabase = MockAnalysisDb::BuildNtdllMock();

    auto parsedRule = symfind::dsl::DslParser::Parse(R"(
        find function in "ntdll" where
            called_by "LdrInitializeThunk";
            exported;
            calls "SomethingThatDoesNotExist";
    )");
    ASSERT_TRUE(parsedRule.has_value());

    auto matchedSymbols = symfind::dsl::DslMatcher::Match(analysisDatabase, *parsedRule);
    EXPECT_TRUE(matchedSymbols.empty());
}

// ─── Test: called_by block with inner predicates ───

TEST(DslMatcher, CalledByBlockMatch)
{
    auto analysisDatabase = MockAnalysisDb::BuildNtdllMock();

    // Find a function that is called by a function with hasLoop
    // LdrpLoadDll has hasLoop=true and calls RtlGetCurrentServiceSessionId
    auto parsedRule = symfind::dsl::DslParser::Parse(R"(
        find function in "ntdll" where
            exported;
            called_by (
                has_loop;
                not exported;
            );
    )");
    ASSERT_TRUE(parsedRule.has_value());

    auto matchedSymbols = symfind::dsl::DslMatcher::Match(analysisDatabase, *parsedRule);
    // RtlGetCurrentServiceSessionId is exported and called by sub_6000 which hasLoop
    ASSERT_GE(matchedSymbols.size(), 1u);
    EXPECT_EQ(matchedSymbols[0].rva, 0x9000u);
}

// ─── Test: not calls ───

TEST(DslMatcher, NotCallsPredicate)
{
    auto analysisDatabase = MockAnalysisDb::BuildNtdllMock();

    // Find unexported functions called by LdrLoadDll that do NOT call
    // RtlGetCurrentServiceSessionId — the three other helpers match.
    auto parsedRule = symfind::dsl::DslParser::Parse(R"(
        find function in "ntdll" where
            called_by "LdrLoadDll";
            not exported;
            not calls "RtlGetCurrentServiceSessionId";
    )");
    ASSERT_TRUE(parsedRule.has_value());

    auto matchedSymbols = symfind::dsl::DslMatcher::Match(analysisDatabase, *parsedRule);
    EXPECT_EQ(matchedSymbols.size(), 3u);
}

// ─── Test: take limits results ───

TEST(DslMatcher, TakeLimitsResults)
{
    auto analysisDatabase = MockAnalysisDb::BuildNtdllMock();

    auto parsedRule = symfind::dsl::DslParser::Parse(R"(
        find function in "ntdll" where
            not exported;
            take 2;
    )");
    ASSERT_TRUE(parsedRule.has_value());

    auto matchedSymbols = symfind::dsl::DslMatcher::Match(analysisDatabase, *parsedRule);
    EXPECT_LE(matchedSymbols.size(), 2u);
}

// ─── Test: numeric predicate — calls_count ───

TEST(DslMatcher, CallsCountPredicate)
{
    auto analysisDatabase = MockAnalysisDb::BuildNtdllMock();

    auto parsedRule = symfind::dsl::DslParser::Parse(R"(
        find function in "ntdll" where
            calls_count >= 5;
            not exported;
    )");
    ASSERT_TRUE(parsedRule.has_value());

    auto matchedSymbols = symfind::dsl::DslMatcher::Match(analysisDatabase, *parsedRule);
    // The loader and both stack-size decoys satisfy the count alone.
    ASSERT_EQ(matchedSymbols.size(), 3u);
    EXPECT_EQ(matchedSymbols[0].rva, 0x6000u);
    EXPECT_EQ(matchedSymbols[1].rva, 0x8000u);
    EXPECT_EQ(matchedSymbols[2].rva, 0xC000u);
}
