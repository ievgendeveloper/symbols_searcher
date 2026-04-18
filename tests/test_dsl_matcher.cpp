#include <gtest/gtest.h>
#include "symfind/dsl_parser.h"
#include "symfind/dsl_matcher.h"
#include "symfind/analysis_db.h"

using namespace symfind;
using namespace symfind::dsl;

/// Helper: build a minimal AnalysisDb manually for testing
/// without needing a real PE file.
class MockAnalysisDb {
public:
    /// Simulates ntdll with the functions from our real use cases.
    static AnalysisDb build_ntdll_mock() {

        // --- Functions ---

        // LdrInitializeThunk (exported)
        AnalyzedFunction ldr_init_thunk;
        ldr_init_thunk.rva = 0x1000;
        ldr_init_thunk.name = "LdrInitializeThunk";
        ldr_init_thunk.exported = true;
        ldr_init_thunk.call_count = 3;
        ldr_init_thunk.callees = {0x2000, 0x3000, 0x4000}; // LdrpInit, ZwContinue, RtlRaiseStatus

        // LdrpInitialize (NOT exported)
        AnalyzedFunction ldrp_init;
        ldrp_init.rva = 0x2000;
        ldrp_init.name = "sub_2000";
        ldrp_init.exported = false;
        ldrp_init.callers = {0x1000};

        // ZwContinue (exported)
        AnalyzedFunction zw_continue;
        zw_continue.rva = 0x3000;
        zw_continue.name = "ZwContinue";
        zw_continue.exported = true;
        zw_continue.callers = {0x1000};

        // RtlRaiseStatus (exported)
        AnalyzedFunction rtl_raise;
        rtl_raise.rva = 0x4000;
        rtl_raise.name = "RtlRaiseStatus";
        rtl_raise.exported = true;
        rtl_raise.callers = {0x1000};

        // LdrLoadDll (exported)
        AnalyzedFunction ldr_load;
        ldr_load.rva = 0x5000;
        ldr_load.name = "LdrLoadDll";
        ldr_load.exported = true;
        ldr_load.call_count = 5;
        ldr_load.callees = {0x6000, 0x7000, 0x8000};

        // LdrpLoadDll (NOT exported, calls RtlGetCurrentServiceSessionId)
        AnalyzedFunction ldrp_load;
        ldrp_load.rva = 0x6000;
        ldrp_load.name = "sub_6000";
        ldrp_load.exported = false;
        ldrp_load.callers = {0x5000};
        ldrp_load.callees = {0x9000}; // RtlGetCurrentServiceSessionId
        ldrp_load.call_count = 8;
        ldrp_load.has_loop = true;

        // LdrpLogInternal (NOT exported, no interesting calls)
        AnalyzedFunction ldrp_log;
        ldrp_log.rva = 0x7000;
        ldrp_log.name = "sub_7000";
        ldrp_log.exported = false;
        ldrp_log.callers = {0x5000};

        // LdrpReleaseDllPath (NOT exported)
        AnalyzedFunction ldrp_release;
        ldrp_release.rva = 0x8000;
        ldrp_release.name = "sub_8000";
        ldrp_release.exported = false;
        ldrp_release.callers = {0x5000};

        // RtlGetCurrentServiceSessionId (exported)
        AnalyzedFunction rtl_session;
        rtl_session.rva = 0x9000;
        rtl_session.name = "RtlGetCurrentServiceSessionId";
        rtl_session.exported = true;
        rtl_session.callers = {0x6000};

        // RtlDecompressBuffer (exported, references a global)
        AnalyzedFunction rtl_decompress;
        rtl_decompress.rva = 0xA000;
        rtl_decompress.name = "RtlDecompressBuffer";
        rtl_decompress.exported = true;
        rtl_decompress.data_refs = {
            Xref{0xA010, 0xB000, 0xA000, XrefType::DataRef},
        };

        // --- Globals ---
        Global decompress_procs;
        decompress_procs.rva = 0xB000;
        decompress_procs.refs = {
            Xref{0xA010, 0xB000, 0xA000, XrefType::DataRef},
        };

        AnalysisDb::Builder builder;
        builder.module_name = "ntdll.dll";
        builder.functions = {
            ldr_init_thunk, ldrp_init, zw_continue, rtl_raise,
            ldr_load, ldrp_load, ldrp_log, ldrp_release,
            rtl_session, rtl_decompress,
        };
        builder.globals = {decompress_procs};

        return builder.build();
    }
};

// ─── Test: find LdrpInitialize ───

TEST(DslMatcher, FindLdrpInitialize) {
    auto db = MockAnalysisDb::build_ntdll_mock();

    auto rule = DslParser::parse(R"(
        find function in "ntdll" where
            called_by "LdrInitializeThunk"
            not exported
            take first
    )");
    ASSERT_TRUE(rule.has_value());

    auto results = DslMatcher::match(db, *rule);
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rva, 0x2000u);
}

// ─── Test: find LdrpLoadDll ───

TEST(DslMatcher, FindLdrpLoadDll) {
    auto db = MockAnalysisDb::build_ntdll_mock();

    auto rule = DslParser::parse(R"(
        find function in "ntdll" where
            called_by "LdrLoadDll"
            not exported
            calls "RtlGetCurrentServiceSessionId"
    )");
    ASSERT_TRUE(rule.has_value());

    auto results = DslMatcher::match(db, *rule);
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rva, 0x6000u);
}

// ─── Test: find RtlDecompressBufferProcs global ───

TEST(DslMatcher, FindDecompressBufferGlobal) {
    auto db = MockAnalysisDb::build_ntdll_mock();

    auto rule = DslParser::parse(R"(
        find global in "ntdll" where
            referenced_by "RtlDecompressBuffer"
            take first
    )");
    ASSERT_TRUE(rule.has_value());

    auto results = DslMatcher::match(db, *rule);
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rva, 0xB000u);
}

// ─── Test: no match when criteria don't fit ───

TEST(DslMatcher, NoMatchWhenExportedRequired) {
    auto db = MockAnalysisDb::build_ntdll_mock();

    auto rule = DslParser::parse(R"(
        find function in "ntdll" where
            called_by "LdrInitializeThunk"
            exported
            calls "SomethingThatDoesNotExist"
    )");
    ASSERT_TRUE(rule.has_value());

    auto results = DslMatcher::match(db, *rule);
    EXPECT_TRUE(results.empty());
}

// ─── Test: called_by block with inner predicates ───

TEST(DslMatcher, CalledByBlockMatch) {
    auto db = MockAnalysisDb::build_ntdll_mock();

    // Find a function that is called by a function with has_loop
    // LdrpLoadDll has has_loop=true and calls RtlGetCurrentServiceSessionId
    auto rule = DslParser::parse(R"(
        find function in "ntdll" where
            exported
            called_by (
                has_loop
                not exported
            )
    )");
    ASSERT_TRUE(rule.has_value());

    auto results = DslMatcher::match(db, *rule);
    // RtlGetCurrentServiceSessionId is exported and called by sub_6000 which has_loop
    ASSERT_GE(results.size(), 1u);
    EXPECT_EQ(results[0].rva, 0x9000u);
}

// ─── Test: not calls ───

TEST(DslMatcher, NotCallsPredicate) {
    auto db = MockAnalysisDb::build_ntdll_mock();

    // Find unexported functions called by LdrLoadDll that do NOT call
    // RtlGetCurrentServiceSessionId — should match sub_7000 and sub_8000
    auto rule = DslParser::parse(R"(
        find function in "ntdll" where
            called_by "LdrLoadDll"
            not exported
            not calls "RtlGetCurrentServiceSessionId"
    )");
    ASSERT_TRUE(rule.has_value());

    auto results = DslMatcher::match(db, *rule);
    EXPECT_EQ(results.size(), 2u);
}

// ─── Test: take limits results ───

TEST(DslMatcher, TakeLimitsResults) {
    auto db = MockAnalysisDb::build_ntdll_mock();

    auto rule = DslParser::parse(R"(
        find function in "ntdll" where
            not exported
            take 2
    )");
    ASSERT_TRUE(rule.has_value());

    auto results = DslMatcher::match(db, *rule);
    EXPECT_LE(results.size(), 2u);
}

// ─── Test: numeric predicate — calls_count ───

TEST(DslMatcher, CallsCountPredicate) {
    auto db = MockAnalysisDb::build_ntdll_mock();

    auto rule = DslParser::parse(R"(
        find function in "ntdll" where
            calls_count >= 5
            not exported
    )");
    ASSERT_TRUE(rule.has_value());

    auto results = DslMatcher::match(db, *rule);
    // sub_6000 (LdrpLoadDll) has call_count=8
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rva, 0x6000u);
}
