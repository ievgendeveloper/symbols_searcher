#include "symfind/dsl_parser.h"
#include <gtest/gtest.h>

TEST(DslParser, MinimalRule)
{
    auto parsedRule = symfind::dsl::DslParser::Parse(R"(
        find function in "ntdll" where
            calls "NtQuerySystemInformation";
    )");

    ASSERT_TRUE(parsedRule.has_value());
    EXPECT_EQ(parsedRule->target, symfind::dsl::TargetKind::Function);
    EXPECT_EQ(parsedRule->moduleName, "ntdll");
    ASSERT_EQ(parsedRule->predicates.size(), 1u);
    EXPECT_EQ(parsedRule->predicates[0]->kind, symfind::dsl::PredKind::Calls);
    EXPECT_EQ(parsedRule->predicates[0]->strValue, "NtQuerySystemInformation");
}

TEST(DslParser, FindGlobal)
{
    auto parsedRule = symfind::dsl::DslParser::Parse(R"(
        find global in "ntdll" where
            referenced_by "RtlDecompressBuffer";
            take first;
    )");

    ASSERT_TRUE(parsedRule.has_value());
    EXPECT_EQ(parsedRule->target, symfind::dsl::TargetKind::Global);
    EXPECT_EQ(parsedRule->moduleName, "ntdll");
    ASSERT_EQ(parsedRule->predicates.size(), 2u);
    EXPECT_EQ(parsedRule->predicates[0]->kind, symfind::dsl::PredKind::ReferencedBy);
    EXPECT_EQ(parsedRule->predicates[1]->kind, symfind::dsl::PredKind::Take);
    EXPECT_EQ(parsedRule->predicates[1]->intValue, 1);
}

TEST(DslParser, NotExported)
{
    auto parsedRule = symfind::dsl::DslParser::Parse(R"(
        find function in "ntdll" where
            called_by "LdrInitializeThunk";
            not exported;
            take first;
    )");
    ASSERT_TRUE(parsedRule.has_value());
    ASSERT_EQ(parsedRule->predicates.size(), 3u);

    EXPECT_EQ(parsedRule->predicates[0]->kind, symfind::dsl::PredKind::CalledBy);
    EXPECT_EQ(parsedRule->predicates[0]->strValue, "LdrInitializeThunk");

    // `not exported` is now parsed as Not(Exported) - composition of two
    // universal rules instead of a dedicated NotExported predicate.
    EXPECT_EQ(parsedRule->predicates[1]->kind, symfind::dsl::PredKind::Not);
    ASSERT_NE(parsedRule->predicates[1]->child, nullptr);
    EXPECT_EQ(parsedRule->predicates[1]->child->kind, symfind::dsl::PredKind::Exported);

    EXPECT_EQ(parsedRule->predicates[2]->kind, symfind::dsl::PredKind::Take);
}

TEST(DslParser, TwoLevelSearch)
{
    auto parsedRule = symfind::dsl::DslParser::Parse(R"(
        find function in "ntdll" where
            called_by "LdrLoadDll";
            not exported;
            calls "RtlGetCurrentServiceSessionId";
    )");

    ASSERT_TRUE(parsedRule.has_value());
    ASSERT_EQ(parsedRule->predicates.size(), 3u);
    EXPECT_EQ(parsedRule->predicates[0]->kind, symfind::dsl::PredKind::CalledBy);
    EXPECT_EQ(parsedRule->predicates[0]->strValue, "LdrLoadDll");
    EXPECT_EQ(parsedRule->predicates[1]->kind, symfind::dsl::PredKind::Not);
    EXPECT_EQ(parsedRule->predicates[2]->kind, symfind::dsl::PredKind::Calls);
    EXPECT_EQ(parsedRule->predicates[2]->strValue, "RtlGetCurrentServiceSessionId");
}

TEST(DslParser, CalledByBlock)
{
    auto parsedRule = symfind::dsl::DslParser::Parse(R"(
        find function in "ntdll" where
            not exported;
            called_by (
                calls "NtQuerySystemInformation";
                has_loop;
            );
    )");

    ASSERT_TRUE(parsedRule.has_value());
    ASSERT_EQ(parsedRule->predicates.size(), 2u);
    EXPECT_EQ(parsedRule->predicates[1]->kind, symfind::dsl::PredKind::CalledByBlock);
    ASSERT_EQ(parsedRule->predicates[1]->children.size(), 2u);
    EXPECT_EQ(parsedRule->predicates[1]->children[0]->kind, symfind::dsl::PredKind::Calls);
    EXPECT_EQ(parsedRule->predicates[1]->children[1]->kind, symfind::dsl::PredKind::HasLoop);
}

TEST(DslParser, NumericPredicates)
{
    auto parsedRule = symfind::dsl::DslParser::Parse(R"(
        find function in "ntdll" where
            calls_count >= 3;
            stack_frame_size >= 0x80;
            xrefs count == 1;
    )");

    ASSERT_TRUE(parsedRule.has_value());
    ASSERT_EQ(parsedRule->predicates.size(), 3u);

    EXPECT_EQ(parsedRule->predicates[0]->kind, symfind::dsl::PredKind::CallsCount);
    EXPECT_EQ(parsedRule->predicates[0]->cmpOp, symfind::dsl::CmpOp::Gte);
    EXPECT_EQ(parsedRule->predicates[0]->intValue, 3);

    EXPECT_EQ(parsedRule->predicates[1]->kind, symfind::dsl::PredKind::StackFrameSize);
    EXPECT_EQ(parsedRule->predicates[1]->cmpOp, symfind::dsl::CmpOp::Gte);
    EXPECT_EQ(parsedRule->predicates[1]->intValue, 0x80);

    EXPECT_EQ(parsedRule->predicates[2]->kind, symfind::dsl::PredKind::Xrefs);
    EXPECT_EQ(parsedRule->predicates[2]->cmpOp, symfind::dsl::CmpOp::Eq);
    EXPECT_EQ(parsedRule->predicates[2]->intValue, 1);
}

TEST(DslParser, NotPredicate)
{
    auto parsedRule = symfind::dsl::DslParser::Parse(R"(
        find function in "ntdll" where
            not calls "RtlFreeHeap";
    )");

    ASSERT_TRUE(parsedRule.has_value());
    ASSERT_EQ(parsedRule->predicates.size(), 1u);
    EXPECT_EQ(parsedRule->predicates[0]->kind, symfind::dsl::PredKind::Not);
    ASSERT_NE(parsedRule->predicates[0]->child, nullptr);
    EXPECT_EQ(parsedRule->predicates[0]->child->kind, symfind::dsl::PredKind::Calls);
    EXPECT_EQ(parsedRule->predicates[0]->child->strValue, "RtlFreeHeap");
}

TEST(DslParser, CommentsIgnored)
{
    auto parsedRule = symfind::dsl::DslParser::Parse(R"(
        # This rule finds LdrpInitialize
        find function in "ntdll" where
            # Must be called from the thunk
            called_by "LdrInitializeThunk";
            not exported;  # internal function
            take first;
    )");

    ASSERT_TRUE(parsedRule.has_value());
    EXPECT_EQ(parsedRule->predicates.size(), 3u);
}

TEST(DslParser, MissingWhere)
{
    auto parsedRule = symfind::dsl::DslParser::Parse(R"(
        find function in "ntdll"
            calls "Something"
    )");

    EXPECT_FALSE(parsedRule.has_value());
}

TEST(DslParser, MissingModuleName)
{
    auto parsedRule = symfind::dsl::DslParser::Parse(R"(
        find function in where
            calls "Something"
    )");

    EXPECT_FALSE(parsedRule.has_value());
}

TEST(DslParser, EmptyPredicates)
{
    auto parsedRule = symfind::dsl::DslParser::Parse(R"(
        find function in "ntdll" where
    )");

    EXPECT_FALSE(parsedRule.has_value());
}