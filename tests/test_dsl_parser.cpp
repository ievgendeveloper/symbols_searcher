#include <gtest/gtest.h>
#include "symfind/dsl_parser.h"

using namespace symfind::dsl;

TEST(DslParser, MinimalRule)
{
    auto rule = DslParser::parse(R"(
        find function in "ntdll" where
            calls "NtQuerySystemInformation";
    )");

    ASSERT_TRUE(rule.has_value());
    EXPECT_EQ(rule->target, TargetKind::Function);
    EXPECT_EQ(rule->module_name, "ntdll");
    ASSERT_EQ(rule->predicates.size(), 1u);
    EXPECT_EQ(rule->predicates[0]->kind, PredKind::Calls);
    EXPECT_EQ(rule->predicates[0]->str_value, "NtQuerySystemInformation");
}

TEST(DslParser, FindGlobal)
{
    auto rule = DslParser::parse(R"(
        find global in "ntdll" where
            referenced_by "RtlDecompressBuffer";
            take first;
    )");

    ASSERT_TRUE(rule.has_value());
    EXPECT_EQ(rule->target, TargetKind::Global);
    EXPECT_EQ(rule->module_name, "ntdll");
    ASSERT_EQ(rule->predicates.size(), 2u);
    EXPECT_EQ(rule->predicates[0]->kind, PredKind::ReferencedBy);
    EXPECT_EQ(rule->predicates[1]->kind, PredKind::Take);
    EXPECT_EQ(rule->predicates[1]->int_value, 1);
}

TEST(DslParser, NotExported)
{
    auto rule = DslParser::parse(R"(
        find function in "ntdll" where
            called_by "LdrInitializeThunk";
            not exported;
            take first;
    )");
    ASSERT_TRUE(rule.has_value());
    ASSERT_EQ(rule->predicates.size(), 3u);

    EXPECT_EQ(rule->predicates[0]->kind, PredKind::CalledBy);
    EXPECT_EQ(rule->predicates[0]->str_value, "LdrInitializeThunk");

    // `not exported` is now parsed as Not(Exported) - composition of two
    // universal rules instead of a dedicated NotExported predicate.
    EXPECT_EQ(rule->predicates[1]->kind, PredKind::Not);
    ASSERT_NE(rule->predicates[1]->child, nullptr);
    EXPECT_EQ(rule->predicates[1]->child->kind, PredKind::Exported);

    EXPECT_EQ(rule->predicates[2]->kind, PredKind::Take);
}

TEST(DslParser, TwoLevelSearch)
{
    auto rule = DslParser::parse(R"(
        find function in "ntdll" where
            called_by "LdrLoadDll";
            not exported;
            calls "RtlGetCurrentServiceSessionId";
    )");

    ASSERT_TRUE(rule.has_value());
    ASSERT_EQ(rule->predicates.size(), 3u);
    EXPECT_EQ(rule->predicates[0]->kind, PredKind::CalledBy);
    EXPECT_EQ(rule->predicates[0]->str_value, "LdrLoadDll");
    EXPECT_EQ(rule->predicates[1]->kind, PredKind::Not);
    EXPECT_EQ(rule->predicates[2]->kind, PredKind::Calls);
    EXPECT_EQ(rule->predicates[2]->str_value, "RtlGetCurrentServiceSessionId");
}

TEST(DslParser, CalledByBlock)
{
    auto rule = DslParser::parse(R"(
        find function in "ntdll" where
            not exported;
            called_by (
                calls "NtQuerySystemInformation";
                has_loop;
            );
    )");

    ASSERT_TRUE(rule.has_value());
    ASSERT_EQ(rule->predicates.size(), 2u);
    EXPECT_EQ(rule->predicates[1]->kind, PredKind::CalledByBlock);
    ASSERT_EQ(rule->predicates[1]->children.size(), 2u);
    EXPECT_EQ(rule->predicates[1]->children[0]->kind, PredKind::Calls);
    EXPECT_EQ(rule->predicates[1]->children[1]->kind, PredKind::HasLoop);
}

TEST(DslParser, NumericPredicates)
{
    auto rule = DslParser::parse(R"(
        find function in "ntdll" where
            calls_count >= 3;
            stack_frame_size >= 0x80;
            xrefs count == 1;
    )");

    ASSERT_TRUE(rule.has_value());
    ASSERT_EQ(rule->predicates.size(), 3u);

    EXPECT_EQ(rule->predicates[0]->kind, PredKind::CallsCount);
    EXPECT_EQ(rule->predicates[0]->cmp_op, CmpOp::Gte);
    EXPECT_EQ(rule->predicates[0]->int_value, 3);

    EXPECT_EQ(rule->predicates[1]->kind, PredKind::StackFrameSize);
    EXPECT_EQ(rule->predicates[1]->cmp_op, CmpOp::Gte);
    EXPECT_EQ(rule->predicates[1]->int_value, 0x80);

    EXPECT_EQ(rule->predicates[2]->kind, PredKind::Xrefs);
    EXPECT_EQ(rule->predicates[2]->cmp_op, CmpOp::Eq);
    EXPECT_EQ(rule->predicates[2]->int_value, 1);
}

TEST(DslParser, NotPredicate)
{
    auto rule = DslParser::parse(R"(
        find function in "ntdll" where
            not calls "RtlFreeHeap";
    )");

    ASSERT_TRUE(rule.has_value());
    ASSERT_EQ(rule->predicates.size(), 1u);
    EXPECT_EQ(rule->predicates[0]->kind, PredKind::Not);
    ASSERT_NE(rule->predicates[0]->child, nullptr);
    EXPECT_EQ(rule->predicates[0]->child->kind, PredKind::Calls);
    EXPECT_EQ(rule->predicates[0]->child->str_value, "RtlFreeHeap");
}

TEST(DslParser, CommentsIgnored)
{
    auto rule = DslParser::parse(R"(
        # This rule finds LdrpInitialize
        find function in "ntdll" where
            # Must be called from the thunk
            called_by "LdrInitializeThunk";
            not exported;  # internal function
            take first;
    )");

    ASSERT_TRUE(rule.has_value());
    EXPECT_EQ(rule->predicates.size(), 3u);
}

TEST(DslParser, MissingWhere)
{
    auto rule = DslParser::parse(R"(
        find function in "ntdll"
            calls "Something"
    )");

    EXPECT_FALSE(rule.has_value());
}

TEST(DslParser, MissingModuleName)
{
    auto rule = DslParser::parse(R"(
        find function in where
            calls "Something"
    )");

    EXPECT_FALSE(rule.has_value());
}

TEST(DslParser, EmptyPredicates)
{
    auto rule = DslParser::parse(R"(
        find function in "ntdll" where
    )");

    EXPECT_FALSE(rule.has_value());
}