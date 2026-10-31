#include "symfind/dsl_lexer.h"
#include <gtest/gtest.h>

TEST(DslLexer, EmptyInput)
{
    symfind::dsl::Lexer lexer("");
    auto token = lexer.Next();
    EXPECT_EQ(token.type, symfind::dsl::TokenType::Eof);
}

TEST(DslLexer, Keywords)
{
    symfind::dsl::Lexer lexer(
        "find function in where calls called_by not exported has_loop take first");
    auto tokens = lexer.TokenizeAll();

    ASSERT_GE(tokens.size(), 11u);
    EXPECT_EQ(tokens[0].type, symfind::dsl::TokenType::Find);
    EXPECT_EQ(tokens[1].type, symfind::dsl::TokenType::Function);
    EXPECT_EQ(tokens[2].type, symfind::dsl::TokenType::In);
    EXPECT_EQ(tokens[3].type, symfind::dsl::TokenType::Where);
    EXPECT_EQ(tokens[4].type, symfind::dsl::TokenType::Calls);
    EXPECT_EQ(tokens[5].type, symfind::dsl::TokenType::CalledBy);
    EXPECT_EQ(tokens[6].type, symfind::dsl::TokenType::Not);
    EXPECT_EQ(tokens[7].type, symfind::dsl::TokenType::Exported);
    EXPECT_EQ(tokens[8].type, symfind::dsl::TokenType::HasLoop);
    EXPECT_EQ(tokens[9].type, symfind::dsl::TokenType::Take);
    EXPECT_EQ(tokens[10].type, symfind::dsl::TokenType::First);
}

TEST(DslLexer, StringLiteral)
{
    symfind::dsl::Lexer lexer(R"("ntdll.dll")");
    auto token = lexer.Next();
    EXPECT_EQ(token.type, symfind::dsl::TokenType::String);
    EXPECT_EQ(token.strValue, "ntdll.dll");
}

TEST(DslLexer, IntegerDecimal)
{
    symfind::dsl::Lexer lexer("42");
    auto token = lexer.Next();
    EXPECT_EQ(token.type, symfind::dsl::TokenType::Integer);
    EXPECT_EQ(token.intValue, 42);
}

TEST(DslLexer, IntegerHex)
{
    symfind::dsl::Lexer lexer("0xFF");
    auto token = lexer.Next();
    EXPECT_EQ(token.type, symfind::dsl::TokenType::Integer);
    EXPECT_EQ(token.intValue, 0xFF);
}

TEST(DslLexer, Operators)
{
    symfind::dsl::Lexer lexer(">= <= == > <");
    auto tokens = lexer.TokenizeAll();
    ASSERT_GE(tokens.size(), 5u);
    EXPECT_EQ(tokens[0].type, symfind::dsl::TokenType::Gte);
    EXPECT_EQ(tokens[1].type, symfind::dsl::TokenType::Lte);
    EXPECT_EQ(tokens[2].type, symfind::dsl::TokenType::Eq);
    EXPECT_EQ(tokens[3].type, symfind::dsl::TokenType::Gt);
    EXPECT_EQ(tokens[4].type, symfind::dsl::TokenType::Lt);
}

TEST(DslLexer, Delimiters)
{
    symfind::dsl::Lexer lexer("()[]");
    auto tokens = lexer.TokenizeAll();
    ASSERT_GE(tokens.size(), 4u);
    EXPECT_EQ(tokens[0].type, symfind::dsl::TokenType::LParen);
    EXPECT_EQ(tokens[1].type, symfind::dsl::TokenType::RParen);
    EXPECT_EQ(tokens[2].type, symfind::dsl::TokenType::LBracket);
    EXPECT_EQ(tokens[3].type, symfind::dsl::TokenType::RBracket);
}

TEST(DslLexer, CommentsSkipped)
{
    symfind::dsl::Lexer lexer("find # this is a comment\nfunction");
    auto tokens = lexer.TokenizeAll();
    ASSERT_GE(tokens.size(), 2u);
    EXPECT_EQ(tokens[0].type, symfind::dsl::TokenType::Find);
    EXPECT_EQ(tokens[1].type, symfind::dsl::TokenType::Function);
}

TEST(DslLexer, FullRule)
{
    const char* ruleSource = R"(
        find function in "ntdll" where
            called_by "LdrLoadDll"
            not exported
            calls "RtlGetCurrentServiceSessionId"
    )";
    symfind::dsl::Lexer lexer(ruleSource);
    auto tokens = lexer.TokenizeAll();

    // Should tokenize without errors
    for (const auto& token : tokens)
    {
        EXPECT_NE(token.type, symfind::dsl::TokenType::Error) << "Error at line " << token.line;
    }
}

TEST(DslLexer, LineTracking)
{
    symfind::dsl::Lexer lexer("find\nfunction\nin");
    auto tokens = lexer.TokenizeAll();
    EXPECT_EQ(tokens[0].line, 1);
    EXPECT_EQ(tokens[1].line, 2);
    EXPECT_EQ(tokens[2].line, 3);
}
