#include "symfind/dsl_lexer.h"
#include <gtest/gtest.h>

using namespace symfind::dsl;

TEST(DslLexer, EmptyInput)
{
    Lexer lexer("");
    auto tok = lexer.next();
    EXPECT_EQ(tok.type, TokenType::Eof);
}

TEST(DslLexer, Keywords)
{
    Lexer lexer("find function in where calls called_by not exported has_loop take first");
    auto tokens = lexer.tokenize_all();

    ASSERT_GE(tokens.size(), 11u);
    EXPECT_EQ(tokens[0].type, TokenType::Find);
    EXPECT_EQ(tokens[1].type, TokenType::Function);
    EXPECT_EQ(tokens[2].type, TokenType::In);
    EXPECT_EQ(tokens[3].type, TokenType::Where);
    EXPECT_EQ(tokens[4].type, TokenType::Calls);
    EXPECT_EQ(tokens[5].type, TokenType::CalledBy);
    EXPECT_EQ(tokens[6].type, TokenType::Not);
    EXPECT_EQ(tokens[7].type, TokenType::Exported);
    EXPECT_EQ(tokens[8].type, TokenType::HasLoop);
    EXPECT_EQ(tokens[9].type, TokenType::Take);
    EXPECT_EQ(tokens[10].type, TokenType::First);
}

TEST(DslLexer, StringLiteral)
{
    Lexer lexer(R"("ntdll.dll")");
    auto tok = lexer.next();
    EXPECT_EQ(tok.type, TokenType::String);
    EXPECT_EQ(tok.str_value, "ntdll.dll");
}

TEST(DslLexer, IntegerDecimal)
{
    Lexer lexer("42");
    auto tok = lexer.next();
    EXPECT_EQ(tok.type, TokenType::Integer);
    EXPECT_EQ(tok.int_value, 42);
}

TEST(DslLexer, IntegerHex)
{
    Lexer lexer("0xFF");
    auto tok = lexer.next();
    EXPECT_EQ(tok.type, TokenType::Integer);
    EXPECT_EQ(tok.int_value, 0xFF);
}

TEST(DslLexer, Operators)
{
    Lexer lexer(">= <= == > <");
    auto tokens = lexer.tokenize_all();
    ASSERT_GE(tokens.size(), 5u);
    EXPECT_EQ(tokens[0].type, TokenType::Gte);
    EXPECT_EQ(tokens[1].type, TokenType::Lte);
    EXPECT_EQ(tokens[2].type, TokenType::Eq);
    EXPECT_EQ(tokens[3].type, TokenType::Gt);
    EXPECT_EQ(tokens[4].type, TokenType::Lt);
}

TEST(DslLexer, Delimiters)
{
    Lexer lexer("()[]");
    auto tokens = lexer.tokenize_all();
    ASSERT_GE(tokens.size(), 4u);
    EXPECT_EQ(tokens[0].type, TokenType::LParen);
    EXPECT_EQ(tokens[1].type, TokenType::RParen);
    EXPECT_EQ(tokens[2].type, TokenType::LBracket);
    EXPECT_EQ(tokens[3].type, TokenType::RBracket);
}

TEST(DslLexer, CommentsSkipped)
{
    Lexer lexer("find # this is a comment\nfunction");
    auto tokens = lexer.tokenize_all();
    ASSERT_GE(tokens.size(), 2u);
    EXPECT_EQ(tokens[0].type, TokenType::Find);
    EXPECT_EQ(tokens[1].type, TokenType::Function);
}

TEST(DslLexer, FullRule)
{
    const char* input = R"(
        find function in "ntdll" where
            called_by "LdrLoadDll"
            not exported
            calls "RtlGetCurrentServiceSessionId"
    )";
    Lexer lexer(input);
    auto tokens = lexer.tokenize_all();

    // Should tokenize without errors
    for (const auto& t : tokens)
    {
        EXPECT_NE(t.type, TokenType::Error) << "Error at line " << t.line;
    }
}

TEST(DslLexer, LineTracking)
{
    Lexer lexer("find\nfunction\nin");
    auto tokens = lexer.tokenize_all();
    EXPECT_EQ(tokens[0].line, 1);
    EXPECT_EQ(tokens[1].line, 2);
    EXPECT_EQ(tokens[2].line, 3);
}
