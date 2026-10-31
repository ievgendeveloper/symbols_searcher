/*
 * symfind DSL — re2c lexer
 *
 * Generate with:  re2c -W --no-debug-info -o lexer.gen.cpp lexer.re
 *
 * Uses the standard re2c API (no custom input mode). The input
 * buffer is guaranteed to be NUL-terminated by Lexer's constructor,
 * so re2c can rely on '\x00' as a sentinel.
 */

#include "symfind/dsl_lexer.h"

#include <cassert>
#include <cstdlib>
#include <string>

namespace symfind::dsl
{

    Lexer::Lexer(std::string_view ruleSource)
        : m_sourceStorage(
              ruleSource) // copy → guarantees NUL terminator at m_sourceStorage.data() + size()
          ,
          m_sourceView(m_sourceStorage)
    {
    }

    Token Lexer::Next()
    {
        Token token{}; // value-initialize all fields to zero/null

    nextToken:
        /* Standard re2c variables — pointers into the input buffer */
        const char* YYCURSOR = m_sourceView.data() + m_position;
        const char* YYMARKER = YYCURSOR;
        const char* tokenStart = YYCURSOR;

        token.line = m_line;
        token.column = m_column;

        /*!re2c
        re2c:define:YYCTYPE = "char";
        re2c:yyfill:enable = 0;

        end            = "\x00";
        whitespace     = [ \t]+;
        newline        = "\r"? "\n";
        digit          = [0-9];
        hexInteger     = "0x" [0-9a-fA-F]+;
        decimalInteger = digit+;
        comment        = "#" [^\n\x00]*;
        identifier     = [a-zA-Z_][a-zA-Z0-9_]*;

        /* Skip whitespace, newlines, comments */
        whitespace
        {
            m_position = YYCURSOR - m_sourceView.data();
            m_column += static_cast<int>(YYCURSOR - tokenStart);
            goto nextToken;
        }
        newline
        {
            m_position = YYCURSOR - m_sourceView.data();
            m_line++;
            m_column = 1;
            goto nextToken;
        }
        comment
        {
            m_position = YYCURSOR - m_sourceView.data();
            m_column += static_cast<int>(YYCURSOR - tokenStart);
            goto nextToken;
        }

        /* End of input */
        end
        {
            /* Don't Advance past the NUL terminator */
            token.type = TokenType::Eof;
            return token;
        }

        /* Keywords — we use goto to a finalization label
           because re2c rule actions can't easily share complex C++ code */
        "find"
        {
            goto kwFind;
        }
        "function"
        {
            goto kwFunction;
        }
        "global"
        {
            goto kwGlobal;
        }
        "in"
        {
            goto kwIn;
        }
        "where"
        {
            goto kwWhere;
        }
        "calls"
        {
            goto kwCalls;
        }
        "called_by"
        {
            goto kwCalledBy;
        }
        "referenced_by"
        {
            goto kwReferencedBy;
        }
        "exported"
        {
            goto kwExported;
        }
        "not"
        {
            goto kwNot;
        }
        "has_loop"
        {
            goto kwHasLoop;
        }
        "take"
        {
            goto kwTake;
        }
        "first"
        {
            goto kwFirst;
        }
        "count"
        {
            goto kwCount;
        }
        "offset"
        {
            goto kwOffset;
        }
        "arg"
        {
            goto kwArg;
        }
        "type"
        {
            goto kwType;
        }
        "xrefs"
        {
            goto kwXrefs;
        }
        "stack_frame_size"
        {
            goto kwStackFrameSize;
        }
        "calls_count"
        {
            goto kwCallsCount;
        }
        "reads_reg"
        {
            goto kwReadsReg;
        }

        /* String literal */
        ["] [^"\x00\n]* ["]
        {
            m_position = YYCURSOR - m_sourceView.data();
            m_column += static_cast<int>(YYCURSOR - tokenStart);
            token.type = TokenType::String;
            /* Strip surrounding quotes; view points into m_sourceStorage which outlives all tokens
             */
            token.strValue =
                std::string_view(tokenStart + 1, static_cast<size_t>(YYCURSOR - tokenStart - 2));
            return token;
        }

        /* Hex integer */
        hexInteger
        {
            m_position = YYCURSOR - m_sourceView.data();
            m_column += static_cast<int>(YYCURSOR - tokenStart);
            token.type = TokenType::Integer;
            token.intValue =
                std::strtoll(std::string(tokenStart, YYCURSOR - tokenStart).c_str(), nullptr, 16);
            return token;
        }

        /* Decimal integer */
        decimalInteger
        {
            m_position = YYCURSOR - m_sourceView.data();
            m_column += static_cast<int>(YYCURSOR - tokenStart);
            token.type = TokenType::Integer;
            token.intValue =
                std::strtoll(std::string(tokenStart, YYCURSOR - tokenStart).c_str(), nullptr, 10);
            return token;
        }

        /* Operators and delimiters */
        ">="
        {
            m_position = YYCURSOR - m_sourceView.data();
            m_column += 2;
            token.type = TokenType::Gte;
            return token;
        }
        "<="
        {
            m_position = YYCURSOR - m_sourceView.data();
            m_column += 2;
            token.type = TokenType::Lte;
            return token;
        }
        "=="
        {
            m_position = YYCURSOR - m_sourceView.data();
            m_column += 2;
            token.type = TokenType::Eq;
            return token;
        }
        ">"
        {
            m_position = YYCURSOR - m_sourceView.data();
            m_column += 1;
            token.type = TokenType::Gt;
            return token;
        }
        "<"
        {
            m_position = YYCURSOR - m_sourceView.data();
            m_column += 1;
            token.type = TokenType::Lt;
            return token;
        }
        "("
        {
            m_position = YYCURSOR - m_sourceView.data();
            m_column += 1;
            token.type = TokenType::LParen;
            return token;
        }
        ")"
        {
            m_position = YYCURSOR - m_sourceView.data();
            m_column += 1;
            token.type = TokenType::RParen;
            return token;
        }
        "["
        {
            m_position = YYCURSOR - m_sourceView.data();
            m_column += 1;
            token.type = TokenType::LBracket;
            return token;
        }
        "]"
        {
            m_position = YYCURSOR - m_sourceView.data();
            m_column += 1;
            token.type = TokenType::RBracket;
            return token;
        }
        ";"
        {
            m_position = YYCURSOR - m_sourceView.data();
            m_column += 1;
            token.type = TokenType::Semi;
            return token;
        }

        /* Catch-all for unknown identifiers and errors */
        identifier
        {
            m_position = YYCURSOR - m_sourceView.data();
            m_column += static_cast<int>(YYCURSOR - tokenStart);
            token.type = TokenType::Error;
            token.strValue =
                std::string_view(tokenStart, static_cast<size_t>(YYCURSOR - tokenStart));
            return token;
        }
        *
        {
            m_position = YYCURSOR - m_sourceView.data();
            m_column++;
            token.type = TokenType::Error;
            return token;
        }
        */

        /* ─── Keyword finalization ─────────────────────── */

#define EMIT_KW(TYPE)                                                                              \
    m_position = YYCURSOR - m_sourceView.data();                                                   \
    m_column += static_cast<int>(YYCURSOR - tokenStart);                                           \
    token.type = TokenType::TYPE;                                                                  \
    return token

    kwFind:
        EMIT_KW(Find);
    kwFunction:
        EMIT_KW(Function);
    kwGlobal:
        EMIT_KW(Global);
    kwIn:
        EMIT_KW(In);
    kwWhere:
        EMIT_KW(Where);
    kwCalls:
        EMIT_KW(Calls);
    kwCalledBy:
        EMIT_KW(CalledBy);
    kwReferencedBy:
        EMIT_KW(ReferencedBy);
    kwExported:
        EMIT_KW(Exported);
    kwNot:
        EMIT_KW(Not);
    kwHasLoop:
        EMIT_KW(HasLoop);
    kwTake:
        EMIT_KW(Take);
    kwFirst:
        EMIT_KW(First);
    kwCount:
        EMIT_KW(Count);
    kwOffset:
        EMIT_KW(Offset);
    kwArg:
        EMIT_KW(Arg);
    kwType:
        EMIT_KW(Type);
    kwXrefs:
        EMIT_KW(Xrefs);
    kwStackFrameSize:
        EMIT_KW(StackFrameSize);
    kwCallsCount:
        EMIT_KW(CallsCount);
    kwReadsReg:
        EMIT_KW(ReadsReg);

#undef EMIT_KW
    }

    std::vector<Token> Lexer::TokenizeAll()
    {
        std::vector<Token> tokens;
        while (true)
        {
            Token token = Next();
            tokens.push_back(token);
            if (token.type == TokenType::Eof || token.type == TokenType::Error)
            {
                break;
            }
        }
        return tokens;
    }

    /* Stub helpers — kept for header-API compatibility, unused after re2c integration */
    char Lexer::Peek() const
    {
        return m_position < m_sourceView.size() ? m_sourceView[m_position] : '\0';
    }
    char Lexer::Advance()
    {
        return m_position < m_sourceView.size() ? m_sourceView[m_position++] : '\0';
    }
    void Lexer::SkipWhitespaceAndComments()
    {
    }
    Token Lexer::ReadString()
    {
        return Next();
    }
    Token Lexer::ReadNumber()
    {
        return Next();
    }
    Token Lexer::ReadKeywordOrError()
    {
        return Next();
    }

} // namespace symfind::dsl
