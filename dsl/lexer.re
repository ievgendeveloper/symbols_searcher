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

namespace symfind::dsl {

Lexer::Lexer(std::string_view source)
    : storage_(source)               // copy → guarantees NUL terminator at storage_.data() + size()
    , source_(storage_)
{}

Token Lexer::next() {
    Token tok{};   // value-initialize all fields to zero/null

next_token:
    /* Standard re2c variables — pointers into the input buffer */
    const char* YYCURSOR = source_.data() + pos_;
    const char* YYMARKER = YYCURSOR;
    const char* tok_start = YYCURSOR;

    tok.line = line_;
    tok.column = column_;

    /*!re2c
        re2c:define:YYCTYPE = "char";
        re2c:yyfill:enable = 0;

        end       = "\x00";
        ws        = [ \t]+;
        nl        = "\r"? "\n";
        digit     = [0-9];
        hex       = "0x" [0-9a-fA-F]+;
        decimal   = digit+;
        comment   = "#" [^\n\x00]*;
        ident     = [a-zA-Z_][a-zA-Z0-9_]*;

        /* Skip whitespace, newlines, comments */
        ws        { pos_ = YYCURSOR - source_.data();
                    column_ += static_cast<int>(YYCURSOR - tok_start);
                    goto next_token; }
        nl        { pos_ = YYCURSOR - source_.data();
                    line_++;
                    column_ = 1;
                    goto next_token; }
        comment   { pos_ = YYCURSOR - source_.data();
                    column_ += static_cast<int>(YYCURSOR - tok_start);
                    goto next_token; }

        /* End of input */
        end       { /* Don't advance past the NUL terminator */
                    tok.type = TokenType::Eof;
                    return tok; }

        /* Keywords — we use goto to a finalization label
           because re2c rule actions can't easily share complex C++ code */
        "find"             { goto kw_find; }
        "function"         { goto kw_function; }
        "global"           { goto kw_global; }
        "in"               { goto kw_in; }
        "where"            { goto kw_where; }
        "calls"            { goto kw_calls; }
        "called_by"        { goto kw_called_by; }
        "referenced_by"    { goto kw_referenced_by; }
        "exported"         { goto kw_exported; }
        "not"              { goto kw_not; }
        "has_loop"         { goto kw_has_loop; }
        "take"             { goto kw_take; }
        "first"            { goto kw_first; }
        "count"            { goto kw_count; }
        "offset"           { goto kw_offset; }
        "arg"              { goto kw_arg; }
        "type"             { goto kw_type; }
        "xrefs"            { goto kw_xrefs; }
        "stack_frame_size" { goto kw_stack_frame_size; }
        "calls_count"      { goto kw_calls_count; }
        "reads_reg"        { goto kw_reads_reg; }

        /* String literal */
        ["] [^"\x00\n]* ["] {
            pos_ = YYCURSOR - source_.data();
            column_ += static_cast<int>(YYCURSOR - tok_start);
            tok.type = TokenType::String;
            /* Strip surrounding quotes; view points into storage_ which outlives all tokens */
            tok.str_value = std::string_view(tok_start + 1,
                                              static_cast<size_t>(YYCURSOR - tok_start - 2));
            return tok;
        }

        /* Hex integer */
        hex {
            pos_ = YYCURSOR - source_.data();
            column_ += static_cast<int>(YYCURSOR - tok_start);
            tok.type = TokenType::Integer;
            tok.int_value = std::strtoll(std::string(tok_start, YYCURSOR - tok_start).c_str(), nullptr, 16);
            return tok;
        }

        /* Decimal integer */
        decimal {
            pos_ = YYCURSOR - source_.data();
            column_ += static_cast<int>(YYCURSOR - tok_start);
            tok.type = TokenType::Integer;
            tok.int_value = std::strtoll(std::string(tok_start, YYCURSOR - tok_start).c_str(), nullptr, 10);
            return tok;
        }

        /* Operators and delimiters */
        ">="  { pos_ = YYCURSOR - source_.data(); column_ += 2; tok.type = TokenType::Gte;      return tok; }
        "<="  { pos_ = YYCURSOR - source_.data(); column_ += 2; tok.type = TokenType::Lte;      return tok; }
        "=="  { pos_ = YYCURSOR - source_.data(); column_ += 2; tok.type = TokenType::Eq;       return tok; }
        ">"   { pos_ = YYCURSOR - source_.data(); column_ += 1; tok.type = TokenType::Gt;       return tok; }
        "<"   { pos_ = YYCURSOR - source_.data(); column_ += 1; tok.type = TokenType::Lt;       return tok; }
        "("   { pos_ = YYCURSOR - source_.data(); column_ += 1; tok.type = TokenType::LParen;   return tok; }
        ")"   { pos_ = YYCURSOR - source_.data(); column_ += 1; tok.type = TokenType::RParen;   return tok; }
        "["   { pos_ = YYCURSOR - source_.data(); column_ += 1; tok.type = TokenType::LBracket; return tok; }
        "]"   { pos_ = YYCURSOR - source_.data(); column_ += 1; tok.type = TokenType::RBracket; return tok; }
        ";"   { pos_ = YYCURSOR - source_.data(); column_ += 1; tok.type = TokenType::Semi;     return tok; }

        /* Catch-all for unknown identifiers and errors */
        ident {
            pos_ = YYCURSOR - source_.data();
            column_ += static_cast<int>(YYCURSOR - tok_start);
            tok.type = TokenType::Error;
            tok.str_value = std::string_view(tok_start,
                                              static_cast<size_t>(YYCURSOR - tok_start));
            return tok;
        }
        * {
            pos_ = YYCURSOR - source_.data();
            column_++;
            tok.type = TokenType::Error;
            return tok;
        }
    */

    /* ─── Keyword finalization ─────────────────────── */

#define EMIT_KW(TYPE)                                              \
    pos_ = YYCURSOR - source_.data();                              \
    column_ += static_cast<int>(YYCURSOR - tok_start);             \
    tok.type = TokenType::TYPE;                                    \
    return tok

kw_find:             EMIT_KW(Find);
kw_function:         EMIT_KW(Function);
kw_global:           EMIT_KW(Global);
kw_in:               EMIT_KW(In);
kw_where:            EMIT_KW(Where);
kw_calls:            EMIT_KW(Calls);
kw_called_by:        EMIT_KW(CalledBy);
kw_referenced_by:    EMIT_KW(ReferencedBy);
kw_exported:         EMIT_KW(Exported);
kw_not:              EMIT_KW(Not);
kw_has_loop:         EMIT_KW(HasLoop);
kw_take:             EMIT_KW(Take);
kw_first:            EMIT_KW(First);
kw_count:            EMIT_KW(Count);
kw_offset:           EMIT_KW(Offset);
kw_arg:              EMIT_KW(Arg);
kw_type:             EMIT_KW(Type);
kw_xrefs:            EMIT_KW(Xrefs);
kw_stack_frame_size: EMIT_KW(StackFrameSize);
kw_calls_count:      EMIT_KW(CallsCount);
kw_reads_reg:        EMIT_KW(ReadsReg);

#undef EMIT_KW
}

std::vector<Token> Lexer::tokenize_all() {
    std::vector<Token> tokens;
    while (true) {
        Token t = next();
        tokens.push_back(t);
        if (t.type == TokenType::Eof || t.type == TokenType::Error) break;
    }
    return tokens;
}

/* Stub helpers — kept for header-API compatibility, unused after re2c integration */
char  Lexer::peek() const { return pos_ < source_.size() ? source_[pos_] : '\0'; }
char  Lexer::advance() { return pos_ < source_.size() ? source_[pos_++] : '\0'; }
void  Lexer::skip_whitespace_and_comments() {}
Token Lexer::read_string()           { return next(); }
Token Lexer::read_number()           { return next(); }
Token Lexer::read_keyword_or_error() { return next(); }

} // namespace symfind::dsl
