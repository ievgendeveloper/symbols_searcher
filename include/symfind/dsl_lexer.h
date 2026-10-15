#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace symfind::dsl
{

    enum class TokenType
    {
        // Keywords
        Find,
        Function,
        Global,
        In,
        Where,
        Calls,
        CalledBy,
        ReferencedBy,
        Exported,
        Not,
        HasLoop,
        Take,
        First,
        Count,
        Offset,
        Arg,
        Type,
        Xrefs,
        StackFrameSize,
        CallsCount,
        ReadsReg,

        // Literals
        String,  ///< "quoted string"
        Integer, ///< 123 or 0xFF

        // Operators
        Gte, ///< >=
        Lte, ///< <=
        Eq,  ///< ==
        Gt,  ///< >
        Lt,  ///< <

        // Delimiters
        LParen,   ///< (
        RParen,   ///< )
        LBracket, ///< [
        RBracket, ///< ]
        Semi,     ///< ;

        // Special
        Eof,
        Error,
    };

    /// A lexer token.
    ///
    /// This struct is intentionally a plain aggregate without
    /// default member initializers. Lemon places `Token` inside
    /// a C-style union (YYMINORTYPE), and in C++ a union member
    /// must be trivially default-constructible. Default member
    /// initializers would make the implicit default ctor
    /// "user-provided", which disqualifies it.
    ///
    /// Always initialize Tokens with `{}` at the call site.
    struct Token
    {
            TokenType type;
            std::string_view str_value;
            int64_t int_value;
            int line;
            int column;
    };

    /// Tokenize a DSL script into a sequence of tokens.
    ///
    /// Implementation is generated from `dsl/lexer.re` by re2c.
    class Lexer
    {
        public:
            explicit Lexer(std::string_view source);

            /// Get the next token.
            [[nodiscard]] Token next();

            /// Tokenize the entire input (until EOF or first Error).
            [[nodiscard]] std::vector<Token> tokenize_all();

        private:
            std::string storage_;     ///< owned NUL-terminated copy of input
            std::string_view source_; ///< view into storage_
            size_t pos_ = 0;
            int line_ = 1;
            int column_ = 1;

            // Internal helpers (kept for ABI compatibility — unused by re2c-generated next()).
            char peek() const;
            char advance();
            void skip_whitespace_and_comments();
            Token read_string();
            Token read_number();
            Token read_keyword_or_error();
    };

} // namespace symfind::dsl
