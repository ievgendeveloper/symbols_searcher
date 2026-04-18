#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace symfind::dsl {

enum class TokenType {
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
    String,         ///< "quoted string"
    Integer,        ///< 123 or 0xFF

    // Operators
    Gte,            ///< >=
    Lte,            ///< <=
    Eq,             ///< ==
    Gt,             ///< >
    Lt,             ///< <

    // Delimiters
    LParen,         ///< (
    RParen,         ///< )
    LBracket,       ///< [
    RBracket,       ///< ]

    // Special
    Eof,
    Error,
};

struct Token {
    TokenType   type = TokenType::Error;
    std::string str_value;          ///< For String tokens
    int64_t     int_value = 0;      ///< For Integer tokens
    int         line = 0;
    int         column = 0;
};

/// Tokenize a DSL script into a sequence of tokens.
class Lexer {
public:
    explicit Lexer(std::string_view source);

    /// Get the next token.
    [[nodiscard]] Token next();

    /// Tokenize the entire input.
    [[nodiscard]] std::vector<Token> tokenize_all();

private:
    std::string_view source_;
    size_t pos_ = 0;
    int line_ = 1;
    int column_ = 1;

    char peek() const;
    char advance();
    void skip_whitespace_and_comments();
    Token read_string();
    Token read_number();
    Token read_keyword_or_error();
};

} // namespace symfind::dsl
