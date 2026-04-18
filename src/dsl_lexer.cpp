#include "symfind/dsl_lexer.h"

#include <spdlog/spdlog.h>
#include <unordered_map>

namespace symfind::dsl {

static const std::unordered_map<std::string, TokenType> keywords = {
    {"find",             TokenType::Find},
    {"function",         TokenType::Function},
    {"global",           TokenType::Global},
    {"in",               TokenType::In},
    {"where",            TokenType::Where},
    {"calls",            TokenType::Calls},
    {"called_by",        TokenType::CalledBy},
    {"referenced_by",    TokenType::ReferencedBy},
    {"exported",         TokenType::Exported},
    {"not",              TokenType::Not},
    {"has_loop",         TokenType::HasLoop},
    {"take",             TokenType::Take},
    {"first",            TokenType::First},
    {"count",            TokenType::Count},
    {"offset",           TokenType::Offset},
    {"arg",              TokenType::Arg},
    {"type",             TokenType::Type},
    {"xrefs",            TokenType::Xrefs},
    {"stack_frame_size", TokenType::StackFrameSize},
    {"calls_count",      TokenType::CallsCount},
    {"reads_reg",        TokenType::ReadsReg},
};

Lexer::Lexer(std::string_view source) : source_(source) {}

char Lexer::peek() const {
    if (pos_ >= source_.size()) return '\0';
    return source_[pos_];
}

char Lexer::advance() {
    char c = source_[pos_++];
    if (c == '\n') { line_++; column_ = 1; }
    else { column_++; }
    return c;
}

void Lexer::skip_whitespace_and_comments() {
    while (pos_ < source_.size()) {
        char c = peek();
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            advance();
        } else if (c == '#') {
            // Comment until end of line
            while (pos_ < source_.size() && peek() != '\n') advance();
        } else {
            break;
        }
    }
}

Token Lexer::read_string() {
    Token tok;
    tok.line = line_;
    tok.column = column_;
    advance(); // skip opening quote

    std::string value;
    while (pos_ < source_.size() && peek() != '"') {
        if (peek() == '\n' || peek() == '\0') {
            spdlog::error("Unterminated string at line {}", line_);
            tok.type = TokenType::Error;
            return tok;
        }
        value += advance();
    }
    if (pos_ < source_.size()) advance(); // skip closing quote

    tok.type = TokenType::String;
    tok.str_value = std::move(value);
    return tok;
}

Token Lexer::read_number() {
    Token tok;
    tok.line = line_;
    tok.column = column_;

    std::string num;
    bool hex = false;

    if (peek() == '0' && pos_ + 1 < source_.size() &&
        (source_[pos_ + 1] == 'x' || source_[pos_ + 1] == 'X')) {
        num += advance(); // '0'
        num += advance(); // 'x'
        hex = true;
        while (pos_ < source_.size() && std::isxdigit(peek())) {
            num += advance();
        }
    } else {
        while (pos_ < source_.size() && std::isdigit(peek())) {
            num += advance();
        }
    }

    tok.type = TokenType::Integer;
    tok.int_value = std::stoll(num, nullptr, hex ? 16 : 10);
    return tok;
}

Token Lexer::read_keyword_or_error() {
    Token tok;
    tok.line = line_;
    tok.column = column_;

    std::string word;
    while (pos_ < source_.size() &&
           (std::isalnum(peek()) || peek() == '_')) {
        word += advance();
    }

    auto it = keywords.find(word);
    if (it != keywords.end()) {
        tok.type = it->second;
        tok.str_value = std::move(word);
    } else {
        spdlog::error("Unknown keyword '{}' at line {}:{}", word, tok.line, tok.column);
        tok.type = TokenType::Error;
        tok.str_value = std::move(word);
    }
    return tok;
}

Token Lexer::next() {
    skip_whitespace_and_comments();

    if (pos_ >= source_.size()) {
        return Token{TokenType::Eof, "", 0, line_, column_};
    }

    char c = peek();

    // String literal
    if (c == '"') return read_string();

    // Number
    if (std::isdigit(c)) return read_number();

    // Keyword or identifier
    if (std::isalpha(c) || c == '_') return read_keyword_or_error();

    // Operators and delimiters
    Token tok;
    tok.line = line_;
    tok.column = column_;

    switch (c) {
        case '(':  advance(); tok.type = TokenType::LParen;   return tok;
        case ')':  advance(); tok.type = TokenType::RParen;   return tok;
        case '[':  advance(); tok.type = TokenType::LBracket; return tok;
        case ']':  advance(); tok.type = TokenType::RBracket; return tok;
        case '>':
            advance();
            if (peek() == '=') { advance(); tok.type = TokenType::Gte; }
            else { tok.type = TokenType::Gt; }
            return tok;
        case '<':
            advance();
            if (peek() == '=') { advance(); tok.type = TokenType::Lte; }
            else { tok.type = TokenType::Lt; }
            return tok;
        case '=':
            advance();
            if (peek() == '=') { advance(); tok.type = TokenType::Eq; }
            else {
                spdlog::error("Expected '==' at line {}:{}", tok.line, tok.column);
                tok.type = TokenType::Error;
            }
            return tok;
        default:
            advance();
            spdlog::error("Unexpected character '{}' at line {}:{}", c, tok.line, tok.column);
            tok.type = TokenType::Error;
            return tok;
    }
}

std::vector<Token> Lexer::tokenize_all() {
    std::vector<Token> tokens;
    while (true) {
        auto tok = next();
        tokens.push_back(tok);
        if (tok.type == TokenType::Eof || tok.type == TokenType::Error) break;
    }
    return tokens;
}

} // namespace symfind::dsl
