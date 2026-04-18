#include "symfind/dsl_parser.h"

#include <spdlog/spdlog.h>

namespace symfind::dsl {

DslParser::DslParser(std::vector<Token> tokens) : tokens_(std::move(tokens)) {}

const Token& DslParser::current() const {
    static const Token eof{TokenType::Eof};
    if (pos_ >= tokens_.size()) return eof;
    return tokens_[pos_];
}

const Token& DslParser::advance() {
    const auto& tok = current();
    if (pos_ < tokens_.size()) pos_++;
    return tok;
}

bool DslParser::at_end() const {
    return pos_ >= tokens_.size() || current().type == TokenType::Eof;
}

bool DslParser::match(TokenType type) {
    if (current().type == type) {
        advance();
        return true;
    }
    return false;
}

bool DslParser::expect(TokenType type) {
    if (!match(type)) {
        spdlog::error("Expected token type {}, got '{}' at line {}",
                      static_cast<int>(type),
                      current().str_value,
                      current().line);
        return false;
    }
    return true;
}

std::optional<CmpOp> DslParser::parse_cmp_op() {
    switch (current().type) {
        case TokenType::Gte: advance(); return CmpOp::Gte;
        case TokenType::Lte: advance(); return CmpOp::Lte;
        case TokenType::Eq:  advance(); return CmpOp::Eq;
        case TokenType::Gt:  advance(); return CmpOp::Gt;
        case TokenType::Lt:  advance(); return CmpOp::Lt;
        default:
            spdlog::error("Expected comparison operator at line {}", current().line);
            return std::nullopt;
    }
}

std::optional<Rule> DslParser::parse(std::string_view source) {
    Lexer lexer(source);
    auto tokens = lexer.tokenize_all();

    DslParser parser(std::move(tokens));
    return parser.parse_rule();
}

std::optional<Rule> DslParser::parse_rule() {
    Rule rule;

    // "find"
    if (!expect(TokenType::Find)) return std::nullopt;

    // "function" | "global"
    if (match(TokenType::Function)) {
        rule.target = TargetKind::Function;
    } else if (match(TokenType::Global)) {
        rule.target = TargetKind::Global;
    } else {
        spdlog::error("Expected 'function' or 'global' after 'find' at line {}",
                      current().line);
        return std::nullopt;
    }

    // "in"
    if (!expect(TokenType::In)) return std::nullopt;

    // "module_name"
    if (current().type != TokenType::String) {
        spdlog::error("Expected module name string at line {}", current().line);
        return std::nullopt;
    }
    rule.module_name = advance().str_value;

    // "where"
    if (!expect(TokenType::Where)) return std::nullopt;

    // Predicates until EOF
    while (!at_end()) {
        auto pred = parse_predicate();
        if (!pred) return std::nullopt;
        rule.predicates.push_back(std::move(pred));
    }

    if (rule.predicates.empty()) {
        spdlog::error("Rule must have at least one predicate");
        return std::nullopt;
    }

    return rule;
}

PredicatePtr DslParser::parse_predicate() {
    auto pred = std::make_unique<Predicate>();

    switch (current().type) {

    // calls "FunctionName"
    case TokenType::Calls: {
        advance();
        if (current().type != TokenType::String) {
            spdlog::error("Expected function name after 'calls' at line {}", current().line);
            return nullptr;
        }
        pred->kind = PredKind::Calls;
        pred->str_value = advance().str_value;
        return pred;
    }

    // called_by "FunctionName"  |  called_by ( ... )
    case TokenType::CalledBy: {
        advance();
        if (current().type == TokenType::String) {
            pred->kind = PredKind::CalledBy;
            pred->str_value = advance().str_value;
        } else if (match(TokenType::LParen)) {
            pred->kind = PredKind::CalledByBlock;
            while (!at_end() && current().type != TokenType::RParen) {
                auto inner = parse_predicate();
                if (!inner) return nullptr;
                pred->children.push_back(std::move(inner));
            }
            if (!expect(TokenType::RParen)) return nullptr;
        } else {
            spdlog::error("Expected string or '(' after 'called_by' at line {}",
                          current().line);
            return nullptr;
        }
        return pred;
    }

    // referenced_by "FunctionName"
    case TokenType::ReferencedBy: {
        advance();
        if (current().type != TokenType::String) {
            spdlog::error("Expected function name after 'referenced_by' at line {}",
                          current().line);
            return nullptr;
        }
        pred->kind = PredKind::ReferencedBy;
        pred->str_value = advance().str_value;
        return pred;
    }

    // not <predicate>  |  "not exported"
    case TokenType::Not: {
        advance();
        if (current().type == TokenType::Exported) {
            advance();
            pred->kind = PredKind::NotExported;
        } else {
            pred->kind = PredKind::Not;
            pred->child = parse_predicate();
            if (!pred->child) return nullptr;
        }
        return pred;
    }

    // exported
    case TokenType::Exported: {
        advance();
        pred->kind = PredKind::Exported;
        return pred;
    }

    // has_loop
    case TokenType::HasLoop: {
        advance();
        pred->kind = PredKind::HasLoop;
        return pred;
    }

    // take first  |  take N
    case TokenType::Take: {
        advance();
        pred->kind = PredKind::Take;
        if (match(TokenType::First)) {
            pred->int_value = 1;
        } else if (current().type == TokenType::Integer) {
            pred->int_value = advance().int_value;
        } else {
            spdlog::error("Expected 'first' or number after 'take' at line {}",
                          current().line);
            return nullptr;
        }
        return pred;
    }

    // calls_count op N
    case TokenType::CallsCount: {
        advance();
        auto op = parse_cmp_op();
        if (!op) return nullptr;
        if (current().type != TokenType::Integer) {
            spdlog::error("Expected integer after operator at line {}", current().line);
            return nullptr;
        }
        pred->kind = PredKind::CallsCount;
        pred->cmp_op = *op;
        pred->int_value = advance().int_value;
        return pred;
    }

    // xrefs count op N
    case TokenType::Xrefs: {
        advance();
        if (!expect(TokenType::Count)) return nullptr;
        auto op = parse_cmp_op();
        if (!op) return nullptr;
        if (current().type != TokenType::Integer) {
            spdlog::error("Expected integer after operator at line {}", current().line);
            return nullptr;
        }
        pred->kind = PredKind::Xrefs;
        pred->cmp_op = *op;
        pred->int_value = advance().int_value;
        return pred;
    }

    // stack_frame_size op N
    case TokenType::StackFrameSize: {
        advance();
        auto op = parse_cmp_op();
        if (!op) return nullptr;
        if (current().type != TokenType::Integer) {
            spdlog::error("Expected integer after operator at line {}", current().line);
            return nullptr;
        }
        pred->kind = PredKind::StackFrameSize;
        pred->cmp_op = *op;
        pred->int_value = advance().int_value;
        return pred;
    }

    // reads_reg <regname>
    case TokenType::ReadsReg: {
        advance();
        if (current().type != TokenType::String) {
            spdlog::error("Expected register name after 'reads_reg' at line {}",
                          current().line);
            return nullptr;
        }
        pred->kind = PredKind::ReadsReg;
        pred->str_value = advance().str_value;
        return pred;
    }

    default:
        spdlog::error("Unexpected token '{}' at line {}",
                      current().str_value, current().line);
        return nullptr;
    }
}

} // namespace symfind::dsl
