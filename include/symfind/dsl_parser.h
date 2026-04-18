#pragma once

#include "symfind/dsl_lexer.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace symfind::dsl {

// ─── Comparison ──────────────────────────────────────

enum class CmpOp { Eq, Gt, Lt, Gte, Lte };

// ─── AST Nodes ───────────────────────────────────────

/// What kind of entity we are searching for.
enum class TargetKind {
    Function,
    Global,
};

/// Types of predicates.
enum class PredKind {
    Calls,              ///< calls "X"
    CalledBy,           ///< called_by "X"
    CalledByBlock,      ///< called_by ( ... predicates ... )
    ReferencedBy,       ///< referenced_by "X"
    Exported,           ///< exported
    NotExported,        ///< not exported
    HasLoop,            ///< has_loop
    Not,                ///< not <predicate>
    CallsCount,         ///< calls_count op N
    Xrefs,              ///< xrefs count op N
    StackFrameSize,     ///< stack_frame_size op N
    ReadsReg,           ///< reads_reg <name>
    ArgType,            ///< arg[N] type "T"
    Take,               ///< take first | take N
};

struct Predicate;
using PredicatePtr = std::unique_ptr<Predicate>;

struct Predicate {
    PredKind    kind;

    // Value fields — used depending on `kind`
    std::string str_value;
    int64_t     int_value = 0;
    CmpOp       cmp_op = CmpOp::Eq;

    // Nested predicate (for `not`)
    PredicatePtr child;

    // Nested predicate list (for `called_by ( ... )`)
    std::vector<PredicatePtr> children;
};

/// A complete DSL rule.
struct Rule {
    TargetKind                  target = TargetKind::Function;
    std::string                 module_name;
    std::vector<PredicatePtr>   predicates;
};

// ─── Parser ──────────────────────────────────────────

/// Parse a DSL script string into a Rule AST.
class DslParser {
public:
    /// Parse a complete rule from source text.
    /// Returns nullopt on parse error (errors logged via spdlog).
    [[nodiscard]]
    static std::optional<Rule> parse(std::string_view source);

private:
    explicit DslParser(std::vector<Token> tokens);

    std::optional<Rule> parse_rule();
    PredicatePtr parse_predicate();
    std::optional<CmpOp> parse_cmp_op();

    const Token& current() const;
    const Token& advance();
    bool expect(TokenType type);
    bool match(TokenType type);
    bool at_end() const;

    std::vector<Token> tokens_;
    size_t pos_ = 0;
};

} // namespace symfind::dsl
