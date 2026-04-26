#pragma once

#include "symfind/dsl_lexer.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace symfind::dsl
{
    // ─── Comparison ──────────────────────────────────────

    enum class CmpOp { Eq, Gt, Lt, Gte, Lte };

    // ─── Target kind ─────────────────────────────────────

    enum class TargetKind
    {
        Function,
        Global,
    };

    // ─── Predicate kinds ─────────────────────────────────

    enum class PredKind
    {
        Calls, ///< calls "X"
        CalledBy, ///< called_by "X"
        CalledByBlock, ///< called_by ( ... predicates ... )
        ReferencedBy, ///< referenced_by "X"
        Exported, ///< exported
        HasLoop, ///< has_loop
        Not, ///< not <predicate>
        CallsCount, ///< calls_count op N
        Xrefs, ///< xrefs count op N
        StackFrameSize, ///< stack_frame_size op N
        ReadsReg, ///< reads_reg "name"
        ArgType, ///< arg[N] type "T"
        Take, ///< take first | take N
    };

    struct Predicate;
    using PredicatePtr = std::unique_ptr<Predicate>;

    struct Predicate
    {
        PredKind kind;

        std::string str_value;
        int64_t int_value = 0;
        CmpOp cmp_op = CmpOp::Eq;

        PredicatePtr child; ///< for `not`
        std::vector<PredicatePtr> children; ///< for `called_by ( ... )`
    };

    /// A complete DSL rule.
    struct Rule
    {
        TargetKind target = TargetKind::Function;
        std::string module_name;
        std::vector<PredicatePtr> predicates;
    };

    // ─── Parser context (used by Lemon-generated parser) ─

    /// State passed to the Lemon parser via %extra_argument.
    /// The grammar action blocks fill in `result`; on syntax error,
    /// `had_error` is set.
    struct ParserContext
    {
        Rule result;
        bool had_error = false;
        int error_line = 0;
    };

    // ─── Public parser API ──────────────────────────────

    /// Parse a DSL script into a Rule AST.
    /// Returns nullopt on syntax error.
    class DslParser
    {
        public:
            [[nodiscard]]
            static std::optional<Rule> parse(std::string_view source);
    };

} // namespace symfind::dsl