#pragma once

#include "symfind/analysis_db.h"
#include "symfind/dsl_parser.h"

#include <cstdint>
#include <vector>

namespace symfind::dsl {

/// Result of a DSL match.
struct MatchResult {
    uint64_t    rva = 0;
    std::string name;               ///< Export name or "sub_XXXX"
    TargetKind  kind = TargetKind::Function;
};

/// Executes a parsed DSL rule against an AnalysisDb.
class DslMatcher {
public:
    /// Run a rule and return all matching results.
    [[nodiscard]]
    static std::vector<MatchResult> match(const AnalysisDb& db,
                                           const Rule& rule);

private:
    /// Check if a function satisfies all predicates.
    static bool match_function(const AnalysisDb& db,
                                const AnalyzedFunction& func,
                                const std::vector<PredicatePtr>& predicates);

    /// Check if a global satisfies all predicates.
    static bool match_global(const AnalysisDb& db,
                              const Global& global,
                              const std::vector<PredicatePtr>& predicates);

    /// Evaluate a single predicate against a function.
    static bool eval_function_pred(const AnalysisDb& db,
                                    const AnalyzedFunction& func,
                                    const Predicate& pred);

    /// Evaluate a single predicate against a global.
    static bool eval_global_pred(const AnalysisDb& db,
                                  const Global& global,
                                  const Predicate& pred);

    /// Numeric comparison helper.
    static bool compare(int64_t lhs, CmpOp op, int64_t rhs);

    /// Apply `take` filtering to results.
    static void apply_take(std::vector<MatchResult>& results,
                            const std::vector<PredicatePtr>& predicates);
};

} // namespace symfind::dsl
