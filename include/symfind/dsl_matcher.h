#pragma once

#include "symfind/analysis_db.h"
#include "symfind/dsl_parser.h"

#include <cstdint>
#include <vector>

namespace symfind::dsl
{

    /// Result of a DSL match.
    struct MatchResult
    {
            uint64_t rva = 0;
            std::string name; ///< Export name or "sub_XXXX"
            TargetKind kind = TargetKind::Function;
    };

    /// Executes a parsed DSL rule against an AnalysisDb.
    class DslMatcher
    {
        public:
            /// Run a rule and return all matching results.
            [[nodiscard]] static std::vector<MatchResult> Match(const AnalysisDb& analysisDatabase,
                                                                const Rule& parsedRule);

        private:
            /// Check if a function satisfies all predicates.
            static bool MatchFunction(const AnalysisDb& analysisDatabase,
                                      const AnalyzedFunction& candidateFunction,
                                      const std::vector<PredicatePtr>& predicates);

            /// Check if a global satisfies all predicates.
            static bool MatchGlobal(const AnalysisDb& analysisDatabase,
                                    const Global& candidateGlobal,
                                    const std::vector<PredicatePtr>& predicates);

            /// Evaluate a single predicate against a function.
            static bool EvalFunctionPred(const AnalysisDb& analysisDatabase,
                                         const AnalyzedFunction& candidateFunction,
                                         const Predicate& predicate);

            /// Evaluate a single predicate against a global.
            static bool EvalGlobalPred(const AnalysisDb& analysisDatabase,
                                       const Global& candidateGlobal, const Predicate& predicate);

            /// Numeric comparison helper.
            static bool Compare(int64_t actualValue, CmpOp comparisonOperator,
                                int64_t expectedValue);

            /// Apply `take` filtering to results.
            static void ApplyTake(std::vector<MatchResult>& matchedSymbols,
                                  const std::vector<PredicatePtr>& predicates);
    };

} // namespace symfind::dsl
