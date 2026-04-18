#include "symfind/dsl_matcher.h"

#include <spdlog/spdlog.h>
#include <algorithm>
#include <format>

namespace symfind::dsl {

bool DslMatcher::compare(int64_t lhs, CmpOp op, int64_t rhs) {
    switch (op) {
        case CmpOp::Eq:  return lhs == rhs;
        case CmpOp::Gt:  return lhs >  rhs;
        case CmpOp::Lt:  return lhs <  rhs;
        case CmpOp::Gte: return lhs >= rhs;
        case CmpOp::Lte: return lhs <= rhs;
    }
    return false;
}

std::vector<MatchResult> DslMatcher::match(const AnalysisDb& db,
                                            const Rule& rule) {
    std::vector<MatchResult> results;

    // Verify module name
    // TODO: case-insensitive comparison
    spdlog::info("Matching rule against module '{}'", db.module_name());

    if (rule.target == TargetKind::Function) {
        for (const auto& func : db.functions()) {
            if (match_function(db, func, rule.predicates)) {
                results.push_back(MatchResult{
                    .rva = func.rva,
                    .name = func.name,
                    .kind = TargetKind::Function,
                });
            }
        }
    } else if (rule.target == TargetKind::Global) {
        for (const auto& global : db.globals()) {
            if (match_global(db, global, rule.predicates)) {
                results.push_back(MatchResult{
                    .rva = global.rva,
                    .name = std::format("global_{:X}", global.rva),
                    .kind = TargetKind::Global,
                });
            }
        }
    }

    // Apply `take` filtering
    apply_take(results, rule.predicates);

    spdlog::info("Found {} matches", results.size());
    return results;
}

bool DslMatcher::match_function(const AnalysisDb& db,
                                 const AnalyzedFunction& func,
                                 const std::vector<PredicatePtr>& predicates) {
    for (const auto& pred : predicates) {
        if (!pred) continue;
        // Skip `take` — it's handled after matching
        if (pred->kind == PredKind::Take) continue;
        if (!eval_function_pred(db, func, *pred)) return false;
    }
    return true;
}

bool DslMatcher::match_global(const AnalysisDb& db,
                               const Global& global,
                               const std::vector<PredicatePtr>& predicates) {
    for (const auto& pred : predicates) {
        if (!pred) continue;
        if (pred->kind == PredKind::Take) continue;
        if (!eval_global_pred(db, global, *pred)) return false;
    }
    return true;
}

bool DslMatcher::eval_function_pred(const AnalysisDb& db,
                                     const AnalyzedFunction& func,
                                     const Predicate& pred) {
    switch (pred.kind) {

    case PredKind::Calls: {
        // Check if this function calls the named function
        const auto* target = db.function_by_name(pred.str_value);
        if (!target) return false;
        return std::find(func.callees.begin(), func.callees.end(),
                         target->rva) != func.callees.end();
    }

    case PredKind::CalledBy: {
        // Check if this function is called by the named function
        const auto* caller = db.function_by_name(pred.str_value);
        if (!caller) return false;
        return std::find(func.callers.begin(), func.callers.end(),
                         caller->rva) != func.callers.end();
    }

    case PredKind::CalledByBlock: {
        // Check if ANY caller of this function matches all inner predicates
        for (uint64_t caller_rva : func.callers) {
            const auto* caller = db.function_at(caller_rva);
            if (!caller) continue;
            bool all_match = true;
            for (const auto& inner : pred.children) {
                if (!eval_function_pred(db, *caller, *inner)) {
                    all_match = false;
                    break;
                }
            }
            if (all_match) return true;
        }
        return false;
    }

    case PredKind::Exported:
        return func.exported;

    case PredKind::NotExported:
        return !func.exported;

    case PredKind::HasLoop:
        return func.has_loop;

    case PredKind::Not:
        return pred.child ? !eval_function_pred(db, func, *pred.child) : true;

    case PredKind::CallsCount:
        return compare(func.call_count, pred.cmp_op, pred.int_value);

    case PredKind::Xrefs: {
        auto xrefs = db.xrefs_to(func.rva);
        return compare(static_cast<int64_t>(xrefs.size()), pred.cmp_op, pred.int_value);
    }

    case PredKind::StackFrameSize:
        return compare(func.stack_frame_size, pred.cmp_op, pred.int_value);

    default:
        spdlog::warn("Unhandled predicate kind {} for function matching",
                     static_cast<int>(pred.kind));
        return false;
    }
}

bool DslMatcher::eval_global_pred(const AnalysisDb& db,
                                   const Global& global,
                                   const Predicate& pred) {
    switch (pred.kind) {

    case PredKind::ReferencedBy: {
        const auto* func = db.function_by_name(pred.str_value);
        if (!func) return false;
        for (const auto& ref : global.refs) {
            if (ref.from_func == func->rva) return true;
        }
        return false;
    }

    case PredKind::Xrefs:
        return compare(static_cast<int64_t>(global.refs.size()),
                       pred.cmp_op, pred.int_value);

    case PredKind::Not:
        return pred.child ? !eval_global_pred(db, global, *pred.child) : true;

    default:
        spdlog::warn("Unhandled predicate kind {} for global matching",
                     static_cast<int>(pred.kind));
        return false;
    }
}

void DslMatcher::apply_take(std::vector<MatchResult>& results,
                             const std::vector<PredicatePtr>& predicates) {
    for (const auto& pred : predicates) {
        if (pred && pred->kind == PredKind::Take) {
            auto n = static_cast<size_t>(pred->int_value);
            if (results.size() > n) {
                results.resize(n);
            }
            break;
        }
    }
}

} // namespace symfind::dsl
