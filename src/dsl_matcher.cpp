#include "symfind/dsl_matcher.h"

#include <algorithm>
#include <spdlog/fmt/fmt.h>
#include <spdlog/spdlog.h>

namespace symfind::dsl
{
    namespace
    {
        std::string_view ModuleBasename(std::string_view moduleName)
        {
            const auto separatorPosition = moduleName.find_last_of("/\\");
            return separatorPosition == std::string_view::npos
                       ? moduleName
                       : moduleName.substr(separatorPosition + 1);
        }

        unsigned char AsciiLower(unsigned char character)
        {
            return character >= 'A' && character <= 'Z'
                       ? static_cast<unsigned char>(character + ('a' - 'A'))
                       : character;
        }

        bool AsciiEqual(std::string_view leftText, std::string_view rightText)
        {
            return leftText.size() == rightText.size() &&
                   std::equal(leftText.begin(), leftText.end(), rightText.begin(),
                              [](unsigned char leftCharacter, unsigned char rightCharacter)
                              {
                                  return AsciiLower(leftCharacter) == AsciiLower(rightCharacter);
                              });
        }

        bool MatchesModule(std::string_view actualModuleName, std::string_view requestedModuleName)
        {
            actualModuleName = ModuleBasename(actualModuleName);
            requestedModuleName = ModuleBasename(requestedModuleName);
            if (actualModuleName.empty() || requestedModuleName.empty())
            {
                return false;
            }
            if (AsciiEqual(actualModuleName, requestedModuleName))
            {
                return true;
            }

            // Existing rules use "ntdll" for "ntdll.dll". Only a bare name
            // may omit .dll; explicit .exe/.sys and other suffixes stay distinct.
            const auto matchesDllAlias =
                [](std::string_view bareModuleName, std::string_view moduleFilename)
            {
                constexpr std::string_view dllSuffix = ".dll";
                return bareModuleName.find('.') == std::string_view::npos &&
                       moduleFilename.size() > dllSuffix.size() &&
                       AsciiEqual(moduleFilename.substr(moduleFilename.size() - dllSuffix.size()),
                                  dllSuffix) &&
                       AsciiEqual(bareModuleName, moduleFilename.substr(0, moduleFilename.size() -
                                                                               dllSuffix.size()));
            };
            return matchesDllAlias(actualModuleName, requestedModuleName) ||
                   matchesDllAlias(requestedModuleName, actualModuleName);
        }
    } // namespace

    bool DslMatcher::Compare(int64_t actualValue, CmpOp comparisonOperator, int64_t expectedValue)
    {
        switch (comparisonOperator)
        {
        case CmpOp::Eq:
            return actualValue == expectedValue;
        case CmpOp::Gt:
            return actualValue > expectedValue;
        case CmpOp::Lt:
            return actualValue < expectedValue;
        case CmpOp::Gte:
            return actualValue >= expectedValue;
        case CmpOp::Lte:
            return actualValue <= expectedValue;
        }
        return false;
    }

    std::vector<MatchResult> DslMatcher::Match(const AnalysisDb& analysisDatabase,
                                               const Rule& parsedRule)
    {
        std::vector<MatchResult> matchedSymbols;

        SPDLOG_INFO("Matching rule against module '{}'", analysisDatabase.ModuleName());
        if (!MatchesModule(analysisDatabase.ModuleName(), parsedRule.moduleName))
        {
            SPDLOG_DEBUG("Rule module '{}' does not match '{}'", parsedRule.moduleName,
                         analysisDatabase.ModuleName());
            return matchedSymbols;
        }

        if (parsedRule.target == TargetKind::Function)
        {
            for (const auto& candidateFunction : analysisDatabase.Functions())
            {
                if (MatchFunction(analysisDatabase, candidateFunction, parsedRule.predicates))
                {
                    matchedSymbols.push_back(MatchResult{
                        candidateFunction.rva, candidateFunction.name, TargetKind::Function});
                }
            }
        }
        else if (parsedRule.target == TargetKind::Global)
        {
            SPDLOG_INFO("Iterating {} globals", analysisDatabase.Globals().size());

            for (const auto& candidateGlobal : analysisDatabase.Globals())
            {
                if (MatchGlobal(analysisDatabase, candidateGlobal, parsedRule.predicates))
                {
                    matchedSymbols.push_back(MatchResult{
                        candidateGlobal.rva, fmt::format("global_{:X}", candidateGlobal.rva),
                        TargetKind::Global});
                }
            }
        }

        // Apply `take` filtering
        ApplyTake(matchedSymbols, parsedRule.predicates);

        SPDLOG_INFO("Found {} matches", matchedSymbols.size());
        return matchedSymbols;
    }

    bool DslMatcher::MatchFunction(const AnalysisDb& analysisDatabase,
                                   const AnalyzedFunction& candidateFunction,
                                   const std::vector<PredicatePtr>& predicates)
    {
        for (const auto& predicate : predicates)
        {
            if (!predicate)
            {
                continue;
            }
            // Skip `take` — it's handled after matching
            if (predicate->kind == PredKind::Take)
            {
                continue;
            }

            if (!EvalFunctionPred(analysisDatabase, candidateFunction, *predicate))
            {
                return false;
            }
        }
        return true;
    }

    bool DslMatcher::MatchGlobal(const AnalysisDb& analysisDatabase, const Global& candidateGlobal,
                                 const std::vector<PredicatePtr>& predicates)
    {
        SPDLOG_INFO("match_global called for global at 0x{:X}, refs={}", candidateGlobal.rva,
                    candidateGlobal.refs.size());

        for (const auto& predicate : predicates)
        {
            if (!predicate)
            {
                continue;
            }

            if (predicate->kind == PredKind::Take)
            {
                continue;
            }

            if (!EvalGlobalPred(analysisDatabase, candidateGlobal, *predicate))
            {
                return false;
            }
        }
        return true;
    }

    bool DslMatcher::EvalFunctionPred(const AnalysisDb& analysisDatabase,
                                      const AnalyzedFunction& candidateFunction,
                                      const Predicate& predicate)
    {
        switch (predicate.kind)
        {
        case PredKind::Calls:
        {
            // Check if this function calls the named function
            const auto* calleeFunction = analysisDatabase.FunctionByName(predicate.strValue);
            if (!calleeFunction)
            {
                return false;
            }

            return std::find(candidateFunction.callees.begin(), candidateFunction.callees.end(),
                             calleeFunction->rva) != candidateFunction.callees.end();
        }

        case PredKind::CalledBy:
        {
            // Check if this function is called by the named function
            const auto* callerFunction = analysisDatabase.FunctionByName(predicate.strValue);
            if (!callerFunction)
            {
                return false;
            }
            return std::find(candidateFunction.callers.begin(), candidateFunction.callers.end(),
                             callerFunction->rva) != candidateFunction.callers.end();
        }

        case PredKind::CalledByBlock:
        {
            // Check if ANY caller of this function matches all inner predicates
            for (uint64_t callerRva : candidateFunction.callers)
            {
                const auto* callerFunction = analysisDatabase.FunctionAt(callerRva);
                if (!callerFunction)
                {
                    continue;
                }
                bool callerMatchesAllPredicates = true;
                for (const auto& callerPredicate : predicate.children)
                {
                    if (!EvalFunctionPred(analysisDatabase, *callerFunction, *callerPredicate))
                    {
                        callerMatchesAllPredicates = false;
                        break;
                    }
                }
                if (callerMatchesAllPredicates)
                {
                    return true;
                }
            }
            return false;
        }

        case PredKind::Exported:
            return candidateFunction.exported;

        case PredKind::HasLoop:
            return candidateFunction.hasLoop;

        case PredKind::Not:
            return predicate.child
                       ? !EvalFunctionPred(analysisDatabase, candidateFunction, *predicate.child)
                       : true;

        case PredKind::CallsCount:
            return Compare(candidateFunction.callCount, predicate.cmpOp, predicate.intValue);

        case PredKind::Xrefs:
        {
            auto incomingReferences = analysisDatabase.XrefsTo(candidateFunction.rva);
            return Compare(static_cast<int64_t>(incomingReferences.size()), predicate.cmpOp,
                           predicate.intValue);
        }

        case PredKind::StackFrameSize:
            return Compare(candidateFunction.stackFrameSize, predicate.cmpOp, predicate.intValue);

        default:
            SPDLOG_WARN("Unhandled predicate kind {} for function matching",
                        static_cast<int>(predicate.kind));
            return false;
        }
    }

    bool DslMatcher::EvalGlobalPred(const AnalysisDb& analysisDatabase,
                                    const Global& candidateGlobal, const Predicate& predicate)
    {
        switch (predicate.kind)
        {
        case PredKind::ReferencedBy:
        {
            SPDLOG_INFO("ReferencedBy: looking for func '{}'", predicate.strValue);
            const auto* referencingFunction = analysisDatabase.FunctionByName(predicate.strValue);
            if (!referencingFunction)
            {
                SPDLOG_INFO("ReferencedBy: function not found in DB");
                return false;
            }
            SPDLOG_INFO("ReferencedBy: found func at rva 0x{:X}, global has {} refs",
                        referencingFunction->rva, candidateGlobal.refs.size());
            for (const auto& dataReference : candidateGlobal.refs)
            {
                SPDLOG_INFO("  ref: from_func=0x{:X}, target=0x{:X}", dataReference.fromFunc,
                            dataReference.toRva);
                if (dataReference.fromFunc == referencingFunction->rva)
                {
                    return true;
                }
            }
            return false;
        }

        case PredKind::Xrefs:
            return Compare(static_cast<int64_t>(candidateGlobal.refs.size()), predicate.cmpOp,
                           predicate.intValue);

        case PredKind::Not:
            return predicate.child
                       ? !EvalGlobalPred(analysisDatabase, candidateGlobal, *predicate.child)
                       : true;

        default:
            SPDLOG_WARN("Unhandled predicate kind {} for global matching",
                        static_cast<int>(predicate.kind));
            return false;
        }
    }

    void DslMatcher::ApplyTake(std::vector<MatchResult>& matchedSymbols,
                               const std::vector<PredicatePtr>& predicates)
    {
        for (const auto& predicate : predicates)
        {
            if (predicate && predicate->kind == PredKind::Take)
            {
                auto resultLimit = static_cast<size_t>(predicate->intValue);
                if (matchedSymbols.size() > resultLimit)
                {
                    matchedSymbols.resize(resultLimit);
                }
                break;
            }
        }
    }

} // namespace symfind::dsl
