/*
 * symfind DSL — Lemon grammar (with semicolon terminators)
 *
 * Generated output:
 *   grammar.c   — parser implementation
 *   grammar.h   — token type constants (TK_xxx)
 *   grammar.out — LALR state machine report (kept for debugging)
 */

%name SymfindParse

%include {
#include "symfind/dsl_parser.h"
#include <cassert>
#include <cstdlib>
#include <utility>

struct PredRaw
{
        symfind::dsl::Predicate* predicate;
};
struct PredListRaw
{
        std::vector<symfind::dsl::PredicatePtr>* predicates;
};
}

%token_type { symfind::dsl::Token }

%type predicate         { PredRaw }
%type pred_list         { PredListRaw }
%type cmp_op            { symfind::dsl::CmpOp }
%type target_kind       { symfind::dsl::TargetKind }

%token_prefix TK_

%extra_argument { symfind::dsl::ParserContext* parserContext }

%syntax_error
{
    parserContext->hadError = true;
    parserContext->errorLine = TOKEN.line;
}

%stack_overflow
{
    parserContext->hadError = true;
}

/* ─── Grammar ─────────────────────────────────────── */

%start_symbol program

program ::= rule.

rule ::= FIND target_kind(targetKindValue) IN STRING(moduleNameToken) WHERE
    pred_list(predicateListNode).
{
    parserContext->result.target = targetKindValue;
    parserContext->result.moduleName = std::string(moduleNameToken.strValue);
    for (auto& predicate : *predicateListNode.predicates)
    {
        parserContext->result.predicates.push_back(std::move(predicate));
    }
    delete predicateListNode.predicates;
}

target_kind(targetKindValue) ::= FUNCTION.
{
    targetKindValue = symfind::dsl::TargetKind::Function;
}
target_kind(targetKindValue) ::= GLOBAL.
{
    targetKindValue = symfind::dsl::TargetKind::Global;
}

/* One or more SEMI-terminated predicates */
pred_list(predicateListNode) ::= predicate(predicateNode) SEMI.
{
    predicateListNode.predicates = new std::vector<symfind::dsl::PredicatePtr>();
    predicateListNode.predicates->emplace_back(predicateNode.predicate);
}
pred_list(predicateListNode) ::= pred_list(previousPredicateList) predicate(predicateNode) SEMI.
{
    previousPredicateList.predicates->emplace_back(predicateNode.predicate);
    predicateListNode = previousPredicateList;
}

/* ─── Predicate variants ─────────────────────────── */

predicate(predicateNode) ::= CALLS STRING(symbolNameToken).
{
    auto* predicate = new symfind::dsl::Predicate;
    predicate->kind = symfind::dsl::PredKind::Calls;
    predicate->strValue = std::string(symbolNameToken.strValue);
    predicateNode.predicate = predicate;
}

predicate(predicateNode) ::= CALLED_BY STRING(symbolNameToken).
{
    auto* predicate = new symfind::dsl::Predicate;
    predicate->kind = symfind::dsl::PredKind::CalledBy;
    predicate->strValue = std::string(symbolNameToken.strValue);
    predicateNode.predicate = predicate;
}
predicate(predicateNode) ::= CALLED_BY LPAREN pred_list(innerNode) RPAREN.
{
    auto* predicate = new symfind::dsl::Predicate;
    predicate->kind = symfind::dsl::PredKind::CalledByBlock;
    for (auto& childPredicate : *innerNode.predicates)
    {
        predicate->children.push_back(std::move(childPredicate));
    }
    delete innerNode.predicates;
    predicateNode.predicate = predicate;
}

predicate(predicateNode) ::= REFERENCED_BY STRING(symbolNameToken).
{
    auto* predicate = new symfind::dsl::Predicate;
    predicate->kind = symfind::dsl::PredKind::ReferencedBy;
    predicate->strValue = std::string(symbolNameToken.strValue);
    predicateNode.predicate = predicate;
}

predicate(predicateNode) ::= EXPORTED.
{
    auto* predicate = new symfind::dsl::Predicate;
    predicate->kind = symfind::dsl::PredKind::Exported;
    predicateNode.predicate = predicate;
}
predicate(predicateNode) ::= NOT predicate(innerNode).
{
    auto* predicate = new symfind::dsl::Predicate;
    predicate->kind = symfind::dsl::PredKind::Not;
    predicate->child.reset(innerNode.predicate);
    predicateNode.predicate = predicate;
}

predicate(predicateNode) ::= HAS_LOOP.
{
    auto* predicate = new symfind::dsl::Predicate;
    predicate->kind = symfind::dsl::PredKind::HasLoop;
    predicateNode.predicate = predicate;
}

predicate(predicateNode) ::= TAKE FIRST.
{
    auto* predicate = new symfind::dsl::Predicate;
    predicate->kind = symfind::dsl::PredKind::Take;
    predicate->intValue = 1;
    predicateNode.predicate = predicate;
}
predicate(predicateNode) ::= TAKE INTEGER(integerToken).
{
    auto* predicate = new symfind::dsl::Predicate;
    predicate->kind = symfind::dsl::PredKind::Take;
    predicate->intValue = integerToken.intValue;
    predicateNode.predicate = predicate;
}

predicate(predicateNode) ::= CALLS_COUNT cmp_op(comparisonOperator) INTEGER(integerToken).
{
    auto* predicate = new symfind::dsl::Predicate;
    predicate->kind = symfind::dsl::PredKind::CallsCount;
    predicate->cmpOp = comparisonOperator;
    predicate->intValue = integerToken.intValue;
    predicateNode.predicate = predicate;
}

predicate(predicateNode) ::= XREFS COUNT cmp_op(comparisonOperator) INTEGER(integerToken).
{
    auto* predicate = new symfind::dsl::Predicate;
    predicate->kind = symfind::dsl::PredKind::Xrefs;
    predicate->cmpOp = comparisonOperator;
    predicate->intValue = integerToken.intValue;
    predicateNode.predicate = predicate;
}

predicate(predicateNode) ::= STACK_FRAME_SIZE cmp_op(comparisonOperator) INTEGER(integerToken).
{
    auto* predicate = new symfind::dsl::Predicate;
    predicate->kind = symfind::dsl::PredKind::StackFrameSize;
    predicate->cmpOp = comparisonOperator;
    predicate->intValue = integerToken.intValue;
    predicateNode.predicate = predicate;
}

predicate(predicateNode) ::= READS_REG STRING(symbolNameToken).
{
    auto* predicate = new symfind::dsl::Predicate;
    predicate->kind = symfind::dsl::PredKind::ReadsReg;
    predicate->strValue = std::string(symbolNameToken.strValue);
    predicateNode.predicate = predicate;
}

/* ─── Comparison operators ───────────────────────── */

cmp_op(comparisonOperator) ::= GTE.
{
    comparisonOperator = symfind::dsl::CmpOp::Gte;
}
cmp_op(comparisonOperator) ::= LTE.
{
    comparisonOperator = symfind::dsl::CmpOp::Lte;
}
cmp_op(comparisonOperator) ::= EQ.
{
    comparisonOperator = symfind::dsl::CmpOp::Eq;
}
cmp_op(comparisonOperator) ::= GT.
{
    comparisonOperator = symfind::dsl::CmpOp::Gt;
}
cmp_op(comparisonOperator) ::= LT.
{
    comparisonOperator = symfind::dsl::CmpOp::Lt;
}
