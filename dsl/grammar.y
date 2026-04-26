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

using namespace symfind::dsl;

struct PredRaw     { Predicate* p; };
struct PredListRaw { std::vector<PredicatePtr>* list; };
}

%token_type { Token }

%type predicate         { PredRaw }
%type pred_list         { PredListRaw }
%type cmp_op            { CmpOp }
%type target_kind       { TargetKind }

%token_prefix TK_

%extra_argument { ParserContext* ctx }

%syntax_error {
    ctx->had_error = true;
    ctx->error_line = TOKEN.line;
}

%stack_overflow {
    ctx->had_error = true;
}

/* ─── Grammar ─────────────────────────────────────── */

%start_symbol program

program ::= rule.

rule ::= FIND target_kind(K) IN STRING(M) WHERE pred_list(L). {
    ctx->result.target = K;
    ctx->result.module_name = std::string(M.str_value);
    for (auto& p : *L.list) {
        ctx->result.predicates.push_back(std::move(p));
    }
    delete L.list;
}

target_kind(K) ::= FUNCTION. { K = TargetKind::Function; }
target_kind(K) ::= GLOBAL.   { K = TargetKind::Global; }

/* One or more SEMI-terminated predicates */
pred_list(L) ::= predicate(P) SEMI. {
    L.list = new std::vector<PredicatePtr>();
    L.list->emplace_back(P.p);
}
pred_list(L) ::= pred_list(L2) predicate(P) SEMI. {
    L2.list->emplace_back(P.p);
    L = L2;
}

/* ─── Predicate variants ─────────────────────────── */

predicate(P) ::= CALLS STRING(S). {
    auto* p = new Predicate;
    p->kind = PredKind::Calls;
    p->str_value = std::string(S.str_value);
    P.p = p;
}

predicate(P) ::= CALLED_BY STRING(S). {
    auto* p = new Predicate;
    p->kind = PredKind::CalledBy;
    p->str_value = std::string(S.str_value);
    P.p = p;
}
predicate(P) ::= CALLED_BY LPAREN pred_list(Inner) RPAREN. {
    auto* p = new Predicate;
    p->kind = PredKind::CalledByBlock;
    for (auto& cp : *Inner.list) {
        p->children.push_back(std::move(cp));
    }
    delete Inner.list;
    P.p = p;
}

predicate(P) ::= REFERENCED_BY STRING(S). {
    auto* p = new Predicate;
    p->kind = PredKind::ReferencedBy;
    p->str_value = std::string(S.str_value);
    P.p = p;
}

predicate(P) ::= EXPORTED. {
    auto* p = new Predicate;
    p->kind = PredKind::Exported;
    P.p = p;
}
predicate(P) ::= NOT predicate(Inner). {
    auto* p = new Predicate;
    p->kind = PredKind::Not;
    p->child.reset(Inner.p);
    P.p = p;
}

predicate(P) ::= HAS_LOOP. {
    auto* p = new Predicate;
    p->kind = PredKind::HasLoop;
    P.p = p;
}

predicate(P) ::= TAKE FIRST. {
    auto* p = new Predicate;
    p->kind = PredKind::Take;
    p->int_value = 1;
    P.p = p;
}
predicate(P) ::= TAKE INTEGER(N). {
    auto* p = new Predicate;
    p->kind = PredKind::Take;
    p->int_value = N.int_value;
    P.p = p;
}

predicate(P) ::= CALLS_COUNT cmp_op(Op) INTEGER(N). {
    auto* p = new Predicate;
    p->kind = PredKind::CallsCount;
    p->cmp_op = Op;
    p->int_value = N.int_value;
    P.p = p;
}

predicate(P) ::= XREFS COUNT cmp_op(Op) INTEGER(N). {
    auto* p = new Predicate;
    p->kind = PredKind::Xrefs;
    p->cmp_op = Op;
    p->int_value = N.int_value;
    P.p = p;
}

predicate(P) ::= STACK_FRAME_SIZE cmp_op(Op) INTEGER(N). {
    auto* p = new Predicate;
    p->kind = PredKind::StackFrameSize;
    p->cmp_op = Op;
    p->int_value = N.int_value;
    P.p = p;
}

predicate(P) ::= READS_REG STRING(S). {
    auto* p = new Predicate;
    p->kind = PredKind::ReadsReg;
    p->str_value = std::string(S.str_value);
    P.p = p;
}

/* ─── Comparison operators ───────────────────────── */

cmp_op(O) ::= GTE. { O = CmpOp::Gte; }
cmp_op(O) ::= LTE. { O = CmpOp::Lte; }
cmp_op(O) ::= EQ.  { O = CmpOp::Eq;  }
cmp_op(O) ::= GT.  { O = CmpOp::Gt;  }
cmp_op(O) ::= LT.  { O = CmpOp::Lt;  }
