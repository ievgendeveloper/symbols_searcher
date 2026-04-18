#pragma once

/// @file symfind.h
/// @brief Public API for the symfind library.
///
/// Usage:
///   1. Load a PE module:       PeModule mod("ntdll.dll");
///   2. Run analysis:           AnalysisDb db = analyze(mod);
///   3. Parse a DSL rule:       auto rule = DslParser::parse(script);
///   4. Match:                  auto results = DslMatcher::match(db, rule);

#include "symfind/pe_module.h"
#include "symfind/disassembler.h"
#include "symfind/function_finder.h"
#include "symfind/analysis_db.h"
#include "symfind/dsl_lexer.h"
#include "symfind/dsl_parser.h"
#include "symfind/dsl_matcher.h"
