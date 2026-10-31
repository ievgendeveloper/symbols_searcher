#pragma once

/// @file symfind.h
/// @brief Public API for the symfind library.
///
/// Usage (ruleSource contains a DSL rule):
///   auto peModule = symfind::PeModule::FromFile("ntdll.dll");
///   auto parsedRule = symfind::dsl::DslParser::Parse(ruleSource);
///   if (peModule && parsedRule)
///   {
///       auto analysisDatabase = symfind::AnalysisDb::Analyze(*peModule);
///       auto matchedSymbols = symfind::dsl::DslMatcher::Match(analysisDatabase, *parsedRule);
///   }

#include "symfind/analysis_db.h"
#include "symfind/disassembler.h"
#include "symfind/dsl_lexer.h"
#include "symfind/dsl_matcher.h"
#include "symfind/dsl_parser.h"
#include "symfind/function_finder.h"
#include "symfind/pe_module.h"
