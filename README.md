# symfind

An embeddable C++20 library for locating unexported symbols (functions and globals) inside PE modules on Windows — **without** loading PDB files, even when they are available.

## Motivation

When building tooling that needs to resolve unexported symbols on a remote target — e.g. a specific internal function inside `ntdll.dll` — common approaches have drawbacks:

- **Hardcoded offsets** break between Windows builds and may miss newer releases entirely.
- **Offset databases** like ntdiff depend on someone else keeping them up to date.
- **PDB symbols** require either an internet connection to the Microsoft symbol server, or shipping PDBs with the product. This is often undesirable or impossible in production deployments.
- **Full-blown reverse engineering frameworks** (IDA, Ghidra, Binary Ninja) cannot be embedded into your own compact product and deployed to arbitrary targets.

`symfind` takes a different approach: it performs lightweight static analysis of the target module and then locates symbols **by describing their algorithmic properties** — which functions they call, who calls them, what globals they reference — using a small declarative DSL.

## High-level design

```
┌─────────────┐    ┌──────────────┐    ┌───────────────┐    ┌──────────┐
│  PE module  │ ─► │  Disassembly │ ─► │  Analysis DB  │ ◄─ │ DSL rule │
│ (ntdll.dll) │    │   (Zydis)    │    │  (functions,  │    │          │
└─────────────┘    └──────────────┘    │   xrefs,      │    └──────────┘
                                       │   globals)    │          │
                                       └───────────────┘          │
                                                ▲                 │
                                                │                 ▼
                                                └─── matcher ─── results
                                                                  │
                                                                  ▼
                                                           RVA of the
                                                           symbol we were
                                                           looking for
```

## DSL — describing what to find

Rather than writing C++ code for every search, symbols are located via small text rules. Example — find `LdrpLoadDll`, which has no unique signature of its own but is the only unexported function called from `LdrLoadDll` that internally calls `RtlGetCurrentServiceSessionId`:

```
find function in "ntdll" where
    called_by "LdrLoadDll"
    not exported
    calls "RtlGetCurrentServiceSessionId"
```

Another example — find the `RtlDecompressBufferProcs` dispatch table (the only global referenced by `RtlDecompressBuffer`):

```
find global in "ntdll" where
    referenced_by "RtlDecompressBuffer"
    take first
```

See [`dsl/examples.sf`](dsl/examples.sf) for more examples.

### Current DSL predicates

| Predicate                 | Meaning                                                  |
|---------------------------|----------------------------------------------------------|
| `calls "X"`               | function calls `X`                                       |
| `called_by "X"`           | function is called by `X`                                |
| `called_by ( ... )`       | function has a caller that matches nested predicates      |
| `referenced_by "X"`       | global is referenced from function `X`                    |
| `exported` / `not exported` | symbol is / isn't exported                               |
| `has_loop`                | function contains a back-edge                             |
| `not <predicate>`         | negation                                                  |
| `calls_count OP N`        | number of `call` instructions inside the function body    |
| `xrefs count OP N`        | number of cross-references to this symbol                 |
| `stack_frame_size OP N`   | size of `sub rsp, N` in prologue                          |
| `take first` / `take N`   | limit the number of results                               |

Comparison operators: `==`, `>`, `<`, `>=`, `<=`. Integer literals can be decimal or `0xHex`. Comments start with `#`.

## Current status

This is **early development**. The DSL layer (lexer + parser + matcher) is implemented and tested against mock data. The analysis layer is stubbed with `TODO`s.

### Implemented

- **DSL lexer** — tokenizes the rule language
- **DSL parser** — produces an AST for all predicates listed above
- **DSL matcher** — walks the AST against an `AnalysisDb` and returns matches
- **PE module loader** — loads modules via LIEF, exposes exports and sections
- **Function discovery via `.pdata`** — parses the exception directory (`RUNTIME_FUNCTION` entries) to get precise function boundaries (start + size) for all functions including unexported ones
- **Zydis disassembler integration** — instruction decoding with branch target and RIP-relative resolution
- Function discovery from call-target scanning (fallback for functions missing from `.pdata`)
- Global variable discovery and cross-reference collection
- RVA-to-file-offset translation in `PeModule::read_at`

### Not yet implemented

- Full analysis pipeline: collecting callees/callers per function, detecting loops, computing `stack_frame_size`
- `PeModule::from_memory` (loading a module from a raw byte buffer)

## Adding a new DSL predicate

A predicate is a single condition in a `find ... where ...` rule, like `calls "X"` or `has_loop`. Adding a new one is the most common form of extending the DSL. This section walks through the full process step by step, explains *why* each file needs to change, and then shows a concrete worked example.

### Theory: where information flows

To understand which files matter, it helps to trace what happens when a rule like `find function in "ntdll" where calls_count >= 3;` is processed.

The input string travels through three stages:

1. **Lexing.** The DSL text is broken into tokens. The keyword `calls_count` becomes a single token of type `TokenType::CallsCount`, the `>=` becomes `TokenType::Gte`, the `3` becomes an integer literal, and the `;` becomes `TokenType::Semi`. This is done by the re2c-generated lexer, which is built from `dsl/lexer.re`.

2. **Parsing.** The sequence of tokens is matched against grammar rules. The rule `predicate ::= CALLS_COUNT cmp_op INTEGER` says: *if you see these three tokens in this order, build a `Predicate` AST node*. The parser is generated by Lemon from `dsl/grammar.y`. The grammar file also contains the C++ code that constructs the AST node.

3. **Matching.** The constructed AST is walked over the analysis database. For each function (or global), the matcher checks every predicate in the AST and returns the symbol if all predicates pass. This is done by hand-written C++ in `src/dsl_matcher.cpp`.

There's also a small **driver** layer in `src/dsl_driver.cpp` that connects the lexer to the parser. It translates between two enumerations of token IDs: the C++ `TokenType` enum (used by the lexer for type safety) and the integer constants `TK_*` (generated by Lemon for the parser).

So when adding a new predicate, you touch every layer the information passes through. The number of files looks intimidating at first, but each change is small and mechanical.

### The seven changes

For any new predicate, you need to update these locations:

1. **`include/symfind/dsl_lexer.h`** — add a new value to the `TokenType` enum.
2. **`dsl/lexer.re`** — add a regex rule that maps the keyword text to the new `TokenType`.
3. **`include/symfind/dsl_parser.h`** — add a new value to the `PredKind` enum so the AST can represent the predicate.
4. **`dsl/grammar.y`** — add a grammar rule that consumes the new tokens and constructs the AST node.
5. **`src/dsl_driver.cpp`** — add a `case` in `token_type_to_id` mapping the new `TokenType` to the new `TK_*` constant.
6. **`src/analysis_db.h`** (or `pe_module.h`) — if the predicate needs new data from analysis, add the relevant field to `AnalyzedFunction` or `Global`.
7. **`src/dsl_matcher.cpp`** — add a `case` in `eval_function_pred` (or `eval_global_pred`) that evaluates the predicate against an `AnalyzedFunction`.

After these changes, run a regular build. CMake re-runs Lemon and re2c automatically because the input files have changed.

### Worked example: adding `is_leaf`

Suppose we want to add a predicate that matches functions which contain no `call` instructions — leaf functions in call-graph terminology. The DSL syntax we want is:

```
find function in "ntdll" where
    is_leaf;
    not exported;
```

#### 1. Add a `TokenType`

In `include/symfind/dsl_lexer.h`:

```cpp
enum class TokenType {
    // ... existing entries ...
    HasLoop,
    IsLeaf,            // ← NEW
    Take,
    // ... rest ...
};
```

The position in the enum doesn't matter, but grouping it near other property predicates keeps things readable.

#### 2. Recognize the keyword in the lexer

In `dsl/lexer.re`, in the keyword section:

```
"has_loop"  { goto kw_has_loop; }
"is_leaf"   { goto kw_is_leaf; }      // ← NEW
"take"      { goto kw_take; }
```

And add a finalization label at the bottom, next to the others:

```cpp
kw_has_loop:  EMIT_KW(HasLoop);
kw_is_leaf:   EMIT_KW(IsLeaf);        // ← NEW
kw_take:      EMIT_KW(Take);
```

The `EMIT_KW` macro updates the lexer's position state and returns a token with the right `TokenType`. We use a goto here instead of inlining the code into each regex action because re2c rule actions are awkward for non-trivial C++ logic.

#### 3. Add a `PredKind`

In `include/symfind/dsl_parser.h`:

```cpp
enum class PredKind {
    // ... existing entries ...
    HasLoop,
    IsLeaf,            // ← NEW
    Not,
    // ... rest ...
};
```

#### 4. Add a grammar rule

In `dsl/grammar.y`, in the predicate variants section:

```
predicate(P) ::= HAS_LOOP. {
    auto* p = new Predicate;
    p->kind = PredKind::HasLoop;
    P.p = p;
}

predicate(P) ::= IS_LEAF. {           // ← NEW
    auto* p = new Predicate;
    p->kind = PredKind::IsLeaf;
    P.p = p;
}
```

The token names use `IS_LEAF` (the `TK_` prefix is added automatically because of `%token_prefix TK_` at the top of the file). This is a flag-style predicate with no operands, so the rule consumes a single token and emits an AST node with no extra data.

#### 5. Map the token in the driver

In `src/dsl_driver.cpp`, inside `token_type_to_id`:

```cpp
case TokenType::HasLoop:        return TK_HAS_LOOP;
case TokenType::IsLeaf:         return TK_IS_LEAF;     // ← NEW
case TokenType::Not:            return TK_NOT;
```

This is the bridge between the C++ side (which uses the typed enum) and the parser side (which uses raw integer token IDs generated by Lemon).

#### 6. Make sure the data is available

For `is_leaf` we need to know whether a function makes any calls. The `AnalyzedFunction` struct in `include/symfind/analysis_db.h` already has a `call_count` field, so no new data is needed. If we were adding a predicate that requires new information — like `argument_count` — we'd add a field here and populate it in the analysis pass.

#### 7. Implement the matcher

In `src/dsl_matcher.cpp`, inside `eval_function_pred`:

```cpp
case PredKind::HasLoop:
    return func.has_loop;

case PredKind::IsLeaf:                     // ← NEW
    return func.call_count == 0;

case PredKind::Not:
    return pred.child ? !eval_function_pred(db, func, *pred.child) : true;
```

#### 8. Build and test

```
cmake --build --preset debug
ctest --preset debug
```

CMake notices that `dsl/grammar.y` and `dsl/lexer.re` have changed and re-runs Lemon and re2c before compiling. If the grammar has conflicts, Lemon will report them and leave a `grammar.out` file in the build directory with full state-machine details.

#### 9. Add a unit test

In `tests/test_dsl_matcher.cpp`:

```cpp
TEST(DslMatcher, IsLeaf) {
    auto db = MockAnalysisDb::build_ntdll_mock();
    auto rule = DslParser::parse(R"(
        find function in "ntdll" where
            is_leaf;
    )");
    ASSERT_TRUE(rule.has_value());
    auto results = DslMatcher::match(db, *rule);
    // Expectations depend on the mock — add functions with
    // call_count = 0 to verify the matching works as intended.
}
```

### Predicates with operands

The `is_leaf` example is the simplest case — a flag predicate with no arguments. More complex shapes require the same set of changes, but the grammar rule and the matcher case are richer. Existing examples in the codebase to learn from:

- **String operand:** `calls "X"` — see the `Calls` token, `predicate ::= CALLS STRING(S)` rule, and the `PredKind::Calls` case in the matcher.
- **Numeric comparison:** `calls_count >= 3` — see the `CallsCount` token, the rule `predicate ::= CALLS_COUNT cmp_op(Op) INTEGER(N)`, and how the matcher applies the comparison via the `compare()` helper.
- **Nested block:** `called_by ( ... )` — see how a list of inner predicates is parsed via `pred_list` recursion and stored in the `children` field of the AST node.

For each new predicate, the cleanest approach is to copy the closest existing example and adapt it. The patterns are consistent, and once you've added two or three predicates the workflow becomes mechanical.

### Common mistakes

A few things that have bitten us in the past, worth watching out for:

**Forgetting the semicolon in test rules.** Every predicate in a DSL rule, including those inside `called_by ( ... )` blocks, must end with `;`. The grammar requires it as a terminator.

**Adding a `TokenType` but forgetting the `token_type_to_id` mapping.** The lexer will produce the new token, but the driver won't translate it for Lemon. Result: the parser sees an unexpected token and errors out. Always verify that step 5 is done.

**Returning a token ID for a `TK_*` constant that Lemon hasn't generated.** Lemon only generates `TK_*` constants for tokens *actually used in the grammar*. If you add `TokenType::Foo` and map it to `TK_FOO` in the driver, but never reference `FOO` in any grammar rule, the build fails because `TK_FOO` is undefined. Either use the token in the grammar or omit it from the mapping.

**Grammar conflicts after adding ambiguous rules.** Lemon will warn at code-generation time. Read the `grammar.out` report — it shows which states have conflicting actions and why. Resolve by adding more context to the rule (e.g. a terminator) or removing redundancy.

## Prerequisites
 
### General
 
- CMake 3.20 or newer
- C++20-capable compiler (MSVC 2022, clang 15+, gcc 11+)
All C++ library dependencies (Zydis, LIEF, spdlog, GoogleTest) are fetched automatically via `FetchContent` — no manual installation needed.
 
### Code generation tools (Windows)
 
The DSL lexer is generated from a grammar file at build time using **re2c**, and the parser is generated from a Lemon grammar. These tools are **build-time only** — nothing from them ends up in the final binary.
 
#### 1. Install Chocolatey (if not already installed)
 
Chocolatey is a package manager for Windows that simplifies installing command-line tools. Open PowerShell **as Administrator** and run:
 
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
```
 
After installation, close and reopen PowerShell, then verify:
 
```powershell
choco --version
```
 
#### 2. Install re2c
 
In an elevated PowerShell:
 
```powershell
choco install re2c -y
```
 
Verify:
 
```powershell
re2c --version
```
 
Expected output: `re2c 3.0` (or newer).
 
#### 3. Lemon parser generator
 
Lemon is **not distributed via Chocolatey** — it's a single C file maintained as part of SQLite. 
It lives in the repository under `tools/lemon/` and is compiled automatically by CMake the first 
time the project is built. No manual installation required.

## Building

Requires CMake 3.20+ and a C++20 compiler. All dependencies are fetched automatically via `FetchContent`.

```
cmake --preset debug
cmake --build --preset debug
ctest --preset debug
```

Presets available:

- `debug` — full build with tests and examples
- `release` — optimized build with examples
- `release-min` — library only, optimized for minimal size

## Dependencies

| Library     | Purpose                          | Version  |
|-------------|----------------------------------|----------|
| Zydis       | x86/x64 disassembly              | 4.1.0    |
| LIEF        | PE parsing (only PE enabled)     | 0.17.6   |
| spdlog      | logging                          | 1.15.0   |
| GoogleTest  | tests (optional)                 | 1.15.2   |

LIEF is configured to build **only** the PE backend (ELF, Mach-O, DEX, OAT, ART are disabled) to keep the library lean.

## Target platforms

Primary focus is Windows x64 PE modules. The core architecture (PE loader, Zydis, DSL) is portable, but the current analysis code assumes x64 calling conventions and Windows-specific structures like the `.pdata` exception directory.

## License

TBD.