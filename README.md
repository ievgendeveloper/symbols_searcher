# symfind

An embeddable C++17 library for locating unexported symbols (functions and globals) inside PE modules on Windows — **without** loading PDB files, even when they are available.

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

Symbols are located via small text rules. This rule identifies a non-exported
callee of `LdrLoadDll` with 128–512 bytes of stack allocation and at least four
direct call instructions. These properties separate `LdrpLoadDll` from logging and path
helpers in the pinned x64 corpus; PDB validation checks the unique resulting RVA.

```
find function in "ntdll" where
    called_by "LdrLoadDll";
    not exported;
    stack_frame_size >= 0x80;
    stack_frame_size <= 0x200;
    calls_count >= 4;
```

Another example selects the first global referenced by `RtlDecompressBuffer`
as the candidate for `RtlDecompressBufferProcs`. Some DLL versions have multiple
matching globals; the PDB comparison records this ambiguity.

```
find global in "ntdll" where
    referenced_by "RtlDecompressBuffer";
    take first;
```

See [`dsl/examples.sf`](dsl/examples.sf) for more examples.

The module in `in "ntdll"` is checked before matching functions or globals.
Module basenames compare without ASCII case sensitivity; a bare name can omit
`.dll`, so `ntdll`, `NTDLL.DLL`, and a path ending in `ntdll.dll` identify the same
module. Explicit `.exe` and `.sys` extensions remain distinct. File and memory
loaders use the DLL name recorded in the PE export directory; files without it
fall back to their filename. A memory image without a module name cannot match
a named rule. Exported symbol names remain case-sensitive.

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
| `calls_count OP N`        | number of resolved direct `call` instructions in owned ranges |
| `xrefs count OP N`        | number of cross-references to this symbol                 |
| `stack_frame_size OP N`   | size of `sub rsp, N` in prologue                          |
| `take first` / `take N`   | limit the number of results                               |

Comparison operators: `==`, `>`, `<`, `>=`, `<=`. Integer literals can be decimal or `0xHex`. Comments start with `#`.

## Current status

This is **early development**. The DSL and PE analysis layers are implemented
and covered by unit tests and integration tests against the host's x64
`ntdll.dll`. Cross-version PDB validation is described below; finding a
candidate alone does not establish that it is the intended symbol.

### Implemented

- **DSL lexer** — tokenizes the rule language
- **DSL parser** — produces an AST for all predicates listed above
- **DSL matcher** — walks the AST against an `AnalysisDb` and returns matches
- **PE module loader** — loads modules via LIEF, exposes exports and sections
- **Function discovery via `.pdata`** — parses the exception directory (`RUNTIME_FUNCTION` entries) to get precise function boundaries (start + size) for all functions including unexported ones
- **Zydis disassembler integration** — instruction decoding with branch target and RIP-relative resolution
- Function discovery from call-target scanning (fallback for functions missing from `.pdata`)
- Grouping function fragments with verified chained x64 unwind records, including calls and data references in continuations
- Global variable discovery and cross-reference collection
- RVA-to-file-offset translation in `symfind::PeModule::ReadAt`

## Checking results against PDB symbols

The symbol-specific tests cover `LdrpInitialize`, `LdrpLoadDll`, and
`RtlDecompressBufferProcs`. The existing real-module tests use
`C:\Windows\System32\ntdll.dll`; `LdrpLoadDll` previously had only mock coverage.

Windows test builds also provide `symfind_compare_symbols`. It runs the same
DSL rules and resolves each expected name independently from an explicit local
PDB using Windows DbgHelp. DLL/PDB GUID and DBI age must match; the PDB Info
stream age may be higher after publishing, following Microsoft's
[PDB validation rules](https://github.com/microsoft/microsoft-pdb/blob/master/PDB/dbi/pdb.cpp).
Export-only fallback is rejected. Comparison uses RVAs, so the image base and
ASLR do not affect it.
The CSV includes selected results and all candidates before `take first`, with
an ambiguity flag; a wrong first candidate is a mismatch.

Build the native tools in an MSVC development shell (or use `build.ps1`), then
fetch a matched pair for the host DLL:

```powershell
cmake --preset debug
cmake --build --preset debug --config Debug
.\build\debug\bin\Debug\symfind_fetch_ntdll.exe --dll C:\Windows\System32\ntdll.dll --label local --allow-network
.\build\debug\bin\Debug\symfind_compare_symbols.exe --corpus pdb_stuff\corpus --csv pdb_stuff\reports\pdb-comparison.csv
```

To prepare the pinned version corpus explicitly, use:

```powershell
.\build\debug\bin\Debug\symfind_corpus_manager.exe --ensure --allow-network
```

Downloaded DLLs/PDBs and per-file metadata stay under ignored
`pdb_stuff/corpus`. DLL bytes come from Microsoft's symbol server or pinned
Microsoft Container Registry layers; matching PDBs come from the symbol server.
Winbindex supplies client version metadata. Fixture metadata records SHA256,
PE/RSDS identity, URLs, and OS provenance. Shared client and server build numbers
are not proof of server coverage.

The pinned corpus contains these representative x64 files:

| OS family | DLL file version | Sample source |
|---|---|---|
| Windows 7 SP1 | `6.1.7601.17514` | Microsoft Symbol Server; WinDbg identity report |
| Windows 10 | `10.0.19041.207` | Microsoft Symbol Server; exact Winbindex hash |
| Windows 11 Pro | `10.0.26100.9444` | Verified host System32; identical Microsoft download |
| Windows Server 2016 | `10.0.14393.5980` | Microsoft KB5027386 SafeOS package |
| Windows Server 2019 | `10.0.17763.9245` | Official Nano Server container System32 |
| Windows Server 2022 | `10.0.20348.5622` | Official Nano Server container System32 |

Server 2016 covers the recovery environment described in
[KB5027386](https://support.microsoft.com/en-us/servicing/os/windows-server/2023/06/kb5027386-compatibility-update-for-installing-and-recovering-windows-server-2016-june-13-2023).
Server 2019/2022 cover Microsoft's
[Nano Server base images](https://learn.microsoft.com/en-us/virtualization/windowscontainers/manage-containers/container-base-images).
They do not establish coverage of installed Desktop Experience DLLs, every
update, or x86. Import additional matched DLL/PDB pairs to extend coverage:

```powershell
.\build\debug\bin\Debug\symfind_fetch_ntdll.exe --dll D:\samples\ntdll.dll --pdb D:\samples\ntdll.pdb --label server-2022-desktop --os "Windows Server 2022 Desktop Experience x64"
```

The additional `windows-11-22h2-symbol-store` entry is `10.0.22621.675`. Its
initial Winbindex lookup resolved to another full-file hash/version on the
symbol server; it is kept as a comparison sample with unverified installed-OS
provenance. Full-file pins stay strict. The local host import duplicates the
primary Windows 11 file and remains available as `local`.

Nano Server archives are cached under `pdb_stuff/archives`; the first full
download adds about 216 MiB of archives. Use repeated `--label` options to select
only the desired fixtures. A cached corpus is verified offline without
`--allow-network`. DLLs are parsed as data, never loaded or executed.

On the sampled files, all three selected RVAs match PDB. The decompression rule
has multiple candidates on several versions; this ambiguity remains visible in
the report. The `LdrpLoadDll` rule produces one candidate without `take first`
and does not depend on `RtlGetCurrentServiceSessionId`, which is absent on Windows 7.
The analyzer attributes calls from verified chained unwind fragments to their
primary procedure, so split `LdrLoadDll` bodies on Windows 11 retain their caller
relationship. It analyzes each owned range separately, excluding gaps and
neighboring functions. These rules are heuristics validated against the listed
samples. Missing files, missing PDB symbols, and differing RVAs are reported
explicitly; they are not converted into skips or accepted as successful comparisons.

CTest automatically prepares the pinned corpus before the PDB integration test.
A complete valid corpus is checked locally without downloads or changes to its
files or metadata. Only absent DLL/PDB files are downloaded. Downloads are staged
separately, and all required pairs must validate before missing files are
published. Existing files, including additional local imports, are never replaced.
Invalid cached files fail validation instead of being silently refreshed.

For an offline run, disable automatic downloading; a missing corpus then fails
with an explicit error:

```powershell
cmake --preset debug -DSYMFIND_AUTO_FETCH_NTDLL=OFF
ctest --preset debug -C Debug --output-on-failure
```

Automatic downloading defaults to `ON`. Selecting unrelated unit tests with
CTest does not trigger corpus preparation. Set `SYMFIND_NTDLL_CORPUS` to test an
existing custom corpus, or `SYMFIND_NTDLL_DLL` and `SYMFIND_NTDLL_PDB` to test a
specific pair; these overrides bypass preparation of the default corpus. The
default corpus path can also be configured with `SYMFIND_NTDLL_CORPUS_DIR`.
CTest always configures the integration test; running the GoogleTest executable
directly without any corpus configuration still skips it. Validation errors,
missing PDB symbols, and differing RVAs fail configured tests. The comparison
CLI also returns a nonzero exit code for unsuccessful comparisons.
PDB handling is confined to validation tools and tests; `symfind` itself keeps
its original PDB-free API.

An independent network test verifies that every pinned DLL/PDB pair can still be
obtained from its remote source, even when the working corpus is complete:

```powershell
cmake --preset debug -DSYMFIND_ENABLE_NETWORK_TESTS=ON
cmake --build --preset debug --target symfind_tests symfind_corpus_manager
ctest --preset network
```

For a Release network check, configure with the same
`-DSYMFIND_ENABLE_NETWORK_TESTS=ON` option, build the `release` preset, then run:

```powershell
ctest --test-dir build/release -C Release -L "^network$" --output-on-failure --no-tests=error
```

Every run starts empty under `pdb_stuff/reproducibility-check/`, with separate
archive and corpus directories. It never reads the working corpus or archive
cache as a fallback and never updates pins. SHA256, PE/RSDS, and PDB identity
checks expose missing or changed remote data. Failed runs retain reports and
downloads for diagnosis, while the working corpus remains untouched. This is a
separate CI job; ordinary `debug` and `release` test presets exclude the `network`
label. If network tests were not enabled at configuration, the `network` preset
fails explicitly instead of reporting success with no tests.

The `build/` directory contains generated build files and binaries only. It can
be absent before configuration or removed without losing fixture data. Persistent
PDB material lives in `pdb_stuff/`: checked-in C++ sources and the pinned manifest,
plus ignored `corpus/`, `archives/`, `metadata/`, `reports/`, `diagnostics/`, and
`backups/`. These downloads persist across builds and test runs; ignoring binary
payloads does not remove the cache. The C++ preparation code and pinned manifest
remain versioned. Temporary preparation data uses `pdb_stuff/tmp/`.

`symfind_fetch_ntdll` and its offline GoogleTest checks are C++17. HTTP uses CPR
with Windows Schannel; gzip/tar reading uses zlib. No Python interpreter is needed.
All utility dependencies are pinned through CMake `FetchContent`. Set
`SYMFIND_BUILD_PDB_TOOLS=OFF` to omit standalone import/comparison tools; tests
still build `symfind_corpus_manager`. Disable tests as well to build the
production library without the fixture dependencies.

`symfind_pdb_util` replaces the one-time Python diagnostics and pinning scripts.
It can inspect PE/RSDS identities, PDB Info/DBI identities, and Windows Update PA30
delta headers. Applying a delta requires the expected output SHA256:

```powershell
.\build\debug\bin\Debug\symfind_pdb_util.exe --pe pdb_stuff\corpus\windows-7\ntdll.dll
.\build\debug\bin\Debug\symfind_pdb_util.exe --pdb pdb_stuff\corpus\windows-7\ntdll.pdb
.\build\debug\bin\Debug\symfind_pdb_util.exe --inspect-delta D:\samples\ntdll.delta --winbindex-metadata pdb_stuff\metadata\ntdll.dll.json.gz
.\build\debug\bin\Debug\symfind_pdb_util.exe --apply-delta D:\samples\ntdll.delta --source D:\samples\base.dll --out D:\samples\ntdll.dll --sha256 EXPECTED_SHA256
```

Winbindex client pins can be refreshed explicitly with `--refresh-winbindex`, or
offline with `--winbindex-metadata FILE`. The result remains subject to strict
full-file hashes; a symbol-store lookup returning other bytes is rejected.

## Naming conventions

C++ variables, parameters, data members and namespaces use `camelCase`. Private
data members use `m_camelCase`. Functions and methods use `PascalCase`,
as do types and enum values. For example, `AnalysisDb::Analyze` returns an
`analysisDatabase`, while its private module-name field is `m_moduleName`.

Names fixed by external contracts keep their required spelling: `main`, C++
operators, third-party APIs, Windows SDK fields, GoogleTest overrides and
generator-defined names such as `YYCURSOR` and `TK_*`. Macros remain uppercase.
DSL keywords, JSON keys, command-line options and file paths retain their existing
syntax; the C++ naming rules do not change these formats.

Function and lambda bodies always span multiple lines. Bodies of `if`, `else`,
`for`, `while` and `do` statements always use braces, even for one statement.
The [`.clang-format`](.clang-format) configuration applies these rules and keeps
lines within 100 columns.

The [`.clang-tidy`](.clang-tidy) configuration checks naming and required braces. With
Ninja, generate a compilation database and run the check from an MSVC development
shell after building:

```powershell
cmake --preset release -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build --preset release
clang-tidy -p build/release src/analysis_db.cpp
```

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
5. **`src/dsl_driver.cpp`** — add a `case` in `TokenTypeToId` mapping the new `TokenType` to the new `TK_*` constant.
6. **`include/symfind/analysis_db.h`** (or `pe_module.h`) — if the predicate needs new data from analysis, add the relevant field to `AnalyzedFunction` or `Global`.
7. **`src/dsl_matcher.cpp`** — add a `case` in `EvalFunctionPred` (or `EvalGlobalPred`) that evaluates the predicate against an `AnalyzedFunction`.

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
enum class TokenType
{
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
"has_loop"  { goto kwHasLoop; }
"is_leaf"   { goto kwIsLeaf; }      // ← NEW
"take"      { goto kwTake; }
```

And add a finalization label at the bottom, next to the others:

```cpp
kwHasLoop:  EMIT_KW(HasLoop);
kwIsLeaf:   EMIT_KW(IsLeaf);        // ← NEW
kwTake:     EMIT_KW(Take);
```

The `EMIT_KW` macro updates the lexer's position state and returns a token with the right `TokenType`. We use a goto here instead of inlining the code into each regex action because re2c rule actions are awkward for non-trivial C++ logic.

#### 3. Add a `PredKind`

In `include/symfind/dsl_parser.h`:

```cpp
enum class PredKind
{
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
predicate(predicateNode) ::= HAS_LOOP. {
    auto* predicate = new symfind::dsl::Predicate;
    predicate->kind = symfind::dsl::PredKind::HasLoop;
    predicateNode.predicate = predicate;
}

predicate(predicateNode) ::= IS_LEAF. {           // ← NEW
    auto* predicate = new symfind::dsl::Predicate;
    predicate->kind = symfind::dsl::PredKind::IsLeaf;
    predicateNode.predicate = predicate;
}
```

The token names use `IS_LEAF` (the `TK_` prefix is added automatically because of `%token_prefix TK_` at the top of the file). This is a flag-style predicate with no operands, so the rule consumes a single token and emits an AST node with no extra data.

#### 5. Map the token in the driver

In `src/dsl_driver.cpp`, inside `TokenTypeToId`:

```cpp
case symfind::dsl::TokenType::HasLoop:
    return TK_HAS_LOOP;
case symfind::dsl::TokenType::IsLeaf:
    return TK_IS_LEAF;     // ← NEW
case symfind::dsl::TokenType::Not:
    return TK_NOT;
```

This is the bridge between the C++ side (which uses the typed enum) and the parser side (which uses raw integer token IDs generated by Lemon).

#### 6. Make sure the data is available

For `is_leaf` we need to know whether a function makes any calls. The `AnalyzedFunction` struct in `include/symfind/analysis_db.h` already has a `callCount` field, so no new data is needed. If we were adding a predicate that requires new information — like `argumentCount` — we'd add a field here and populate it in the analysis pass.

#### 7. Implement the matcher

In `src/dsl_matcher.cpp`, inside `EvalFunctionPred`:

```cpp
case symfind::dsl::PredKind::HasLoop:
    return candidateFunction.hasLoop;

case symfind::dsl::PredKind::IsLeaf:                     // ← NEW
    return candidateFunction.callCount == 0;

case symfind::dsl::PredKind::Not:
    return predicate.child ? !EvalFunctionPred(analysisDatabase, candidateFunction, *predicate.child) : true;
```

#### 8. Build and test

Run the helper script from the project directory. It configures the MSVC
environment, builds the project, and runs the tests (`debug` by default):

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\build.ps1
```

Use `-Preset release` for a release build or `-NoTest` to skip tests.
See the [Building](#building) section for the available presets.

CMake notices that `dsl/grammar.y` and `dsl/lexer.re` have changed and re-runs Lemon and re2c before compiling. If the grammar has conflicts, Lemon will report them and leave a `grammar.out` file in the build directory with full state-machine details.

#### 9. Add a unit test

In `tests/test_dsl_matcher.cpp`:

```cpp
TEST(DslMatcher, IsLeaf)
{
    auto analysisDatabase = MockAnalysisDb::BuildNtdllMock();
    auto parsedRule = symfind::dsl::DslParser::Parse(R"(
        find function in "ntdll" where
            is_leaf;
    )");
    ASSERT_TRUE(parsedRule.has_value());
    auto matchedSymbols = symfind::dsl::DslMatcher::Match(analysisDatabase, *parsedRule);
    // Expectations depend on the mock — add functions with
    // callCount = 0 to verify the matching works as intended.
}
```

### Predicates with operands

The `is_leaf` example is the simplest case — a flag predicate with no arguments. More complex shapes require the same set of changes, but the grammar rule and the matcher case are richer. Existing examples in the codebase to learn from:

- **String operand:** `calls "X"` — see the `Calls` token, `predicate ::= CALLS STRING(symbolNameToken)` rule, and the `PredKind::Calls` case in the matcher.
- **Numeric comparison:** `calls_count >= 3` — see the `CallsCount` token, the rule `predicate ::= CALLS_COUNT cmp_op(comparisonOperator) INTEGER(integerToken)`, and how the matcher applies the comparison via the `Compare()` helper.
- **Nested block:** `called_by ( ... )` — see how a list of inner predicates is parsed via `pred_list` recursion and stored in the `children` field of the AST node.

For each new predicate, the cleanest approach is to copy the closest existing example and adapt it. The patterns are consistent, and once you've added two or three predicates the workflow becomes mechanical.

### Common mistakes

A few things that have bitten us in the past, worth watching out for:

**Forgetting the semicolon in test rules.** Every predicate in a DSL rule, including those inside `called_by ( ... )` blocks, must end with `;`. The grammar requires it as a terminator.

**Adding a `TokenType` but forgetting the `TokenTypeToId` mapping.** The lexer will produce the new token, but the driver won't translate it for Lemon. Result: the parser sees an unexpected token and errors out. Always verify that step 5 is done.

**Returning a token ID for a `TK_*` constant that Lemon hasn't generated.** Lemon only generates `TK_*` constants for tokens *actually used in the grammar*. If you add `TokenType::Foo` and map it to `TK_FOO` in the driver, but never reference `FOO` in any grammar rule, the build fails because `TK_FOO` is undefined. Either use the token in the grammar or omit it from the mapping.

**Grammar conflicts after adding ambiguous rules.** Lemon will warn at code-generation time. Read the `grammar.out` report — it shows which states have conflicting actions and why. Resolve by adding more context to the rule (e.g. a terminator) or removing redundancy.

## Prerequisites
 
### General
 
- CMake 3.25 or newer (LIEF requires at least 3.24; preset schema 6 requires 3.25)
- C++17-capable compiler (MSVC 2022, clang 15+, gcc 11+)
All C++ library dependencies (Zydis, LIEF, spdlog, GoogleTest) are fetched automatically via `FetchContent` — no manual installation needed.

MSVC builds use the static CRT (`/MTd` in Debug, `/MT` otherwise), asynchronous exception handling (`/EHa`), disabled RTTI (`/GR-`), and UTF-8 source encoding. Windows targets define `UNICODE` and `_UNICODE`; non-Debug images store only the PDB basename in their debug directory.
 
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

The project requires the MSVC compiler and a configured environment.
Run the helper script from any PowerShell — it locates Visual Studio
automatically and runs configure/build/test in a single shell:

```powershell
powershell.exe -Executionpolicy Bypass -File "build.ps1"               # debug
powershell.exe -Executionpolicy Bypass -File "build.ps1" release       # release
powershell.exe -Executionpolicy Bypass -File "build.ps1" -NoTest       # skip tests
```

Presets available:

- `debug` — full build with tests and examples
- `release` — optimized build with examples
- `release-min` — library only, optimized for minimal size

## Dependencies

| Library     | Purpose                          | Version  |
|-------------|----------------------------------|----------|
| Zydis       | x86/x64 disassembly              | 4.1.0    |
| [LIEF](https://github.com/lief-project/LIEF/releases/tag/1.0.0) | PE parsing with its required COFF backend | 1.0.0 |
| spdlog      | shared logging dependency for symfind and LIEF | 1.17.0 |
| GoogleTest  | tests (optional)                 | 1.15.2   |
| [tl_expected](https://github.com/TartanLlama/expected/tree/v1.3.1) | C++17-compatible `tl::expected` | 1.3.1 |
| [span-lite](https://github.com/martinmoene/span-lite/tree/v0.11.0) | C++17-compatible `nonstd::span` byte views | 0.11.0 |
| [CPR](https://github.com/libcpr/cpr/tree/1.11.2) | PDB tool HTTP downloads | 1.11.2 |
| [nlohmann/json](https://github.com/nlohmann/json/tree/v3.11.3) | Fixture manifests | 3.11.3 |
| [zlib](https://github.com/madler/zlib/tree/v1.3.1) | PDB tool gzip/archive reading | 1.3.1 |

LIEF is pinned to release tag `1.0.0`. PE and its required COFF backend are
enabled; other binary-format backends, Runtime API, bindings, and examples are
disabled. LIEF shares the project's pinned `tl::expected` version. Configuration
rejects a source override or disconnected cache that still provides an older
LIEF version. Both libraries also use the same compiled spdlog target to keep
logging types and the registry consistent.

The library, examples, fixture tools, and tests compile as C++17. Public byte
views use `nonstd::span`; formatting uses the fmt implementation supplied by
spdlog. `tl::expected` is available through the public CMake dependencies; include
`<tl/expected.hpp>` when using it. Existing optional-returning APIs retain their
return types.

## Target platforms

Primary focus is Windows x64 PE modules. The core architecture (PE loader, Zydis, DSL) is portable, but the current analysis code assumes x64 calling conventions and Windows-specific structures like the `.pdata` exception directory.

## License

MIT. See [LICENSE](LICENSE). Third-party components retain their own licenses.
