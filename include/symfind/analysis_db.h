#pragma once

#include "symfind/disassembler.h"
#include "symfind/pe_module.h"

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace symfind
{
    /// Cross-reference type.
    enum class XrefType
    {
        Call,      ///< call instruction
        Jump,      ///< jmp instruction
        DataRef,   ///< lea / mov with RIP-relative addressing (reference to data)
        DataRead,  ///< mov reg, [rip+offset] (read from global)
        DataWrite, ///< mov [rip+offset], reg (write to global)
    };

    /// A cross-reference from one address to another.
    struct Xref
    {
            uint64_t fromRva = 0;  ///< Address of the referencing instruction
            uint64_t toRva = 0;    ///< Target address
            uint64_t fromFunc = 0; ///< RVA of the function containing `from`
            XrefType type = XrefType::Call;
    };

    /// A global variable (or data reference) discovered by analysis.
    struct Global
    {
            uint64_t rva = 0;
            uint64_t size = 0;      ///< Estimated size (0 if unknown)
            std::vector<Xref> refs; ///< All xrefs pointing to this global
    };

    /// Analyzed function with all relationships resolved.
    struct AnalyzedFunction
    {
            uint64_t rva = 0;
            uint64_t size = 0;
            std::string name; ///< Export name or auto-generated "sub_XXXX"
            bool exported = false;

            /// Functions this function calls (RVAs).
            std::vector<uint64_t> callees;

            /// Functions that call this function (RVAs).
            std::vector<uint64_t> callers;

            /// Global data references from this function.
            std::vector<Xref> dataRefs;

            /// Approximate stack frame size from `sub rsp, N`.
            uint32_t stackFrameSize = 0;

            /// Number of call instructions inside the function body.
            uint32_t callCount = 0;

            /// Whether the function contains a loop (back-edge detected).
            bool hasLoop = false;

            /// Actual code spans owned by this procedure, excluding gaps.
            /// size retains the primary contiguous span for API compatibility.
            std::vector<FunctionRange> ranges;
    };

    /// The complete analysis result for a module.
    /// This is the "database" that the DSL matcher queries.
    class AnalysisDb
    {
        public:
            /// Run full analysis on a module.
            [[nodiscard]] static AnalysisDb Analyze(const PeModule& peModule);

            /// Module name.
            [[nodiscard]] const std::string& ModuleName() const;

            /// All analyzed functions.
            [[nodiscard]] const std::vector<AnalyzedFunction>& Functions() const;

            /// All discovered globals.
            [[nodiscard]] const std::vector<Global>& Globals() const;

            /// Look up a function by RVA.
            [[nodiscard]] const AnalyzedFunction* FunctionAt(uint64_t functionRva) const;

            /// Look up a function by name (export name).
            [[nodiscard]] const AnalyzedFunction* FunctionByName(
                const std::string_view functionName) const;

            /// Look up a global by RVA.
            [[nodiscard]] const Global* GlobalAt(uint64_t globalRva) const;

            /// Get all xrefs to a given RVA.
            [[nodiscard]] std::vector<Xref> XrefsTo(uint64_t targetRva) const;

            /// Get all xrefs from a given function.
            [[nodiscard]] std::vector<Xref> XrefsFrom(uint64_t functionRva) const;

            /// Build a database manually (for testing / mock data).
            struct Builder
            {
                    std::string moduleName;
                    std::vector<AnalyzedFunction> functions;
                    std::vector<Global> globals;

                    [[nodiscard]] AnalysisDb Build()
                    {
                        AnalysisDb analysisDatabase;
                        analysisDatabase.m_moduleName = std::move(moduleName);
                        analysisDatabase.m_functions = std::move(functions);
                        analysisDatabase.m_globals = std::move(globals);
                        analysisDatabase.BuildIndices();
                        return analysisDatabase;
                    }
            };

        private:
            std::string m_moduleName;
            std::vector<AnalyzedFunction> m_functions;
            std::vector<Global> m_globals;

            // Lookup indices
            std::unordered_map<uint64_t, size_t> m_functionIndexByRva;
            std::unordered_map<std::string, size_t> m_functionIndexByName;
            std::unordered_map<uint64_t, size_t> m_globalIndexByRva;

            // Xref index: targetRva -> list of xrefs
            std::unordered_map<uint64_t, std::vector<Xref>> m_dataReferencesByTargetRva;

            void BuildIndices();
    };

} // namespace symfind
