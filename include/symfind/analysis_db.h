#pragma once

#include "symfind/pe_module.h"
#include "symfind/disassembler.h"

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <optional>

namespace symfind
{
    /// Cross-reference type.
    enum class XrefType
    {
        Call, ///< call instruction
        Jump, ///< jmp instruction
        DataRef, ///< lea / mov with RIP-relative addressing (reference to data)
        DataRead, ///< mov reg, [rip+offset] (read from global)
        DataWrite, ///< mov [rip+offset], reg (write to global)
    };

    /// A cross-reference from one address to another.
    struct Xref
    {
        uint64_t from_rva = 0; ///< Address of the referencing instruction
        uint64_t to_rva = 0; ///< Target address
        uint64_t from_func = 0; ///< RVA of the function containing `from`
        XrefType type = XrefType::Call;
    };

    /// A global variable (or data reference) discovered by analysis.
    struct Global
    {
        uint64_t rva = 0;
        uint64_t size = 0; ///< Estimated size (0 if unknown)
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
        std::vector<Xref> data_refs;

        /// Approximate stack frame size from `sub rsp, N`.
        uint32_t stack_frame_size = 0;

        /// Number of call instructions inside the function body.
        uint32_t call_count = 0;

        /// Whether the function contains a loop (back-edge detected).
        bool has_loop = false;
    };

    /// The complete analysis result for a module.
    /// This is the "database" that the DSL matcher queries.
    class AnalysisDb
    {
        public:
            /// Run full analysis on a module.
            [[nodiscard]]
            static AnalysisDb analyze(const PeModule& module);

            /// Module name.
            [[nodiscard]] const std::string& module_name() const;

            /// All analyzed functions.
            [[nodiscard]] const std::vector<AnalyzedFunction>& functions() const;

            /// All discovered globals.
            [[nodiscard]] const std::vector<Global>& globals() const;

            /// Look up a function by RVA.
            [[nodiscard]] const AnalyzedFunction* function_at(uint64_t rva) const;

            /// Look up a function by name (export name).
            [[nodiscard]] const AnalyzedFunction* function_by_name(const std::string_view name) const;

            /// Look up a global by RVA.
            [[nodiscard]] const Global* global_at(uint64_t rva) const;

            /// Get all xrefs to a given RVA.
            [[nodiscard]] std::vector<Xref> xrefs_to(uint64_t rva) const;

            /// Get all xrefs from a given function.
            [[nodiscard]] std::vector<Xref> xrefs_from(uint64_t func_rva) const;

            /// Build a database manually (for testing / mock data).
            struct Builder
            {
                std::string module_name;
                std::vector<AnalyzedFunction> functions;
                std::vector<Global> globals;

                [[nodiscard]] AnalysisDb build()
                {
                    AnalysisDb db;
                    db.module_name_ = std::move(module_name);
                    db.functions_ = std::move(functions);
                    db.globals_ = std::move(globals);
                    db.build_indices();
                    return db;
                }
            };

        private:
            std::string module_name_;
            std::vector<AnalyzedFunction> functions_;
            std::vector<Global> globals_;

            // Lookup indices
            std::unordered_map<uint64_t, size_t> func_by_rva_;
            std::unordered_map<std::string, size_t> func_by_name_;
            std::unordered_map<uint64_t, size_t> global_by_rva_;

            // Xref index: target_rva -> list of xrefs
            std::unordered_map<uint64_t, std::vector<Xref>> xref_index_;

            void build_indices();
    };

} // namespace symfind