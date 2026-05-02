#pragma once

#include "analysis_db.h"
#include "symfind/pe_module.h"
#include "symfind/disassembler.h"

#include <cstdint>
#include <vector>

namespace symfind
{
    /// A discovered function within the module.
    struct Function
    {
        uint64_t rva = 0; ///< Start address (RVA)
        uint64_t size = 0; ///< Size in bytes (0 if unknown)
        bool exported = false; ///< Has a matching export entry
        std::string export_name; ///< Export name (empty if not exported)
    };

    /// Discovers function boundaries within a PE module.
    ///
    /// Uses multiple strategies:
    ///   1. Export table entries (known good starting points)
    ///   2. Exception directory (.pdata) on x64 — RUNTIME_FUNCTION entries
    ///   3. Call target analysis — collect all `call` targets
    ///   4. Prologue pattern matching (push rbp; sub rsp, N)
    class FunctionFinder
    {
        public:
            /// Discover all functions in the given module.
            [[nodiscard]]
            static std::vector<Function> find(const PeModule& module,
                                              const Disassembler& disasm);


            /// Collect functions from export table.
            static void from_exports(const PeModule& module,
                                     std::vector<Function>& out);

            /// Collect functions from .pdata (x64 exception directory).
            static void from_exception_directory(const PeModule& module,
                                                 std::vector<Function>& out);

            /// Collect functions by scanning for call targets.
            static void from_call_targets(const PeModule& module,
                                          const Disassembler& disassembler,
                                          std::vector<Function>& out);

        private:
            /// Merge and deduplicate results.
            static void deduplicate(std::vector<Function>& funcs);
    };

    /// Disassembles a function body and collects all direct call targets.
    /// Indirect calls (call rax, call [rip+...]) are skipped.
    [[nodiscard]] std::vector<uint64_t> collect_callees(const PeModule& module,
                                                        const Disassembler& disasm,
                                                        uint64_t func_rva,
                                                        uint64_t func_size);

    /// For each function, populates its `callers` list based on the
    /// `callees` of all other functions. Builds reverse links.
    void link_callers(std::vector<symfind::AnalyzedFunction>& functions);

} // namespace symfind