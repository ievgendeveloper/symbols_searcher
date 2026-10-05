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
                                              const Disassembler& disassembler);


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

    /**
     * @brief collect references to data inside code of function
     * @param module - pe file loaded from disk (or memory) - dll or exe (.sys file maybe)
     * @param disassembler - disassembler to analyze function's code
     * @param func_rva - relative virtual address of function
     * @param func_size - size in bytes of function
     * @return - vector of reference objects to data
     */
    [[nodiscard]] std::vector<Xref> collect_data_refs(const PeModule& module,
                                                      const Disassembler& disassembler,
                                                      uint64_t func_rva,
                                                      uint64_t func_size);

    /**
     * @brief Create the enumeration of Globals after data from functions was agregated
     * @param functions - result of analysis of separate functions
     * @return - vector of Globals (objects with information about global variables and type of access to them)
     */
    [[nodiscard]] std::vector<Global> collect_globals(const std::vector<AnalyzedFunction>& functions);

    /**
     * @brief Compute the number of bytes for the stack frame of the function
     * @param module - pe file loaded from disk (or memory) - dll or exe (.sys file maybe)
     * @param disassembler - disassembler to analyze function's code
     * @param functionRva - relative virtual address of function
     * @param functionSize - size in bytes of function
     * @return number of bytes for the stack frame
     */
    [[nodiscard]] uint32_t compute_stack_frame_size(const PeModule& module,
                                                    const Disassembler& disassembler,
                                                    uint64_t functionRva,
                                                    uint64_t functionSize);

    /**
     * @brief Compute the number of bytes for the stack frame of the function directly from memory
     * @param disassembler - disassembler to analyze function's code 
     * @param body - the code of function needs to be analyzed
     * @param functionRva - relative virtual address of function
     * @return number of bytes for the stack frame
     */
    [[nodiscard]] uint32_t compute_stack_frame_size_in_body(
        const symfind::Disassembler& disassembler,
        std::span<const uint8_t> body,
        uint64_t functionRva);

    /**
     * @brief Find potential loop construction inside function's body
     * @param disassembler - disassembler to analyze function's code 
     * @param body - the code of function needs to be analyzed
     * @param functionRva - relative virtual address of function
     * @param functionSize - size in bytes of function's body
     * @return true if loop was found or false otherwise
     */
    [[nodiscard]] bool detect_loops_in_body(const Disassembler& disassembler,
                                            std::span<const uint8_t> body,
                                            uint64_t functionRva,
                                            uint64_t functionSize);

    /**
     * @brief Find potential loop construction inside module's function when we know it's location
     * @param module - pe file loaded from disk (or memory) - dll or exe (.sys file maybe)
     * @param disassembler - disassembler to analyze function's code 
     * @param functionRva - relative virtual address of function
     * @param functionSize - size in bytes of function's body
     * @return 
     */
    [[nodiscard]] bool detect_loops(const PeModule& module,
                                    const Disassembler& disassembler,
                                    uint64_t functionRva,
                                    uint64_t functionSize);

} // namespace symfind
