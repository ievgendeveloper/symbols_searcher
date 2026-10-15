#include "symfind/function_finder.h"

#include <algorithm>
#include <map>
#include <spdlog/spdlog.h>

namespace symfind
{
    std::vector<Function> FunctionFinder::find(const PeModule& module,
                                               const Disassembler& disassembler)
    {
        std::vector<Function> functions;

        from_exports(module, functions);
        from_exception_directory(module, functions);
        from_call_targets(module, disassembler, functions);
        deduplicate(functions);

        SPDLOG_INFO("Found {} functions in '{}'", functions.size(), module.name());
        return functions;
    }

    void FunctionFinder::from_exports(const PeModule& module,
                                      std::vector<Function>& out)
    {
        for (const auto& exp : module.exports())
        {
            Function f;
            f.rva = module.canonical_function_rva(exp.rva).value_or(exp.rva);
            f.exported = true;
            f.export_name = exp.name;
            out.push_back(f);
        }
    }

    void FunctionFinder::from_exception_directory(const PeModule& module,
                                                  std::vector<Function>& out)
    {
        size_t numberOfFoundedFunctions = 0;
        const auto& limits = module.exception_functions();
        for (const auto& element : limits)
        {
            out.emplace_back(element.rva, element.size, false, std::string(), element.ranges);
            ++numberOfFoundedFunctions;
        }

        SPDLOG_INFO("The number of functions founded by parsing exception directory: {}", numberOfFoundedFunctions);
    }

    void FunctionFinder::from_call_targets(const PeModule& module,
                                           const Disassembler& disassembler,
                                           std::vector<Function>& out)
    {
        size_t numberOfFoundedFunctions = 0;
        const auto& sections = module.sections();
        for (const auto& section : sections)
        {
            if (!section.executable)
            {
                continue;
            }

            auto sectionData = module.read_at(section.virtual_address, section.virtual_size);
            const auto instructions =
                disassembler.disassemble(sectionData, section.virtual_address);
            for (const auto& instruction : instructions)
            {
                if (!instruction.is_call || !instruction.branch_target)
                {
                    continue;
                }

                const auto target = module.canonical_function_rva(instruction.branch_target)
                                        .value_or(instruction.branch_target);
                out.emplace_back(target, 0, false, std::string());
                ++numberOfFoundedFunctions;
            }
        }

        SPDLOG_INFO("The number of functions founded by disassembling: {}", numberOfFoundedFunctions);
    }

    void FunctionFinder::deduplicate(std::vector<Function>& funcs)
    {
        // skip too small libraries where nothing to regroup
        if (funcs.size() < 2)
        {
            return;
        }

        std::sort(funcs.begin(), funcs.end(),
                  [](const Function& a, const Function& b)
                  { return a.rva < b.rva; });

        // Single pass: merge runs of equal-RVA entries into the leftmost one,
        // taking the most informative field from each.
        size_t write = 0;
        for (size_t read = 1; read < funcs.size(); ++read)
        {
            if (funcs[read].rva == funcs[write].rva)
            {
                // Same function - merge data into the write slot.
                if (funcs[write].size == 0)
                {
                    funcs[write].size = funcs[read].size;
                }

                if (!funcs[write].exported && funcs[read].exported)
                {
                    funcs[write].exported = true;
                }

                if (funcs[write].export_name.empty())
                {
                    funcs[write].export_name = std::move(funcs[read].export_name);
                }
                if (funcs[write].ranges.empty())
                {
                    funcs[write].ranges = std::move(funcs[read].ranges);
                }
            }
            else
            {
                ++write;
                if (write != read)
                {
                    funcs[write] = std::move(funcs[read]);
                }
            }
        }

        funcs.resize(write + 1);
    }

    std::vector<uint64_t> collect_callees(const PeModule& module, const Disassembler& disasm, uint64_t func_rva, uint64_t func_size)
    {
        std::vector<uint64_t> result;
        if (func_size == 0)
        {
            return result;
        }

        const auto body = module.read_at(func_rva, func_size);
        if (body.empty())
        {
            return result;
        }

        disasm.disassemble_cb(body, func_rva, [&](const Instruction& instruction) -> bool
                              {
            if (instruction.is_call && instruction.branch_target != 0)
            {
                result.push_back(module.canonical_function_rva(instruction.branch_target)
                                     .value_or(instruction.branch_target));
            }

            return true; });

        return result;
    }

    void link_callers(std::vector<AnalyzedFunction>& functions)
    {
        // Build a temporary RVA -> index map for O(1) lookup
        std::unordered_map<uint64_t, size_t> rva_to_index;
        rva_to_index.reserve(functions.size());
        for (size_t i = 0; i < functions.size(); ++i)
        {
            rva_to_index[functions[i].rva] = i;
        }

        for (size_t i = 0; i < functions.size(); ++i)
        {
            for (uint64_t callee_rva : functions[i].callees)
            {
                auto it = rva_to_index.find(callee_rva);
                if (it != rva_to_index.end())
                {
                    functions[it->second].callers.push_back(functions[i].rva);
                }
            }
        }
    }

    // We prefer anonymous namespaces over `static` for internal linkage.
    //
    // Both make a symbol local to this translation unit, but the anonymous
    // namespace is the more general C++ mechanism:
    //
    //   * It applies uniformly to functions, variables, types, templates,
    //     and constants. `static` only works for functions and variables -
    //     a file-scope `struct` cannot be made TU-local with `static`,
    //     which leaves type definitions exposed to ODR violations across
    //     translation units.
    //
    //   * It groups all TU-private declarations into a single, visually
    //     obvious block instead of scattering `static` keywords across
    //     the file.
    //
    //   * It is the idiom recommended by the C++ standard, the Core
    //     Guidelines (SF.22), and major style guides; `static` at file
    //     scope is largely retained for C compatibility.
    //
    // `static` remains appropriate for its other meanings - local
    // variables with static storage duration, and class members - but
    // not for hiding free functions or types from other TUs.
    namespace
    {
        bool is_data_section(const PeModule& module, uint64_t rva)
        {
            for (const auto& sec : module.sections())
            {
                if (rva >= sec.virtual_address &&
                    rva < sec.virtual_address + sec.virtual_size)
                {
                    return !sec.executable; // data section = non-executable
                }
            }

            return false; // outside any section
        }
    } // namespace

    std::vector<Xref> collect_data_refs(const PeModule& module, const Disassembler& disassembler,
                                        uint64_t func_rva, uint64_t func_size)
    {
        std::vector<Xref> references;
        if (func_size == 0)
        {
            return references;
        }

        const auto body = module.read_at(func_rva, func_size);
        if (body.empty())
        {
            return references;
        }

        disassembler.disassemble_cb(body, func_rva, [&](const Instruction& instruction) -> bool
                                    {
            if (instruction.mem_absolute == 0)
            {
                return true; // not RIP-relative
            }

            if (!is_data_section(module, instruction.mem_absolute))
            {
                return true;
            }

            Xref crossReference{};
            crossReference.from_rva = instruction.address;
            crossReference.to_rva = instruction.mem_absolute;
            crossReference.from_func = func_rva;

            if (instruction.is_lea)
            {
                crossReference.type = XrefType::DataRef;
            }
            else if (instruction.is_mem_read)
            {
                crossReference.type = XrefType::DataRead;
            }
            else if (instruction.is_mem_write)
            {
                crossReference.type = XrefType::DataWrite;
            }
            else
            {
                return true; // some other RIP-relative we don't handle
            }

            references.push_back(crossReference);
            return true; });

        return references;
    }

    std::vector<Global> collect_globals(const std::vector<AnalyzedFunction>& functions)
    {
        // Group xrefs by their target RVA (the address of the global).
        // Using a map keeps the result sorted by RVA, which is nice for
        // determinism and binary search if we need it later.
        std::map<uint64_t, std::vector<Xref>> by_target;

        for (const auto& func : functions)
        {
            for (const auto& ref : func.data_refs)
            {
                by_target[ref.to_rva].push_back(ref);
            }
        }

        // Materialize into Global structs
        std::vector<Global> globals;
        globals.reserve(by_target.size());
        for (auto& [rva, refs] : by_target)
        {
            Global g{};
            g.rva = rva;
            g.size = 0; // unknown - we don't infer global sizes yet
            g.refs = std::move(refs);
            globals.push_back(std::move(g));
        }

        return globals;
    }

    uint32_t compute_stack_frame_size_in_body(const symfind::Disassembler& disassembler,
                                              std::span<const uint8_t> body, uint64_t functionRva)
    {
        // The prologue is typically the first few instructions. We scan up to
        // a small limit and take the first `sub rsp, imm` we encounter - that's
        // the stack frame size. Anything beyond the prologue is unrelated.
        constexpr int kPrologueScanLimit = 16;

        uint32_t frameSize = 0;
        int instructionCounter = 0;

        disassembler.disassemble_cb(body, functionRva, [&](const Instruction& instruction)
                                    {
            if (instruction.is_sub_rsp_imm)
            {
                frameSize = static_cast<uint32_t>(instruction.imm_value);
                return false; // stop - found it
            }

            // Stop scanning once we leave the prologue
            if (++instructionCounter >= kPrologueScanLimit)
            {
                return false;
            }

            return true; });

        return frameSize;
    }

    bool detect_loops_in_body(const Disassembler& disassembler, std::span<const uint8_t> body,
                              uint64_t functionRva, uint64_t functionSize)
    {
        if (body.empty())
        {
            return false;
        }

        const auto func_end = functionRva + functionSize;
        bool hasLoop = false;

        disassembler.disassemble_cb(body, functionRva, [&](const Instruction& instruction) -> bool
                                    {
            if (!instruction.is_jump)
            {
                return true; // not a branch
            }

            if (instruction.branch_target == 0)
            {
                return true; // indirect jump
            }

            // Backward jump within the function body = back-edge
            if (instruction.branch_target < instruction.address &&
                instruction.branch_target >= functionRva &&
                instruction.branch_target < func_end)
            {
                hasLoop = true;
                return false; // found one, stop scanning
            }
            return true; });

        return hasLoop;
    }

    bool detect_loops(const PeModule& module, const Disassembler& disassembler,
                      uint64_t functionRva, uint64_t functionSize)
    {
        if (functionSize == 0)
        {
            return false;
        }

        const auto body = module.read_at(functionRva, functionSize);
        return detect_loops_in_body(disassembler, body, functionRva, functionSize);
    }

    uint32_t compute_stack_frame_size(const PeModule& module, const Disassembler& disassembler,
                                      uint64_t functionRva, uint64_t functionSize)
    {
        if (functionSize == 0)
        {
            return 0;
        }

        const auto body = module.read_at(functionRva, functionSize);
        if (body.empty())
        {
            return 0;
        }

        return compute_stack_frame_size_in_body(disassembler, body, functionRva);
    }

} // namespace symfind
