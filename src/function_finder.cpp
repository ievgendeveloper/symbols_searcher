#include "symfind/function_finder.h"

#include <spdlog/spdlog.h>
#include <algorithm>
#include <map>

namespace symfind
{

    std::vector<Function> FunctionFinder::find(const PeModule& module,
                                               const Disassembler& disasm)
    {
        std::vector<Function> funcs;

        from_exports(module, funcs);
        from_exception_directory(module, funcs);
        from_call_targets(module, disasm, funcs);
        deduplicate(funcs);

        spdlog::info("Found {} functions in '{}'", funcs.size(), module.name());
        return funcs;
    }

    void FunctionFinder::from_exports(const PeModule& module,
                                      std::vector<Function>& out)
    {
        for (const auto& exp : module.exports())
        {
            Function f;
            f.rva = exp.rva;
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
            out.emplace_back(element.rva, element.size, false, std::string());
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

                out.emplace_back(instruction.branch_target, 0, false, std::string());
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
                  [](const Function& a, const Function& b) { return a.rva < b.rva; });

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
                result.push_back(instruction.branch_target);
            }

            return true;
        });

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
            return true;
        });

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

} // namespace symfind