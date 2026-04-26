#include "symfind/function_finder.h"

#include <spdlog/spdlog.h>
#include <algorithm>

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
        for (const auto& section: sections)
        {
            if (!section.executable)
            {
                continue;
            }

            auto sectionData = module.read_at(section.virtual_address, section.virtual_size);
            const auto instructions =
                disassembler.disassemble(sectionData, section.virtual_address);
            for (const auto& instruction: instructions)
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
        std::sort(funcs.begin(), funcs.end(),
                  [](const Function& a, const Function& b) { return a.rva < b.rva; });

        auto last = std::unique(funcs.begin(), funcs.end(),
                                [](const Function& a, const Function& b)
                                {
                                    return a.rva == b.rva;
                                });
        funcs.erase(last, funcs.end());
    }

} // namespace symfind