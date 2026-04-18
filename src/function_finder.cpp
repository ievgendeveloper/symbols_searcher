#include "symfind/function_finder.h"

#include <spdlog/spdlog.h>
#include <algorithm>

namespace symfind {

std::vector<Function> FunctionFinder::find(const PeModule& module,
                                            const Disassembler& disasm) {
    std::vector<Function> funcs;

    from_exports(module, funcs);
    from_exception_directory(module, funcs);
    from_call_targets(module, disasm, funcs);
    deduplicate(funcs);

    spdlog::info("Found {} functions in '{}'", funcs.size(), module.name());
    return funcs;
}

void FunctionFinder::from_exports(const PeModule& module,
                                   std::vector<Function>& out) {
    for (const auto& exp : module.exports()) {
        Function f;
        f.rva = exp.rva;
        f.exported = true;
        f.export_name = exp.name;
        out.push_back(f);
    }
}

void FunctionFinder::from_exception_directory(const PeModule& module,
                                               std::vector<Function>& out) {
    // TODO: Parse .pdata section — each RUNTIME_FUNCTION entry
    //       gives us (begin_address, end_address, unwind_info).
    //       This is the most reliable source for x64 functions.
    spdlog::debug("Exception directory analysis not yet implemented");
}

void FunctionFinder::from_call_targets(const PeModule& module,
                                        const Disassembler& disasm,
                                        std::vector<Function>& out) {
    // TODO: Disassemble executable sections, collect all direct
    //       call targets, add them as function starts.
    spdlog::debug("Call target analysis not yet implemented");
}

void FunctionFinder::deduplicate(std::vector<Function>& funcs) {
    std::sort(funcs.begin(), funcs.end(),
              [](const Function& a, const Function& b) { return a.rva < b.rva; });

    auto last = std::unique(funcs.begin(), funcs.end(),
                             [](const Function& a, const Function& b) {
                                 return a.rva == b.rva;
                             });
    funcs.erase(last, funcs.end());
}

} // namespace symfind
