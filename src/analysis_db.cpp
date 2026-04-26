#include "symfind/analysis_db.h"

#include <spdlog/spdlog.h>
#include <format>

namespace symfind
{

    AnalysisDb AnalysisDb::analyze(const PeModule& module)
    {
        AnalysisDb db;
        db.module_name_ = module.name();

        Disassembler disasm;

        // Step 1: Find all functions
        auto funcs = FunctionFinder::find(module, disasm);

        // Step 2: For each function, disassemble its body and collect xrefs
        for (const auto& func : funcs)
        {
            AnalyzedFunction af;
            af.rva = func.rva;
            af.size = func.size;
            af.exported = func.exported;
            af.name = func.exported
                          ? func.export_name
                          : std::format("sub_{:X}", func.rva);

            // TODO: Disassemble function body, collect:
            //   - callees (call targets)
            //   - data_refs (RIP-relative references to globals)
            //   - stack_frame_size (from sub rsp, N)
            //   - call_count
            //   - has_loop (back-edge detection)

            db.functions_.push_back(std::move(af));
        }

        // Step 3: Build caller/callee relationships
        // TODO: For each function's callees, add reverse caller links

        // Step 4: Collect globals from data references
        // TODO: Group all data_refs by target address -> Global entries

        db.build_indices();

        spdlog::info("Analysis complete for '{}': {} functions, {} globals",
                     db.module_name_, db.functions_.size(), db.globals_.size());

        return db;
    }

    const std::string& AnalysisDb::module_name() const { return module_name_; }

    const std::vector<AnalyzedFunction>& AnalysisDb::functions() const { return functions_; }

    const std::vector<Global>& AnalysisDb::globals() const { return globals_; }

    const AnalyzedFunction* AnalysisDb::function_at(uint64_t rva) const
    {
        auto it = func_by_rva_.find(rva);
        if (it != func_by_rva_.end())
            return &functions_[it->second];
        return nullptr;
    }

    const AnalyzedFunction* AnalysisDb::function_by_name(const std::string_view name) const
    {
        auto it = func_by_name_.find(std::string(name));
        if (it != func_by_name_.end())
            return &functions_[it->second];
        return nullptr;
    }

    const Global* AnalysisDb::global_at(uint64_t rva) const
    {
        auto it = global_by_rva_.find(rva);
        if (it != global_by_rva_.end())
            return &globals_[it->second];
        return nullptr;
    }

    std::vector<Xref> AnalysisDb::xrefs_to(uint64_t rva) const
    {
        auto it = xref_index_.find(rva);
        if (it != xref_index_.end())
            return it->second;
        return {};
    }

    std::vector<Xref> AnalysisDb::xrefs_from(uint64_t func_rva) const
    {
        const auto* func = function_at(func_rva);
        if (!func)
            return {};
        return func->data_refs;
    }

    void AnalysisDb::build_indices()
    {
        func_by_rva_.clear();
        func_by_name_.clear();
        global_by_rva_.clear();
        xref_index_.clear();

        for (size_t i = 0; i < functions_.size(); ++i)
        {
            func_by_rva_[functions_[i].rva] = i;
            if (!functions_[i].name.empty())
            {
                func_by_name_[functions_[i].name] = i;
            }

            // Index all xrefs from this function
            for (const auto& xref : functions_[i].data_refs)
            {
                xref_index_[xref.to_rva].push_back(xref);
            }
        }

        for (size_t i = 0; i < globals_.size(); ++i)
        {
            global_by_rva_[globals_[i].rva] = i;
        }
    }

} // namespace symfind