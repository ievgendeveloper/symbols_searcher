#include "symfind/analysis_db.h"
#include "symfind/function_finder.h"

#include <algorithm>
#include <spdlog/fmt/fmt.h>
#include <spdlog/spdlog.h>

namespace symfind
{
    AnalysisDb AnalysisDb::Analyze(const PeModule& peModule)
    {
        AnalysisDb analysisDatabase;
        analysisDatabase.m_moduleName = peModule.Name();

        const Disassembler disassembler;

        // Step 1: Find all functions
        const auto discoveredFunctions = FunctionFinder::Find(peModule, disassembler);

        // Step 2: For each function, disassemble its body and collect xrefs
        for (const auto& discoveredFunction : discoveredFunctions)
        {
            AnalyzedFunction analyzedFunction;
            analyzedFunction.rva = discoveredFunction.rva;
            analyzedFunction.size = discoveredFunction.size;
            analyzedFunction.exported = discoveredFunction.exported;
            analyzedFunction.name = discoveredFunction.exported
                                        ? discoveredFunction.exportName
                                        : fmt::format("sub_{:X}", discoveredFunction.rva);

            analyzedFunction.ranges = discoveredFunction.ranges;
            if (analyzedFunction.ranges.empty() && discoveredFunction.size != 0)
            {
                analyzedFunction.ranges.push_back(
                    {discoveredFunction.rva, discoveredFunction.size});
            }
            for (const auto& ownedRange : analyzedFunction.ranges)
            {
                const auto calleeRvas =
                    CollectCallees(peModule, disassembler, ownedRange.rva, ownedRange.size);
                analyzedFunction.callees.insert(analyzedFunction.callees.end(), calleeRvas.begin(),
                                                calleeRvas.end());
                auto dataReferences =
                    CollectDataRefs(peModule, disassembler, ownedRange.rva, ownedRange.size);
                for (auto& dataReference : dataReferences)
                {
                    dataReference.fromFunc = analyzedFunction.rva;
                }
                analyzedFunction.dataRefs.insert(analyzedFunction.dataRefs.end(),
                                                 dataReferences.begin(), dataReferences.end());

                // A backward branch may cross between owned spans. Test actual
                // membership rather than including the bytes in sparse gaps.
                const auto functionBody = peModule.ReadAt(ownedRange.rva, ownedRange.size);
                disassembler.DisassembleCb(
                    functionBody, ownedRange.rva,
                    [&](const Instruction& instruction)
                    {
                        if (instruction.isJump && instruction.branchTarget != 0 &&
                            instruction.branchTarget < instruction.address &&
                            std::any_of(
                                analyzedFunction.ranges.begin(), analyzedFunction.ranges.end(),
                                [&](const FunctionRange& candidateRange)
                                {
                                    return instruction.branchTarget >= candidateRange.rva &&
                                           instruction.branchTarget - candidateRange.rva <
                                               candidateRange.size;
                                }))
                        {
                            analyzedFunction.hasLoop = true;
                            return false;
                        }
                        return true;
                    });
            }
            analyzedFunction.callCount = static_cast<uint32_t>(analyzedFunction.callees.size());
            analyzedFunction.stackFrameSize = ComputeStackFrameSize(
                peModule, disassembler, analyzedFunction.rva, analyzedFunction.size);

            analysisDatabase.m_functions.push_back(std::move(analyzedFunction));
        }

        LinkCallers(analysisDatabase.m_functions);
        analysisDatabase.m_globals = CollectGlobals(analysisDatabase.m_functions);
        analysisDatabase.BuildIndices();

        // Several exports can name the same procedure, including alternate
        // entries in its unwind-owned spans. Preserve every alias in the name
        // index while retaining the chosen display name on AnalyzedFunction.
        for (const auto& exportEntry : peModule.Exports())
        {
            if (exportEntry.name.empty())
            {
                continue;
            }
            const auto canonicalFunctionRva =
                peModule.CanonicalFunctionRva(exportEntry.rva).value_or(exportEntry.rva);
            const auto functionEntry =
                analysisDatabase.m_functionIndexByRva.find(canonicalFunctionRva);
            if (functionEntry != analysisDatabase.m_functionIndexByRva.end())
            {
                analysisDatabase.m_functionIndexByName[exportEntry.name] = functionEntry->second;
            }
        }

        SPDLOG_INFO("Analysis complete for '{}': {} functions, {} globals",
                    analysisDatabase.m_moduleName, analysisDatabase.m_functions.size(),
                    analysisDatabase.m_globals.size());

        return analysisDatabase;
    }

    const std::string& AnalysisDb::ModuleName() const
    {
        return m_moduleName;
    }

    const std::vector<AnalyzedFunction>& AnalysisDb::Functions() const
    {
        return m_functions;
    }

    const std::vector<Global>& AnalysisDb::Globals() const
    {
        return m_globals;
    }

    const AnalyzedFunction* AnalysisDb::FunctionAt(uint64_t functionRva) const
    {
        auto functionEntry = m_functionIndexByRva.find(functionRva);
        if (functionEntry != m_functionIndexByRva.end())
        {
            return &m_functions[functionEntry->second];
        }
        return nullptr;
    }

    const AnalyzedFunction* AnalysisDb::FunctionByName(const std::string_view functionName) const
    {
        auto functionEntry = m_functionIndexByName.find(std::string(functionName));
        if (functionEntry != m_functionIndexByName.end())
        {
            return &m_functions[functionEntry->second];
        }

        return nullptr;
    }

    const Global* AnalysisDb::GlobalAt(uint64_t globalRva) const
    {
        auto globalEntry = m_globalIndexByRva.find(globalRva);
        if (globalEntry != m_globalIndexByRva.end())
        {
            return &m_globals[globalEntry->second];
        }

        return nullptr;
    }

    std::vector<Xref> AnalysisDb::XrefsTo(uint64_t targetRva) const
    {
        auto referenceEntry = m_dataReferencesByTargetRva.find(targetRva);
        if (referenceEntry != m_dataReferencesByTargetRva.end())
        {
            return referenceEntry->second;
        }

        return {};
    }

    std::vector<Xref> AnalysisDb::XrefsFrom(uint64_t functionRva) const
    {
        const auto* analyzedFunction = FunctionAt(functionRva);
        if (!analyzedFunction)
        {
            return {};
        }

        return analyzedFunction->dataRefs;
    }

    void AnalysisDb::BuildIndices()
    {
        m_functionIndexByRva.clear();
        m_functionIndexByName.clear();
        m_globalIndexByRva.clear();
        m_dataReferencesByTargetRva.clear();

        for (size_t functionIndex = 0; functionIndex < m_functions.size(); ++functionIndex)
        {
            m_functionIndexByRva[m_functions[functionIndex].rva] = functionIndex;
            if (!m_functions[functionIndex].name.empty())
            {
                m_functionIndexByName[m_functions[functionIndex].name] = functionIndex;
            }

            // Index all xrefs from this function
            for (const auto& dataReference : m_functions[functionIndex].dataRefs)
            {
                m_dataReferencesByTargetRva[dataReference.toRva].push_back(dataReference);
            }
        }

        for (size_t globalIndex = 0; globalIndex < m_globals.size(); ++globalIndex)
        {
            m_globalIndexByRva[m_globals[globalIndex].rva] = globalIndex;
        }
    }

} // namespace symfind
