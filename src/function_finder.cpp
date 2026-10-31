#include "symfind/function_finder.h"

#include <algorithm>
#include <map>
#include <spdlog/spdlog.h>

namespace symfind
{
    std::vector<Function> FunctionFinder::Find(const PeModule& module,
                                               const Disassembler& disassembler)
    {
        std::vector<Function> functions;

        FromExports(module, functions);
        FromExceptionDirectory(module, functions);
        FromCallTargets(module, disassembler, functions);
        Deduplicate(functions);

        SPDLOG_INFO("Found {} functions in '{}'", functions.size(), module.Name());
        return functions;
    }

    void FunctionFinder::FromExports(const PeModule& module,
                                     std::vector<Function>& discoveredFunctions)
    {
        for (const auto& exportEntry : module.Exports())
        {
            Function exportedFunction;
            exportedFunction.rva =
                module.CanonicalFunctionRva(exportEntry.rva).value_or(exportEntry.rva);
            exportedFunction.exported = true;
            exportedFunction.exportName = exportEntry.name;
            discoveredFunctions.push_back(exportedFunction);
        }
    }

    void FunctionFinder::FromExceptionDirectory(const PeModule& module,
                                                std::vector<Function>& discoveredFunctions)
    {
        size_t discoveredFunctionCount = 0;
        const auto& exceptionFunctions = module.ExceptionFunctions();
        for (const auto& functionBounds : exceptionFunctions)
        {
            discoveredFunctions.push_back(Function{functionBounds.rva, functionBounds.size, false,
                                                   std::string(), functionBounds.ranges});
            ++discoveredFunctionCount;
        }

        SPDLOG_INFO("The number of functions founded by parsing exception directory: {}",
                    discoveredFunctionCount);
    }

    void FunctionFinder::FromCallTargets(const PeModule& module, const Disassembler& disassembler,
                                         std::vector<Function>& discoveredFunctions)
    {
        size_t discoveredFunctionCount = 0;
        const auto& sections = module.Sections();
        for (const auto& section : sections)
        {
            if (!section.executable)
            {
                continue;
            }

            auto sectionBytes = module.ReadAt(section.virtualAddress, section.virtualSize);
            const auto decodedInstructions =
                disassembler.Disassemble(sectionBytes, section.virtualAddress);
            for (const auto& instruction : decodedInstructions)
            {
                if (!instruction.isCall || !instruction.branchTarget)
                {
                    continue;
                }

                const auto calleeRva = module.CanonicalFunctionRva(instruction.branchTarget)
                                           .value_or(instruction.branchTarget);
                discoveredFunctions.push_back(Function{calleeRva, 0, false, std::string(), {}});
                ++discoveredFunctionCount;
            }
        }

        SPDLOG_INFO("The number of functions founded by disassembling: {}",
                    discoveredFunctionCount);
    }

    void FunctionFinder::Deduplicate(std::vector<Function>& functions)
    {
        // skip too small libraries where nothing to regroup
        if (functions.size() < 2)
        {
            return;
        }

        std::sort(functions.begin(), functions.end(),
                  [](const Function& leftFunction, const Function& rightFunction)
                  {
                      return leftFunction.rva < rightFunction.rva;
                  });

        // Single pass: merge runs of equal-RVA entries into the leftmost one,
        // taking the most informative field from each.
        size_t writeIndex = 0;
        for (size_t readIndex = 1; readIndex < functions.size(); ++readIndex)
        {
            if (functions[readIndex].rva == functions[writeIndex].rva)
            {
                // Same function - merge data into the write slot.
                if (functions[writeIndex].size == 0)
                {
                    functions[writeIndex].size = functions[readIndex].size;
                }

                if (!functions[writeIndex].exported && functions[readIndex].exported)
                {
                    functions[writeIndex].exported = true;
                }

                if (functions[writeIndex].exportName.empty())
                {
                    functions[writeIndex].exportName = std::move(functions[readIndex].exportName);
                }
                if (functions[writeIndex].ranges.empty())
                {
                    functions[writeIndex].ranges = std::move(functions[readIndex].ranges);
                }
            }
            else
            {
                ++writeIndex;
                if (writeIndex != readIndex)
                {
                    functions[writeIndex] = std::move(functions[readIndex]);
                }
            }
        }

        functions.resize(writeIndex + 1);
    }

    std::vector<uint64_t> CollectCallees(const PeModule& module, const Disassembler& disassembler,
                                         uint64_t functionRva, uint64_t functionSize)
    {
        std::vector<uint64_t> calleeRvas;
        if (functionSize == 0)
        {
            return calleeRvas;
        }

        const auto functionBytes = module.ReadAt(functionRva, functionSize);
        if (functionBytes.empty())
        {
            return calleeRvas;
        }

        disassembler.DisassembleCb(functionBytes, functionRva,
                                   [&](const Instruction& instruction) -> bool
                                   {
                                       if (instruction.isCall && instruction.branchTarget != 0)
                                       {
                                           calleeRvas.push_back(
                                               module.CanonicalFunctionRva(instruction.branchTarget)
                                                   .value_or(instruction.branchTarget));
                                       }

                                       return true;
                                   });

        return calleeRvas;
    }

    void LinkCallers(std::vector<AnalyzedFunction>& functions)
    {
        // Build a temporary RVA -> index map for O(1) lookup
        std::unordered_map<uint64_t, size_t> functionIndexByRva;
        functionIndexByRva.reserve(functions.size());
        for (size_t functionIndex = 0; functionIndex < functions.size(); ++functionIndex)
        {
            functionIndexByRva[functions[functionIndex].rva] = functionIndex;
        }

        for (size_t functionIndex = 0; functionIndex < functions.size(); ++functionIndex)
        {
            for (uint64_t calleeRva : functions[functionIndex].callees)
            {
                auto calleeIndexEntry = functionIndexByRva.find(calleeRva);
                if (calleeIndexEntry != functionIndexByRva.end())
                {
                    functions[calleeIndexEntry->second].callers.push_back(
                        functions[functionIndex].rva);
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
        bool IsDataSection(const PeModule& module, uint64_t requestedRva)
        {
            for (const auto& section : module.Sections())
            {
                if (requestedRva >= section.virtualAddress &&
                    requestedRva < section.virtualAddress + section.virtualSize)
                {
                    return !section.executable; // data section = non-executable
                }
            }

            return false; // outside any section
        }
    } // namespace

    std::vector<Xref> CollectDataRefs(const PeModule& module, const Disassembler& disassembler,
                                      uint64_t functionRva, uint64_t functionSize)
    {
        std::vector<Xref> dataReferences;
        if (functionSize == 0)
        {
            return dataReferences;
        }

        const auto functionBytes = module.ReadAt(functionRva, functionSize);
        if (functionBytes.empty())
        {
            return dataReferences;
        }

        disassembler.DisassembleCb(functionBytes, functionRva,
                                   [&](const Instruction& instruction) -> bool
                                   {
                                       if (instruction.memAbsolute == 0)
                                       {
                                           return true; // not RIP-relative
                                       }

                                       if (!IsDataSection(module, instruction.memAbsolute))
                                       {
                                           return true;
                                       }

                                       Xref dataReference{};
                                       dataReference.fromRva = instruction.address;
                                       dataReference.toRva = instruction.memAbsolute;
                                       dataReference.fromFunc = functionRva;

                                       if (instruction.isLea)
                                       {
                                           dataReference.type = XrefType::DataRef;
                                       }
                                       else if (instruction.isMemRead)
                                       {
                                           dataReference.type = XrefType::DataRead;
                                       }
                                       else if (instruction.isMemWrite)
                                       {
                                           dataReference.type = XrefType::DataWrite;
                                       }
                                       else
                                       {
                                           return true; // some other RIP-relative we don't handle
                                       }

                                       dataReferences.push_back(dataReference);
                                       return true;
                                   });

        return dataReferences;
    }

    std::vector<Global> CollectGlobals(const std::vector<AnalyzedFunction>& functions)
    {
        // Group xrefs by their target RVA (the address of the global).
        // Using a map keeps the result sorted by RVA, which is nice for
        // determinism and binary search if we need it later.
        std::map<uint64_t, std::vector<Xref>> referencesByTargetRva;

        for (const auto& analyzedFunction : functions)
        {
            for (const auto& dataReference : analyzedFunction.dataRefs)
            {
                referencesByTargetRva[dataReference.toRva].push_back(dataReference);
            }
        }

        // Materialize into Global structs
        std::vector<Global> globals;
        globals.reserve(referencesByTargetRva.size());
        for (auto& [globalRva, dataReferences] : referencesByTargetRva)
        {
            Global global{};
            global.rva = globalRva;
            global.size = 0; // unknown - we don't infer global sizes yet
            global.refs = std::move(dataReferences);
            globals.push_back(std::move(global));
        }

        return globals;
    }

    uint32_t ComputeStackFrameSizeInBody(const symfind::Disassembler& disassembler,
                                         nonstd::span<const uint8_t> functionBytes,
                                         uint64_t functionRva)
    {
        // The prologue is typically the first few instructions. We scan up to
        // a small limit and take the first `sub rsp, imm` we encounter - that's
        // the stack frame size. Anything beyond the prologue is unrelated.
        constexpr int prologueScanLimit = 16;

        uint32_t stackFrameSize = 0;
        int scannedInstructionCount = 0;

        disassembler.DisassembleCb(functionBytes, functionRva,
                                   [&](const Instruction& instruction)
                                   {
                                       if (instruction.isSubRspImm)
                                       {
                                           stackFrameSize =
                                               static_cast<uint32_t>(instruction.immValue);
                                           return false; // stop - found it
                                       }

                                       // Stop scanning once we leave the prologue
                                       if (++scannedInstructionCount >= prologueScanLimit)
                                       {
                                           return false;
                                       }

                                       return true;
                                   });

        return stackFrameSize;
    }

    bool DetectLoopsInBody(const Disassembler& disassembler,
                           nonstd::span<const uint8_t> functionBytes, uint64_t functionRva,
                           uint64_t functionSize)
    {
        if (functionBytes.empty())
        {
            return false;
        }

        const auto functionEndRva = functionRva + functionSize;
        bool hasLoop = false;

        disassembler.DisassembleCb(functionBytes, functionRva,
                                   [&](const Instruction& instruction) -> bool
                                   {
                                       if (!instruction.isJump)
                                       {
                                           return true; // not a branch
                                       }

                                       if (instruction.branchTarget == 0)
                                       {
                                           return true; // indirect jump
                                       }

                                       // Backward jump within the function body = back-edge
                                       if (instruction.branchTarget < instruction.address &&
                                           instruction.branchTarget >= functionRva &&
                                           instruction.branchTarget < functionEndRva)
                                       {
                                           hasLoop = true;
                                           return false; // found one, stop scanning
                                       }
                                       return true;
                                   });

        return hasLoop;
    }

    bool DetectLoops(const PeModule& module, const Disassembler& disassembler, uint64_t functionRva,
                     uint64_t functionSize)
    {
        if (functionSize == 0)
        {
            return false;
        }

        const auto functionBytes = module.ReadAt(functionRva, functionSize);
        return DetectLoopsInBody(disassembler, functionBytes, functionRva, functionSize);
    }

    uint32_t ComputeStackFrameSize(const PeModule& module, const Disassembler& disassembler,
                                   uint64_t functionRva, uint64_t functionSize)
    {
        if (functionSize == 0)
        {
            return 0;
        }

        const auto functionBytes = module.ReadAt(functionRva, functionSize);
        if (functionBytes.empty())
        {
            return 0;
        }

        return ComputeStackFrameSizeInBody(disassembler, functionBytes, functionRva);
    }

} // namespace symfind
