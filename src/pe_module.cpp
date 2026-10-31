#include "symfind/pe_module.h"

#include <LIEF/PE.hpp>
#include <LIEF/PE/exceptions_info/RuntimeFunctionX64.hpp>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <set>
#include <spdlog/spdlog.h>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <unordered_set>

namespace symfind
{
    namespace
    {
        std::string ModuleBasename(std::string_view filePath)
        {
            const auto separatorPosition = filePath.find_last_of("/\\");
            return std::string(filePath.substr(
                separatorPosition == std::string_view::npos ? 0 : separatorPosition + 1));
        }

        std::string ExportModuleName(const LIEF::PE::Binary& peBinary)
        {
            const auto* exportDirectory = peBinary.get_export();
            return exportDirectory ? ModuleBasename(exportDirectory->name()) : std::string{};
        }

        struct FunctionRangeOwner
        {
                uint64_t rva;
                uint64_t size;
                uint64_t primary;
        };

        struct ExceptionFunctions
        {
                std::vector<FunctionBounds> functions;
                std::vector<FunctionRangeOwner> owners;
        };

        ExceptionFunctions CollectExceptionFunctions(const LIEF::PE::Binary& peBinary,
                                                     nonstd::span<const uint8_t> mappedImage,
                                                     const std::vector<Section>& sections)
        {
            // Keep the full runtimeFunction identity. LIEF's chained pointer is
            // resolved by BeginAddress alone; raw EndAddress/UnwindData must also
            // match before a continuation is assigned to another procedure.
            using RuntimeKey = std::tuple<uint32_t, uint32_t, uint32_t>;
            struct RuntimeNode
            {
                    uint32_t begin, end, unwind;
                    bool headerValid = false;
                    bool chained = false;
                    bool conflicted = false;
                    uint8_t frame = 0;
                    std::optional<RuntimeKey> parent;
            };

            const auto isReadableRange = [&](uint64_t rangeRva, uint64_t rangeSize)
            {
                return rangeRva <= mappedImage.size() && rangeSize <= mappedImage.size() - rangeRva;
            };
            const auto readUint32 = [&](uint64_t valueRva)
            {
                uint32_t decodedValue = 0;
                for (size_t byteIndex = 0; byteIndex < 4; ++byteIndex)
                {
                    decodedValue |= static_cast<uint32_t>(
                                        mappedImage[static_cast<size_t>(valueRva) + byteIndex])
                                    << (byteIndex * 8);
                }
                return decodedValue;
            };
            const auto isExecutableRange = [&](uint32_t rangeBeginRva, uint32_t rangeEndRva)
            {
                if (rangeEndRva <= rangeBeginRva ||
                    !isReadableRange(rangeBeginRva,
                                     static_cast<uint64_t>(rangeEndRva) - rangeBeginRva))
                {
                    return false;
                }
                return std::any_of(
                    sections.begin(), sections.end(),
                    [&](const Section& section)
                    {
                        return section.executable && rangeBeginRva >= section.virtualAddress &&
                               rangeBeginRva - section.virtualAddress <= section.virtualSize &&
                               static_cast<uint64_t>(rangeEndRva) - rangeBeginRva <=
                                   section.virtualSize - (rangeBeginRva - section.virtualAddress);
                    });
            };

            std::vector<RuntimeNode> runtimeNodes;
            std::map<RuntimeKey, size_t> nodeIndexByIdentity;
            for (const auto& exceptionInfo : peBinary.exceptions())
            {
                const auto* runtimeFunction = exceptionInfo.as<LIEF::PE::RuntimeFunctionX64>();
                if (!runtimeFunction ||
                    !isExecutableRange(runtimeFunction->rva_start(), runtimeFunction->rva_end()))
                {
                    continue;
                }
                const RuntimeKey runtimeIdentity{runtimeFunction->rva_start(),
                                                 runtimeFunction->rva_end(),
                                                 runtimeFunction->unwind_rva()};
                if (nodeIndexByIdentity.find(runtimeIdentity) != nodeIndexByIdentity.end())
                {
                    continue; // Identical duplicate metadata adds no additional code.
                }
                nodeIndexByIdentity.emplace(runtimeIdentity, runtimeNodes.size());
                RuntimeNode runtimeNode{runtimeFunction->rva_start(), runtimeFunction->rva_end(),
                                        runtimeFunction->unwind_rva()};
                if (isReadableRange(runtimeNode.unwind, 4))
                {
                    const auto unwindVersion = mappedImage[runtimeNode.unwind] & 7;
                    const auto unwindFlags = mappedImage[runtimeNode.unwind] >> 3;
                    const auto unwindCodeCount = mappedImage[runtimeNode.unwind + 2];
                    runtimeNode.frame = mappedImage[runtimeNode.unwind + 3];
                    runtimeNode.chained = (unwindFlags & 4) != 0;
                    const auto unwindPayloadRva = static_cast<uint64_t>(runtimeNode.unwind) + 4 +
                                                  ((unwindCodeCount + 1u) & ~1u) * 2;
                    runtimeNode.headerValid =
                        (unwindVersion == 1 || unwindVersion == 2) && (unwindFlags & ~7) == 0 &&
                        !(runtimeNode.chained && (unwindFlags & 3)) &&
                        isReadableRange(runtimeNode.unwind, unwindPayloadRva - runtimeNode.unwind);
                    if (runtimeNode.headerValid && runtimeNode.chained)
                    {
                        runtimeNode.headerValid = isReadableRange(unwindPayloadRva, 12);
                        if (runtimeNode.headerValid)
                        {
                            runtimeNode.parent = RuntimeKey{readUint32(unwindPayloadRva),
                                                            readUint32(unwindPayloadRva + 4),
                                                            readUint32(unwindPayloadRva + 8)};
                        }
                    }
                    else if (runtimeNode.headerValid && (unwindFlags & 3))
                    {
                        runtimeNode.headerValid = isReadableRange(unwindPayloadRva, 4);
                    }
                }
                runtimeNodes.push_back(std::move(runtimeNode));
            }

            // An overlapping runtime table cannot establish unique ownership.
            // Mark all affected nodes once, without quadratic work on malformed
            // tables, and keep their bounds independent rather than guessing.
            std::vector<size_t> orderedNodeIndices;
            orderedNodeIndices.reserve(runtimeNodes.size());
            for (size_t nodeIndex = 0; nodeIndex < runtimeNodes.size(); ++nodeIndex)
            {
                orderedNodeIndices.push_back(nodeIndex);
            }
            std::sort(orderedNodeIndices.begin(), orderedNodeIndices.end(),
                      [&](size_t leftNodeIndex, size_t rightNodeIndex)
                      {
                          return runtimeNodes[leftNodeIndex].begin <
                                 runtimeNodes[rightNodeIndex].begin;
                      });
            std::multimap<uint32_t, size_t> activeNodesByEnd;
            std::set<size_t> unmarkedActiveNodes;
            for (const auto nodeIndex : orderedNodeIndices)
            {
                while (!activeNodesByEnd.empty() &&
                       activeNodesByEnd.begin()->first <= runtimeNodes[nodeIndex].begin)
                {
                    unmarkedActiveNodes.erase(activeNodesByEnd.begin()->second);
                    activeNodesByEnd.erase(activeNodesByEnd.begin());
                }
                if (!activeNodesByEnd.empty())
                {
                    runtimeNodes[nodeIndex].conflicted = true;
                    for (const auto activeNodeIndex : unmarkedActiveNodes)
                    {
                        runtimeNodes[activeNodeIndex].conflicted = true;
                    }
                    unmarkedActiveNodes.clear();
                }
                else
                {
                    unmarkedActiveNodes.insert(nodeIndex);
                }
                activeNodesByEnd.emplace(runtimeNodes[nodeIndex].end, nodeIndex);
            }

            const auto primaryFor = [&](size_t initialNodeIndex)
            {
                size_t currentNodeIndex = initialNodeIndex;
                std::set<size_t> visitedNodeIndices;
                constexpr size_t maxChainDepth = 64;
                while (visitedNodeIndices.size() < maxChainDepth &&
                       visitedNodeIndices.insert(currentNodeIndex).second)
                {
                    const auto& runtimeNode = runtimeNodes[currentNodeIndex];
                    if (!runtimeNode.headerValid || runtimeNode.conflicted)
                    {
                        return initialNodeIndex;
                    }
                    if (!runtimeNode.chained)
                    {
                        return currentNodeIndex;
                    }
                    if (!runtimeNode.parent)
                    {
                        return initialNodeIndex;
                    }
                    const auto parentNodeIterator = nodeIndexByIdentity.find(*runtimeNode.parent);
                    if (parentNodeIterator == nodeIndexByIdentity.end() ||
                        runtimeNodes[parentNodeIterator->second].frame != runtimeNode.frame)
                    {
                        return initialNodeIndex;
                    }
                    currentNodeIndex = parentNodeIterator->second;
                }
                return initialNodeIndex; // Cycle, malformed parent, or unsupported depth.
            };

            std::map<size_t, FunctionBounds> functionBoundsByPrimary;
            ExceptionFunctions exceptionFunctions;
            for (size_t nodeIndex = 0; nodeIndex < runtimeNodes.size(); ++nodeIndex)
            {
                const auto primaryNodeIndex = primaryFor(nodeIndex);
                const auto& primaryNode = runtimeNodes[primaryNodeIndex];
                const auto functionBoundsIterator =
                    functionBoundsByPrimary
                        .try_emplace(primaryNodeIndex,
                                     FunctionBounds{primaryNode.begin,
                                                    static_cast<uint64_t>(primaryNode.end) -
                                                        primaryNode.begin,
                                                    {}})
                        .first;
                const auto& runtimeNode = runtimeNodes[nodeIndex];
                const FunctionRange ownedRange{
                    runtimeNode.begin, static_cast<uint64_t>(runtimeNode.end) - runtimeNode.begin};
                functionBoundsIterator->second.ranges.push_back(ownedRange);
                if (!runtimeNode.conflicted)
                {
                    exceptionFunctions.owners.push_back(
                        {ownedRange.rva, ownedRange.size, primaryNode.begin});
                }
            }
            for (auto& [primaryNodeIndex, functionBounds] : functionBoundsByPrimary)
            {
                std::sort(functionBounds.ranges.begin(), functionBounds.ranges.end(),
                          [](const FunctionRange& leftRange, const FunctionRange& rightRange)
                          {
                              return leftRange.rva < rightRange.rva;
                          });
                exceptionFunctions.functions.push_back(std::move(functionBounds));
            }
            std::sort(exceptionFunctions.functions.begin(), exceptionFunctions.functions.end(),
                      [](const FunctionBounds& leftFunction, const FunctionBounds& rightFunction)
                      {
                          return leftFunction.rva < rightFunction.rva;
                      });
            std::sort(exceptionFunctions.owners.begin(), exceptionFunctions.owners.end(),
                      [](const FunctionRangeOwner& leftOwner, const FunctionRangeOwner& rightOwner)
                      {
                          return leftOwner.rva < rightOwner.rva;
                      });
            return exceptionFunctions;
        }
    } // namespace

    struct PeModule::Impl
    {
            std::string fullPath;
            std::string moduleName;
            uint64_t imageBase = 0;
            std::vector<ExportEntry> exports;
            std::vector<Section> sections;
            std::vector<uint8_t> rawData;
            std::unordered_map<std::string, uint64_t> exportMap;
            std::unordered_set<uint64_t> exportRvas;
            std::vector<FunctionBounds> exceptionFunctions;
            std::vector<FunctionRangeOwner> functionRangeOwners;
    };

    static std::vector<uint8_t> MapImage(LIEF::PE::Binary& peBinary,
                                         nonstd::span<const uint8_t> peBytes)
    {
        // Find the highest virtual offset to size the buffer
        uint64_t mappedImageSize = 0;
        for (const auto& section : peBinary.sections())
        {
            const uint64_t sectionEndRva = section.virtual_address() + section.virtual_size();
            mappedImageSize = std::max(sectionEndRva, mappedImageSize);
        }
        mappedImageSize =
            LIEF::align(mappedImageSize, peBinary.optional_header().section_alignment());
        std::vector<uint8_t> mappedImage(mappedImageSize, 0);

        // Copy PE headers directly from raw bytes (no file IO)
        const size_t headersSize = peBinary.sizeof_headers();
        const size_t headerCopySize = std::min(headersSize, peBytes.size());
        std::memcpy(mappedImage.data(), peBytes.data(), headerCopySize);

        // Copy each section's content to its virtualAddress - unchanged
        for (const auto& section : peBinary.sections())
        {
            const auto sectionBytes = section.content();
            const auto sectionCopySize =
                std::min<size_t>(sectionBytes.size(), section.virtual_size());
            std::memcpy(mappedImage.data() + section.virtual_address(), sectionBytes.data(),
                        sectionCopySize);
        }
        return mappedImage;
    }

    static std::vector<uint8_t> MapImage(LIEF::PE::Binary& peBinary, const std::string& filePath)
    {
        // Find the highest virtual offset to size the buffer
        uint64_t mappedImageSize = 0;
        for (const auto& section : peBinary.sections())
        {
            const uint64_t sectionEndRva = section.virtual_address() + section.virtual_size();
            mappedImageSize = std::max(sectionEndRva, mappedImageSize);
        }

        // Round up to section alignment to be safe
        mappedImageSize =
            LIEF::align(mappedImageSize, peBinary.optional_header().section_alignment());

        std::vector<uint8_t> mappedImage(mappedImageSize, 0);

        // Copy the PE Headers from file to memory buffer
        {
            std::ifstream inputFile(filePath, std::ios::binary);
            if (inputFile)
            {
                const size_t headersSize = peBinary.sizeof_headers();
                inputFile.read(reinterpret_cast<char*>(mappedImage.data()),
                               static_cast<std::streamsize>(headersSize));
            }
        }

        // Copy each section's raw bytes to its virtualAddress offset
        for (const auto& section : peBinary.sections())
        {
            const auto sectionBytes = section.content(); // LIEF's own span type.
            const auto sectionCopySize =
                std::min<size_t>(sectionBytes.size(), section.virtual_size());
            std::memcpy(mappedImage.data() + section.virtual_address(), sectionBytes.data(),
                        sectionCopySize);
            // Bytes beyond rawSize up to virtualSize remain zero - already initialized
        }

        return mappedImage;
    }

    std::optional<PeModule> PeModule::FromFile(const std::string& filePath)
    {
        auto parserConfig = LIEF::PE::ParserConfig::default_conf();
        parserConfig.parse_exceptions = true; // should be done if we want to extract information
                                              // about function from exception directory
        parserConfig.parse_arm64x_binary = false; // should not be used (here is forced explicitly)
                                                  // because the project is not about arm
        parserConfig.parse_signature =
            false; // have some bugs during parsing signature in ntdll.dll of win11

        auto peBinary = LIEF::PE::Parser::parse(filePath, parserConfig);
        if (!peBinary)
        {
            SPDLOG_ERROR("Failed to parse PE file: {}", filePath);
            return std::nullopt;
        }

        PeModule peModule;
        peModule.m_impl = std::make_shared<Impl>();
        peModule.m_impl->fullPath = std::filesystem::canonical(filePath).string();
        peModule.m_impl->moduleName = ExportModuleName(*peBinary);
        if (peModule.m_impl->moduleName.empty())
        {
            peModule.m_impl->moduleName = ModuleBasename(filePath);
        }
        peModule.m_impl->imageBase = peBinary->imagebase();

        // Collect exports
        if (peBinary->has_exports())
        {
            for (const auto& peExport : peBinary->get_export()->entries())
            {
                ExportEntry exportEntry;
                exportEntry.name = peExport.name();
                exportEntry.rva = peExport.address();
                exportEntry.ordinal = peExport.ordinal();
                peModule.m_impl->exports.push_back(exportEntry);
                peModule.m_impl->exportMap[exportEntry.name] = exportEntry.rva;
                peModule.m_impl->exportRvas.insert(exportEntry.rva);
            }
        }

        // Collect sections
        for (const auto& peSection : peBinary->sections())
        {
            Section section;
            section.name = peSection.name();
            section.virtualAddress = peSection.virtual_address();
            section.virtualSize = peSection.virtual_size();
            section.rawOffset = peSection.offset();
            section.rawSize = peSection.size();

            const auto sectionCharacteristics = peSection.characteristics();
            section.executable =
                (sectionCharacteristics &
                 static_cast<uint64_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_EXECUTE)) != 0;
            section.readable =
                (sectionCharacteristics &
                 static_cast<uint64_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_READ)) != 0;
            section.writable =
                (sectionCharacteristics &
                 static_cast<uint64_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_WRITE)) != 0;

            peModule.m_impl->sections.push_back(section);
        }

        // Store raw content (still not clear what to do with overlay, let's keep it for now as is)
        auto overlayBytes = peBinary->overlay();
        peModule.m_impl->rawData = MapImage(*peBinary, peModule.m_impl->fullPath);

        auto exceptionFunctions = CollectExceptionFunctions(*peBinary, peModule.m_impl->rawData,
                                                            peModule.m_impl->sections);
        peModule.m_impl->exceptionFunctions = std::move(exceptionFunctions.functions);
        peModule.m_impl->functionRangeOwners = std::move(exceptionFunctions.owners);

        SPDLOG_INFO("Loaded PE module '{}': base=0x{:X}, {} exports, {} sections",
                    peModule.m_impl->fullPath, peModule.m_impl->imageBase,
                    peModule.m_impl->exports.size(), peModule.m_impl->sections.size());

        return peModule;
    }

    std::optional<PeModule> PeModule::FromMemory(nonstd::span<const uint8_t> peBytes,
                                                 uint64_t baseAddress)
    {
        auto parserConfig = LIEF::PE::ParserConfig::default_conf();
        parserConfig.parse_exceptions = true; // should be done if we want to extract information
                                              // about function from exception directory
        parserConfig.parse_arm64x_binary = false; // should not be used (here is forced explicitly)
                                                  // because the project is not about arm
        parserConfig.parse_signature =
            false; // have some bugs during parsing signature in ntdll.dll of win11

        auto peBinary = LIEF::PE::Parser::parse(peBytes.data(), peBytes.size(), parserConfig);
        if (!peBinary)
        {
            SPDLOG_ERROR("Failed to parse PE from memory at base 0x{:X}, size={}", baseAddress,
                         peBytes.size());
            return std::nullopt;
        }

        PeModule peModule;
        peModule.m_impl = std::make_shared<Impl>();
        peModule.m_impl->moduleName = ExportModuleName(*peBinary);
        peModule.m_impl->imageBase = baseAddress;

        // Collect exports
        if (peBinary->has_exports())
        {
            for (const auto& peExport : peBinary->get_export()->entries())
            {
                ExportEntry exportEntry;
                exportEntry.name = peExport.name();
                exportEntry.rva = peExport.address();
                exportEntry.ordinal = peExport.ordinal();
                peModule.m_impl->exports.push_back(exportEntry);
                peModule.m_impl->exportMap[exportEntry.name] = exportEntry.rva;
                peModule.m_impl->exportRvas.insert(exportEntry.rva);
            }
        }

        // Collect sections
        for (const auto& peSection : peBinary->sections())
        {
            Section section;
            section.name = peSection.name();
            section.virtualAddress = peSection.virtual_address();
            section.virtualSize = peSection.virtual_size();
            section.rawOffset = peSection.offset();
            section.rawSize = peSection.size();

            const auto sectionCharacteristics = peSection.characteristics();
            section.executable =
                (sectionCharacteristics &
                 static_cast<uint64_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_EXECUTE)) != 0;
            section.readable =
                (sectionCharacteristics &
                 static_cast<uint64_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_READ)) != 0;
            section.writable =
                (sectionCharacteristics &
                 static_cast<uint64_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_WRITE)) != 0;

            peModule.m_impl->sections.push_back(section);
        }

        // Store raw content (still not clear what to do with overlay, let's keep it for now as is)
        auto overlayBytes = peBinary->overlay();
        peModule.m_impl->rawData = MapImage(*peBinary, peBytes);

        auto exceptionFunctions = CollectExceptionFunctions(*peBinary, peModule.m_impl->rawData,
                                                            peModule.m_impl->sections);
        peModule.m_impl->exceptionFunctions = std::move(exceptionFunctions.functions);
        peModule.m_impl->functionRangeOwners = std::move(exceptionFunctions.owners);

        SPDLOG_INFO("Loaded PE module: base=0x{:X}, {} exports, {} sections",
                    peModule.m_impl->imageBase, peModule.m_impl->exports.size(),
                    peModule.m_impl->sections.size());

        return peModule;
    }

    const std::string& PeModule::Name() const
    {
        return m_impl->moduleName;
    }

    uint64_t PeModule::ImageBase() const
    {
        return m_impl->imageBase;
    }

    const std::vector<ExportEntry>& PeModule::Exports() const
    {
        return m_impl->exports;
    }

    const std::vector<Section>& PeModule::Sections() const
    {
        return m_impl->sections;
    }

    bool PeModule::IsExported(uint64_t symbolRva) const
    {
        return m_impl->exportRvas.find(symbolRva) != m_impl->exportRvas.end();
    }

    std::optional<uint64_t> PeModule::ExportRva(const std::string& exportName) const
    {
        auto exportIterator = m_impl->exportMap.find(exportName);
        if (exportIterator != m_impl->exportMap.end())
        {
            return exportIterator->second;
        }
        return std::nullopt;
    }

    nonstd::span<const uint8_t> PeModule::ReadAt(uint64_t startRva, size_t byteCount) const
    {
        if (startRva > m_impl->rawData.size() || byteCount > m_impl->rawData.size() - startRva)
        {
            return {};
        }

        return {m_impl->rawData.data() + startRva, byteCount};
    }

    nonstd::span<const uint8_t> PeModule::RawImage() const
    {
        return m_impl->rawData;
    }

    const std::vector<FunctionBounds>& PeModule::ExceptionFunctions() const
    {
        return m_impl->exceptionFunctions;
    }

    std::optional<uint64_t> PeModule::CanonicalFunctionRva(uint64_t instructionRva) const
    {
        const auto& ownedRanges = m_impl->functionRangeOwners;
        const auto nextRangeIterator =
            std::upper_bound(ownedRanges.begin(), ownedRanges.end(), instructionRva,
                             [](uint64_t requestedRva, const FunctionRangeOwner& ownedRange)
                             {
                                 return requestedRva < ownedRange.rva;
                             });
        if (nextRangeIterator == ownedRanges.begin())
        {
            return std::nullopt;
        }
        const auto& ownedRange = *std::prev(nextRangeIterator);
        if (instructionRva - ownedRange.rva >= ownedRange.size)
        {
            return std::nullopt;
        }
        return ownedRange.primary;
    }

} // namespace symfind
