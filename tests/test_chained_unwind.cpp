#include "symfind/analysis_db.h"
#include "symfind/dsl_matcher.h"
#include "symfind/dsl_parser.h"
#include "symfind/function_finder.h"
#include "symfind/pe_module.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <climits>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

#include <Windows.h>

namespace
{
    using Bytes = std::vector<uint8_t>;
    constexpr uint64_t preferredImageBase = 0x140000000;
    constexpr uint32_t primaryFunctionRva = 0x1000;
    constexpr uint32_t independentFunctionRva = 0x1100;
    constexpr uint32_t continuationRva = 0x1200;
    constexpr uint32_t targetFunctionRva = 0x1300;
    constexpr uint32_t gapCalleeRva = 0x1340;
    constexpr uint32_t anchorFunctionRva = 0x1380;
    constexpr uint32_t primaryDataRva = 0x4120;
    constexpr uint32_t independentDataRva = 0x4110;
    constexpr size_t optionalHeaderOffset = 0x98;

    struct SectionFixture
    {
            std::string_view name;
            uint32_t rva, raw, size, flags;
    };

    constexpr uint32_t fileAlignment = 0x200;
    constexpr uint32_t sectionAlignment = 0x1000;
    constexpr uint32_t headersSize = 2 * fileAlignment;
    constexpr uint32_t initializedDataFlags = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
    constexpr SectionFixture textSection{".text", sectionAlignment, headersSize, 2 * fileAlignment,
                                         IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE |
                                             IMAGE_SCN_MEM_READ};
    constexpr SectionFixture pdataSection{".pdata", textSection.rva + sectionAlignment,
                                          textSection.raw + textSection.size, fileAlignment,
                                          initializedDataFlags};
    constexpr SectionFixture xdataSection{".xdata", pdataSection.rva + sectionAlignment,
                                          pdataSection.raw + pdataSection.size, fileAlignment,
                                          initializedDataFlags};
    constexpr SectionFixture edataSection{".edata", xdataSection.rva + sectionAlignment,
                                          xdataSection.raw + xdataSection.size, fileAlignment,
                                          initializedDataFlags};
    constexpr std::array sectionFixtures{textSection, pdataSection, xdataSection, edataSection};

    constexpr uint32_t relativeBranchSize = sizeof(uint8_t) + sizeof(int32_t);
    constexpr uint8_t rexWPrefix = 0x48;
    constexpr uint8_t leaOpcode = 0x8d;
    constexpr uint8_t modrmRaxRipRelative = 0x05; // mod=00, reg=RAX, r/m=RIP+disp32.
    constexpr std::array leaRaxRipPrefix{rexWPrefix, leaOpcode, modrmRaxRipRelative};
    constexpr uint32_t ripRelativeLeaSize = leaRaxRipPrefix.size() + sizeof(int32_t);

    void Put(Bytes& peBytes, size_t writeOffset, uint64_t valueToWrite, size_t valueSize)
    {
        if (writeOffset > peBytes.size() || valueSize > peBytes.size() - writeOffset ||
            valueSize > sizeof(valueToWrite))
        {
            throw std::runtime_error("Synthetic PE write is out of bounds");
        }

        for (size_t byteIndex = 0; byteIndex < valueSize; ++byteIndex)
        {
            peBytes[writeOffset + byteIndex] =
                static_cast<uint8_t>(valueToWrite >> (byteIndex * CHAR_BIT));
        }
    }

    void PutText(Bytes& peBytes, size_t writeOffset, std::string_view textValue)
    {
        if (writeOffset > peBytes.size() || textValue.size() > peBytes.size() - writeOffset)
        {
            throw std::runtime_error("Synthetic PE text is out of bounds");
        }

        std::copy(textValue.begin(), textValue.end(),
                  peBytes.begin() + static_cast<uint32_t>(writeOffset));
    }

    auto FileOffset(uint32_t targetRva)
    {
        for (const auto& section : sectionFixtures)
        {
            if (targetRva >= section.rva && targetRva - section.rva < section.size)
            {
                return section.raw + targetRva - section.rva;
            }
        }

        throw std::runtime_error("Synthetic PE RVA is outside a section");
    }

    void RuntimeFunction(Bytes& peBytes, size_t runtimeEntryOffset, uint32_t functionBeginRva,
                         uint32_t functionEndRva, uint32_t unwindInfoRva)
    {
        Put(peBytes, runtimeEntryOffset + offsetof(IMAGE_RUNTIME_FUNCTION_ENTRY, BeginAddress),
            functionBeginRva, sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY::BeginAddress));
        Put(peBytes, runtimeEntryOffset + offsetof(IMAGE_RUNTIME_FUNCTION_ENTRY, EndAddress),
            functionEndRva, sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY::EndAddress));
        Put(peBytes, runtimeEntryOffset + offsetof(IMAGE_RUNTIME_FUNCTION_ENTRY, UnwindInfoAddress),
            unwindInfoRva, sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY::UnwindInfoAddress));
    }

    void DirectBranch(Bytes& peBytes, uint32_t instructionRva, uint32_t branchTargetRva,
                      uint8_t branchOpcode)
    {
        const auto instructionOffset = FileOffset(instructionRva);
        peBytes[instructionOffset] = branchOpcode;
        const auto relativeDisplacement =
            static_cast<int64_t>(branchTargetRva) - instructionRva - relativeBranchSize;
        Put(peBytes, instructionOffset + sizeof(branchOpcode),
            static_cast<uint32_t>(relativeDisplacement), sizeof(int32_t));
    }

    void LeaData(Bytes& peBytes, uint32_t instructionRva, uint32_t dataRva)
    {
        const auto instructionOffset = FileOffset(instructionRva);
        std::copy(leaRaxRipPrefix.begin(), leaRaxRipPrefix.end(),
                  peBytes.begin() + instructionOffset);
        const auto relativeDisplacement =
            static_cast<int64_t>(dataRva) - instructionRva - ripRelativeLeaSize;
        Put(peBytes, instructionOffset + leaRaxRipPrefix.size(),
            static_cast<uint32_t>(relativeDisplacement), sizeof(int32_t));
    }

    // Raw PE bytes, never loaded as an executable. The gap contains a separate
    // function so widening the primary span would produce a false call edge.
    Bytes MakeChainedPe()
    {
        // The SDK exposes runtimeFunction and its flags, but not this x64 header.
        struct UnwindInfoHeader
        {
                uint8_t versionAndFlags, prologSize, codeCount, frameRegisterAndOffset;
        };
        constexpr uint8_t unwindVersion = 1;
        constexpr unsigned unwindVersionBits = 3;
        constexpr uint32_t unwindSlotSize =
            sizeof(UnwindInfoHeader) + sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
        constexpr uint32_t primaryUnwindInfoRva = xdataSection.rva;
        constexpr uint32_t continuationUnwindInfoRva = primaryUnwindInfoRva + 2 * unwindSlotSize;
        constexpr uint32_t standardFunctionSize = 0x10;
        struct FunctionFixture
        {
                uint32_t begin, size, unwind;
        };
        constexpr std::array functionFixtures{
            FunctionFixture{primaryFunctionRva, standardFunctionSize, primaryUnwindInfoRva},
            FunctionFixture{independentFunctionRva, 2 * standardFunctionSize,
                            primaryUnwindInfoRva + unwindSlotSize},
            FunctionFixture{continuationRva, standardFunctionSize, continuationUnwindInfoRva},
            FunctionFixture{targetFunctionRva, standardFunctionSize,
                            continuationUnwindInfoRva + 2 * unwindSlotSize},
            FunctionFixture{gapCalleeRva, standardFunctionSize,
                            continuationUnwindInfoRva + 3 * unwindSlotSize},
            FunctionFixture{anchorFunctionRva, standardFunctionSize,
                            continuationUnwindInfoRva + 4 * unwindSlotSize},
        };

        // These placements are part of the fixture: tests below patch the tables.
        constexpr uint32_t exportDirectorySize = 0x180;
        constexpr uint32_t exportFunctionsRva = edataSection.rva + 0x40;
        constexpr uint32_t moduleNameRva = edataSection.rva + 0x80;
        constexpr uint32_t loaderNameRva = edataSection.rva + 0x98;
        constexpr uint32_t anchorNameRva = edataSection.rva + 0xa8;
        constexpr std::array<DWORD, 2> exportedFunctionRvas{primaryFunctionRva, anchorFunctionRva};
        constexpr std::array<DWORD, exportedFunctionRvas.size()> exportedNameRvas{anchorNameRva,
                                                                                  loaderNameRva};
        constexpr std::array<WORD, exportedNameRvas.size()> exportedNameOrdinals{1, 0};
        constexpr uint32_t exportNamesRva = exportFunctionsRva + sizeof(exportedFunctionRvas);
        constexpr uint32_t exportOrdinalsRva = exportNamesRva + sizeof(exportedNameRvas);

        Bytes peBytes(edataSection.raw + edataSection.size);
        const auto writeStructure = [&peBytes](size_t structureOffset, const auto& peStructure)
        {
            PutText(peBytes, structureOffset,
                    {reinterpret_cast<const char*>(&peStructure), sizeof(peStructure)});
        };

        constexpr size_t ntHeadersOffset =
            optionalHeaderOffset - offsetof(IMAGE_NT_HEADERS64, OptionalHeader);
        IMAGE_DOS_HEADER dosHeader{};
        dosHeader.e_magic = IMAGE_DOS_SIGNATURE;
        dosHeader.e_lfanew = static_cast<LONG>(ntHeadersOffset);
        writeStructure(0, dosHeader);

        IMAGE_NT_HEADERS64 ntHeaders{};
        ntHeaders.Signature = IMAGE_NT_SIGNATURE;
        ntHeaders.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
        ntHeaders.FileHeader.NumberOfSections = static_cast<WORD>(sectionFixtures.size());
        ntHeaders.FileHeader.TimeDateStamp = 1;
        ntHeaders.FileHeader.SizeOfOptionalHeader = sizeof(ntHeaders.OptionalHeader);
        ntHeaders.FileHeader.Characteristics =
            IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE_DLL;
        auto& optionalHeader = ntHeaders.OptionalHeader;
        optionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        optionalHeader.SizeOfCode = textSection.size;
        optionalHeader.SizeOfInitializedData =
            pdataSection.size + xdataSection.size + edataSection.size;
        optionalHeader.AddressOfEntryPoint = primaryFunctionRva;
        optionalHeader.BaseOfCode = textSection.rva;
        optionalHeader.ImageBase = preferredImageBase;
        optionalHeader.SectionAlignment = sectionAlignment;
        optionalHeader.FileAlignment = fileAlignment;
        optionalHeader.MajorOperatingSystemVersion = 6;
        optionalHeader.MajorSubsystemVersion = optionalHeader.MajorOperatingSystemVersion;
        optionalHeader.SizeOfImage = edataSection.rva + sectionAlignment;
        optionalHeader.SizeOfHeaders = headersSize;
        optionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
        optionalHeader.DllCharacteristics =
            IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA | IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
            IMAGE_DLLCHARACTERISTICS_NX_COMPAT | IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE;
        optionalHeader.SizeOfStackReserve = optionalHeader.SizeOfHeapReserve =
            static_cast<ULONGLONG>(1024 * 1024);
        optionalHeader.SizeOfStackCommit = optionalHeader.SizeOfHeapCommit = sectionAlignment;
        optionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] = {edataSection.rva,
                                                                      exportDirectorySize};
        optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION] = {
            pdataSection.rva,
            static_cast<DWORD>(functionFixtures.size() * sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY))};
        writeStructure(ntHeadersOffset, ntHeaders);

        constexpr auto sectionTableOffset = ntHeadersOffset + sizeof(ntHeaders);
        for (size_t sectionIndex = 0; sectionIndex < sectionFixtures.size(); ++sectionIndex)
        {
            IMAGE_SECTION_HEADER sectionHeader{};
            std::copy(sectionFixtures[sectionIndex].name.begin(),
                      sectionFixtures[sectionIndex].name.end(), sectionHeader.Name);
            sectionHeader.Misc.VirtualSize = sectionFixtures[sectionIndex].size;
            sectionHeader.VirtualAddress = sectionFixtures[sectionIndex].rva;
            sectionHeader.SizeOfRawData = sectionFixtures[sectionIndex].size;
            sectionHeader.PointerToRawData = sectionFixtures[sectionIndex].raw;
            sectionHeader.Characteristics = sectionFixtures[sectionIndex].flags;
            writeStructure(sectionTableOffset + sectionIndex * sizeof(sectionHeader),
                           sectionHeader);
        }

        constexpr uint8_t int3Opcode = 0xcc;
        constexpr uint8_t jmpRel32Opcode = 0xe9;
        constexpr uint8_t callRel32Opcode = 0xe8;
        constexpr uint8_t retOpcode = 0xc3;
        std::fill(peBytes.begin() + textSection.raw,
                  peBytes.begin() + textSection.raw + textSection.size, int3Opcode);
        DirectBranch(peBytes, primaryFunctionRva, continuationRva,
                     jmpRel32Opcode); // JMP is not a call.
        DirectBranch(peBytes, independentFunctionRva, gapCalleeRva, callRel32Opcode);
        DirectBranch(peBytes, independentFunctionRva + relativeBranchSize, continuationRva,
                     callRel32Opcode);
        LeaData(peBytes, independentFunctionRva + 2 * relativeBranchSize, independentDataRva);
        peBytes[FileOffset(independentFunctionRva + 2 * relativeBranchSize + ripRelativeLeaSize)] =
            retOpcode;
        DirectBranch(peBytes, continuationRva, targetFunctionRva, callRel32Opcode);
        LeaData(peBytes, continuationRva + relativeBranchSize, primaryDataRva);
        peBytes[FileOffset(continuationRva + relativeBranchSize + ripRelativeLeaSize)] = retOpcode;
        DirectBranch(peBytes, targetFunctionRva, anchorFunctionRva, callRel32Opcode);
        peBytes[FileOffset(targetFunctionRva + relativeBranchSize)] = retOpcode;
        peBytes[FileOffset(gapCalleeRva)] = retOpcode;
        peBytes[FileOffset(anchorFunctionRva)] = retOpcode;

        constexpr UnwindInfoHeader leafUnwindHeader{unwindVersion, 0, 0, 0};
        for (size_t functionIndex = 0; functionIndex < functionFixtures.size(); ++functionIndex)
        {
            const auto& functionFixture = functionFixtures[functionIndex];
            RuntimeFunction(peBytes,
                            pdataSection.raw + functionIndex * sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY),
                            functionFixture.begin, functionFixture.begin + functionFixture.size,
                            functionFixture.unwind);
            writeStructure(FileOffset(functionFixture.unwind), leafUnwindHeader);
        }
        constexpr UnwindInfoHeader chainedUnwindHeader{
            unwindVersion | (UNW_FLAG_CHAININFO << unwindVersionBits), 0, 0, 0};
        writeStructure(FileOffset(continuationUnwindInfoRva), chainedUnwindHeader);
        RuntimeFunction(peBytes, FileOffset(continuationUnwindInfoRva) + sizeof(UnwindInfoHeader),
                        primaryFunctionRva, primaryFunctionRva + standardFunctionSize,
                        primaryUnwindInfoRva);

        IMAGE_EXPORT_DIRECTORY exportDirectory{};
        exportDirectory.Name = moduleNameRva;
        exportDirectory.Base = 1;
        exportDirectory.NumberOfFunctions = static_cast<DWORD>(exportedFunctionRvas.size());
        exportDirectory.NumberOfNames = static_cast<DWORD>(exportedNameRvas.size());
        exportDirectory.AddressOfFunctions = exportFunctionsRva;
        exportDirectory.AddressOfNames = exportNamesRva;
        exportDirectory.AddressOfNameOrdinals = exportOrdinalsRva;
        writeStructure(FileOffset(edataSection.rva), exportDirectory);
        writeStructure(FileOffset(exportFunctionsRva), exportedFunctionRvas);
        writeStructure(FileOffset(exportNamesRva), exportedNameRvas);
        writeStructure(FileOffset(exportOrdinalsRva), exportedNameOrdinals);
        PutText(peBytes, FileOffset(moduleNameRva), "chain-fixture.dll");
        PutText(peBytes, FileOffset(loaderNameRva), "TestLoader");
        PutText(peBytes, FileOffset(anchorNameRva), "TestAnchor");
        return peBytes;
    }

    const symfind::FunctionBounds* BoundsAt(const symfind::PeModule& peModule, uint64_t targetRva)
    {
        const auto& exceptionFunctions = peModule.ExceptionFunctions();
        const auto matchingFunction =
            std::find_if(exceptionFunctions.begin(), exceptionFunctions.end(),
                         [targetRva](const auto& candidateFunction)
                         {
                             return candidateFunction.rva == targetRva;
                         });
        return matchingFunction == exceptionFunctions.end() ? nullptr : &*matchingFunction;
    }

    std::vector<std::pair<uint64_t, uint64_t>> RangesOf(
        const std::vector<symfind::FunctionRange>& functionRanges)
    {
        std::vector<std::pair<uint64_t, uint64_t>> rangeBounds;
        rangeBounds.reserve(functionRanges.size());
        for (const auto& functionRange : functionRanges)
        {
            rangeBounds.emplace_back(functionRange.rva, functionRange.size);
        }
        return rangeBounds;
    }

    bool Contains(const std::vector<uint64_t>& candidateRvas, uint64_t targetRva)
    {
        return std::find(candidateRvas.begin(), candidateRvas.end(), targetRva) !=
               candidateRvas.end();
    }

    class TemporaryPe
    {
        public:
            explicit TemporaryPe(const Bytes& peBytes)
            {
                static std::atomic<uint64_t> temporaryFileSequence{0};
                const auto timestampTicks =
                    std::chrono::steady_clock::now().time_since_epoch().count();
                filePath = std::filesystem::temp_directory_path() /
                           ("symfind-chain-" + std::to_string(timestampTicks) + "-" +
                            std::to_string(temporaryFileSequence.fetch_add(1)) + ".dll");
                if (std::filesystem::exists(filePath))
                {
                    throw std::runtime_error("Synthetic PE temporary path already exists");
                }

                std::ofstream outputFile(filePath, std::ios::binary | std::ios::trunc);
                outputFile.write(reinterpret_cast<const char*>(peBytes.data()),
                                 static_cast<std::streamsize>(peBytes.size()));
                if (!outputFile)
                {
                    throw std::runtime_error("Cannot save synthetic PE fixture");
                }
            }

            ~TemporaryPe()
            {
                std::error_code removeError;
                std::filesystem::remove(filePath, removeError);
            }

            TemporaryPe(const TemporaryPe&) = delete;
            TemporaryPe& operator=(const TemporaryPe&) = delete;

            std::filesystem::path filePath;
    };

    TEST(ChainedUnwind, MemoryLoaderKeepsSparseRangesAndCanonicalOwner)
    {
        const auto peModule = symfind::PeModule::FromMemory(MakeChainedPe(), preferredImageBase);
        ASSERT_TRUE(peModule.has_value());
        ASSERT_EQ(peModule->ExceptionFunctions().size(), 5);
        const auto* primaryFunctionBounds = BoundsAt(*peModule, primaryFunctionRva);
        ASSERT_NE(primaryFunctionBounds, nullptr);
        EXPECT_EQ(primaryFunctionBounds->size, 0x10);
        EXPECT_EQ(RangesOf(primaryFunctionBounds->ranges),
                  (std::vector<std::pair<uint64_t, uint64_t>>{{primaryFunctionRva, 0x10},
                                                              {continuationRva, 0x10}}));
        EXPECT_EQ(BoundsAt(*peModule, continuationRva), nullptr);
        EXPECT_NE(BoundsAt(*peModule, independentFunctionRva), nullptr);
        EXPECT_EQ(peModule->CanonicalFunctionRva(primaryFunctionRva + 5), primaryFunctionRva);
        EXPECT_EQ(peModule->CanonicalFunctionRva(continuationRva), primaryFunctionRva);
        EXPECT_EQ(peModule->CanonicalFunctionRva(continuationRva + 5), primaryFunctionRva);
        EXPECT_EQ(peModule->CanonicalFunctionRva(independentFunctionRva + 5),
                  independentFunctionRva);
        EXPECT_FALSE(peModule->CanonicalFunctionRva(continuationRva + 0x10).has_value());
        EXPECT_FALSE(peModule->CanonicalFunctionRva(0x1150).has_value());
    }

    TEST(ChainedUnwind, FileAndMemoryLoadersProduceSameOwnership)
    {
        const auto peBytes = MakeChainedPe();
        const TemporaryPe temporaryPeFile(peBytes);
        const auto memoryModule = symfind::PeModule::FromMemory(peBytes, preferredImageBase);
        const auto fileModule = symfind::PeModule::FromFile(temporaryPeFile.filePath.string());
        ASSERT_TRUE(memoryModule.has_value());
        ASSERT_TRUE(fileModule.has_value());
        EXPECT_EQ(memoryModule->Name(), "chain-fixture.dll");
        EXPECT_EQ(fileModule->Name(), memoryModule->Name());
        EXPECT_NE(fileModule->Name(), temporaryPeFile.filePath.filename().string());
        ASSERT_EQ(memoryModule->ExceptionFunctions().size(),
                  fileModule->ExceptionFunctions().size());
        for (const auto& expectedFunctionBounds : memoryModule->ExceptionFunctions())
        {
            const auto* actualFunctionBounds = BoundsAt(*fileModule, expectedFunctionBounds.rva);
            ASSERT_NE(actualFunctionBounds, nullptr);
            EXPECT_EQ(actualFunctionBounds->size, expectedFunctionBounds.size);
            EXPECT_EQ(RangesOf(actualFunctionBounds->ranges),
                      RangesOf(expectedFunctionBounds.ranges));
        }
        EXPECT_EQ(fileModule->CanonicalFunctionRva(continuationRva + 5), primaryFunctionRva);
        const auto analysisDatabase = symfind::AnalysisDb::Analyze(*fileModule);
        const auto* loaderFunction = analysisDatabase.FunctionByName("TestLoader");
        ASSERT_NE(loaderFunction, nullptr);
        EXPECT_EQ(loaderFunction->callees, (std::vector<uint64_t>{targetFunctionRva}));
    }

    TEST(ChainedUnwind, ModuleIdentityStripsEitherExportPathSeparator)
    {
        struct IdentityCase
        {
                std::string_view embeddedName;
                std::string_view basename;
        };
        const std::array identityCases{
            IdentityCase{R"(C:\x\one.dll)", "one.dll"},
            IdentityCase{"dir/two.dll", "two.dll"},
        };
        for (const auto& identityCase : identityCases)
        {
            SCOPED_TRACE(identityCase.embeddedName);
            auto peBytes = MakeChainedPe();
            IMAGE_EXPORT_DIRECTORY exportDirectory{};
            std::memcpy(&exportDirectory, peBytes.data() + edataSection.raw,
                        sizeof(exportDirectory));
            const auto moduleNameOffset = FileOffset(exportDirectory.Name);
            ASSERT_LE(identityCase.embeddedName.size(),
                      std::string_view("chain-fixture.dll").size());
            PutText(peBytes, moduleNameOffset, identityCase.embeddedName);
            peBytes[moduleNameOffset + identityCase.embeddedName.size()] = 0;

            const TemporaryPe temporaryPeFile(peBytes);
            const auto memoryModule = symfind::PeModule::FromMemory(peBytes, preferredImageBase);
            const auto fileModule = symfind::PeModule::FromFile(temporaryPeFile.filePath.string());
            ASSERT_TRUE(memoryModule.has_value());
            ASSERT_TRUE(fileModule.has_value());
            EXPECT_EQ(memoryModule->Name(), identityCase.basename);
            EXPECT_EQ(fileModule->Name(), identityCase.basename);
        }
    }

    TEST(ChainedUnwind, ModuleIdentityDoesNotRequireNamedFunctionExports)
    {
        auto peBytes = MakeChainedPe();
        Put(peBytes, edataSection.raw + offsetof(IMAGE_EXPORT_DIRECTORY, NumberOfNames), 0,
            sizeof(IMAGE_EXPORT_DIRECTORY::NumberOfNames));
        const auto memoryModule = symfind::PeModule::FromMemory(peBytes, preferredImageBase);
        ASSERT_TRUE(memoryModule.has_value());
        EXPECT_EQ(memoryModule->Name(), "chain-fixture.dll");
    }

    TEST(ChainedUnwind, MissingExportIdentityUsesOnlyFileBasename)
    {
        for (const bool exportDirectoryPresent : {true, false})
        {
            SCOPED_TRACE(exportDirectoryPresent);
            auto peBytes = MakeChainedPe();
            if (exportDirectoryPresent)
            {
                IMAGE_EXPORT_DIRECTORY exportDirectory{};
                std::memcpy(&exportDirectory, peBytes.data() + edataSection.raw,
                            sizeof(exportDirectory));
                peBytes[FileOffset(exportDirectory.Name)] = 0;
                Put(peBytes, edataSection.raw + offsetof(IMAGE_EXPORT_DIRECTORY, NumberOfNames), 0,
                    sizeof(IMAGE_EXPORT_DIRECTORY::NumberOfNames));
            }
            else
            {
                constexpr auto exportDirectoryOffset =
                    optionalHeaderOffset + offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory) +
                    IMAGE_DIRECTORY_ENTRY_EXPORT * sizeof(IMAGE_DATA_DIRECTORY);
                Put(peBytes, exportDirectoryOffset, 0, sizeof(IMAGE_DATA_DIRECTORY));
            }

            const TemporaryPe temporaryPeFile(peBytes);
            const auto memoryModule = symfind::PeModule::FromMemory(peBytes, preferredImageBase);
            const auto fileModule = symfind::PeModule::FromFile(temporaryPeFile.filePath.string());
            ASSERT_TRUE(memoryModule.has_value());
            ASSERT_TRUE(fileModule.has_value());
            EXPECT_TRUE(memoryModule->Name().empty());
            EXPECT_EQ(fileModule->Name(), temporaryPeFile.filePath.filename().string());
        }
    }

    TEST(ChainedUnwind, ContinuationCallRepairsCallerEdgeWithoutClaimingGap)
    {
        const auto peModule = symfind::PeModule::FromMemory(MakeChainedPe(), preferredImageBase);
        ASSERT_TRUE(peModule.has_value());
        const auto analysisDatabase = symfind::AnalysisDb::Analyze(*peModule);
        const auto* loaderFunction = analysisDatabase.FunctionByName("TestLoader");
        const auto* targetFunction = analysisDatabase.FunctionAt(targetFunctionRva);
        const auto* independentFunction = analysisDatabase.FunctionAt(independentFunctionRva);
        ASSERT_NE(loaderFunction, nullptr);
        ASSERT_NE(targetFunction, nullptr);
        ASSERT_NE(independentFunction, nullptr);
        EXPECT_EQ(loaderFunction->rva, primaryFunctionRva);
        EXPECT_EQ(loaderFunction->size, 0x10);
        EXPECT_EQ(loaderFunction->ranges.size(), 2);
        EXPECT_EQ(loaderFunction->callees, (std::vector<uint64_t>{targetFunctionRva}));
        EXPECT_EQ(loaderFunction->callCount, 1);
        EXPECT_FALSE(Contains(loaderFunction->callees, gapCalleeRva));
        EXPECT_FALSE(
            Contains(loaderFunction->callees, continuationRva)); // A JMP does not become a CALL.
        EXPECT_TRUE(Contains(targetFunction->callers, primaryFunctionRva));
        EXPECT_FALSE(Contains(targetFunction->callers, continuationRva));
        EXPECT_TRUE(
            Contains(independentFunction->callees,
                     primaryFunctionRva)); // Incoming call to a continuation is canonicalized.
        EXPECT_TRUE(Contains(independentFunction->callees, gapCalleeRva));
        EXPECT_EQ(analysisDatabase.FunctionAt(continuationRva), nullptr);
        const auto parsedRule = symfind::dsl::DslParser::Parse(R"(
            find function in "chain-fixture" where
                called_by "TestLoader";
                not exported;
                calls "TestAnchor";
        )");
        ASSERT_TRUE(parsedRule.has_value());
        const auto matchedSymbols = symfind::dsl::DslMatcher::Match(analysisDatabase, *parsedRule);
        ASSERT_EQ(matchedSymbols.size(), 1);
        EXPECT_EQ(matchedSymbols.front().rva, targetFunctionRva);
    }

    TEST(ChainedUnwind, ExportAliasesKeepNameLookupAndNamedCallPredicates)
    {
        for (const uint32_t aliasEntryRva : {primaryFunctionRva, continuationRva})
        {
            SCOPED_TRACE(aliasEntryRva);
            auto peBytes = MakeChainedPe();
            // TestAnchor becomes another export of TestLoader's procedure,
            // either at the exact entry or at an owned continuation entry.
            Put(peBytes, FileOffset(0x4044), aliasEntryRva, 4);
            const auto peModule = symfind::PeModule::FromMemory(peBytes, preferredImageBase);
            ASSERT_TRUE(peModule.has_value());
            const auto analysisDatabase = symfind::AnalysisDb::Analyze(*peModule);
            const auto* loaderAliasFunction = analysisDatabase.FunctionByName("TestLoader");
            const auto* anchorAliasFunction = analysisDatabase.FunctionByName("TestAnchor");
            ASSERT_NE(loaderAliasFunction, nullptr);
            ASSERT_NE(anchorAliasFunction, nullptr);
            EXPECT_EQ(loaderAliasFunction, anchorAliasFunction);
            EXPECT_EQ(loaderAliasFunction->rva, primaryFunctionRva);
            for (const std::string_view exportAlias : {"TestLoader", "TestAnchor"})
            {
                SCOPED_TRACE(exportAlias);
                for (const std::string_view predicateName : {"calls", "called_by"})
                {
                    SCOPED_TRACE(predicateName);
                    const auto ruleSource =
                        std::string("find function in \"chain-fixture\" where ") +
                        std::string(predicateName) + " \"" + std::string(exportAlias) +
                        "\"; not exported;";
                    const auto parsedRule = symfind::dsl::DslParser::Parse(ruleSource);
                    ASSERT_TRUE(parsedRule.has_value());
                    const auto matchedSymbols =
                        symfind::dsl::DslMatcher::Match(analysisDatabase, *parsedRule);
                    ASSERT_EQ(matchedSymbols.size(), 1);
                    EXPECT_EQ(matchedSymbols.front().rva, predicateName == "calls"
                                                              ? independentFunctionRva
                                                              : targetFunctionRva);
                }
            }
        }
    }

    TEST(ChainedUnwind, RepeatedCallsInContinuationRemainSeparateInstructions)
    {
        auto peBytes = MakeChainedPe();
        std::fill_n(peBytes.begin() + FileOffset(continuationRva), 0x10, 0xcc);
        DirectBranch(peBytes, continuationRva, targetFunctionRva, 0xe8);
        DirectBranch(peBytes, continuationRva + 5, targetFunctionRva, 0xe8);
        peBytes[FileOffset(continuationRva + 10)] = 0xc3;
        const auto peModule = symfind::PeModule::FromMemory(peBytes, preferredImageBase);
        ASSERT_TRUE(peModule.has_value());
        const auto analysisDatabase = symfind::AnalysisDb::Analyze(*peModule);
        const auto* primaryFunction = analysisDatabase.FunctionAt(primaryFunctionRva);
        ASSERT_NE(primaryFunction, nullptr);
        EXPECT_EQ(primaryFunction->callCount, 2);
        EXPECT_TRUE(Contains(primaryFunction->callees, targetFunctionRva));
    }

    TEST(ChainedUnwind, ContinuationDataReferenceBelongsToPrimaryAndGapRemainsIndependent)
    {
        const auto peModule = symfind::PeModule::FromMemory(MakeChainedPe(), preferredImageBase);
        ASSERT_TRUE(peModule.has_value());
        const auto analysisDatabase = symfind::AnalysisDb::Analyze(*peModule);
        const auto* primaryFunction = analysisDatabase.FunctionAt(primaryFunctionRva);
        ASSERT_NE(primaryFunction, nullptr);
        ASSERT_EQ(primaryFunction->dataRefs.size(), 1);
        EXPECT_EQ(primaryFunction->dataRefs.front().fromRva, continuationRva + 5);
        EXPECT_EQ(primaryFunction->dataRefs.front().fromFunc, primaryFunctionRva);
        EXPECT_EQ(primaryFunction->dataRefs.front().toRva, primaryDataRva);
        const auto* independentFunction = analysisDatabase.FunctionAt(independentFunctionRva);
        ASSERT_NE(independentFunction, nullptr);
        ASSERT_EQ(independentFunction->dataRefs.size(), 1);
        EXPECT_EQ(independentFunction->dataRefs.front().fromFunc, independentFunctionRva);
        EXPECT_EQ(independentFunction->dataRefs.front().toRva, independentDataRva);
        const auto* referencedGlobal = analysisDatabase.GlobalAt(primaryDataRva);
        ASSERT_NE(referencedGlobal, nullptr);
        ASSERT_EQ(referencedGlobal->refs.size(), 1);
        EXPECT_EQ(referencedGlobal->refs.front().fromFunc, primaryFunctionRva);
    }

    TEST(ChainedUnwind, OddUnwindCodeCountAlignsChainedRuntimeFunction)
    {
        auto peBytes = MakeChainedPe();
        const auto primaryUnwindOffset = FileOffset(0x3000);
        peBytes[primaryUnwindOffset + 1] = 4;
        peBytes[primaryUnwindOffset + 2] = 1;
        peBytes[primaryUnwindOffset + 4] = 4;
        peBytes[primaryUnwindOffset + 5] = 0x72; // UWOP_ALLOC_SMALL: 64-byte primary frame.
        const auto primaryCodeOffset = FileOffset(primaryFunctionRva);
        const std::array<uint8_t, 4> stackAllocationBytes{0x48, 0x83, 0xec, 0x40};
        std::copy(stackAllocationBytes.begin(), stackAllocationBytes.end(),
                  peBytes.begin() + primaryCodeOffset);
        DirectBranch(peBytes, primaryFunctionRva + 4, continuationRva, 0xe9);

        const auto continuationUnwindOffset = FileOffset(0x3020);
        peBytes[continuationUnwindOffset + 1] = 5;
        peBytes[continuationUnwindOffset + 2] =
            3; // SAVE_NONVOL_FAR consumes three UNWIND_CODE slots.
        peBytes[continuationUnwindOffset + 4] = 5;
        peBytes[continuationUnwindOffset + 5] =
            0x35; // Save RBX at RSP + 0x20 in the inherited frame.
        Put(peBytes, continuationUnwindOffset + 6, 0x20, 4);
        Put(peBytes, continuationUnwindOffset + 10, 0,
            2); // Pad the odd count to an even slot count.
        RuntimeFunction(peBytes, FileOffset(0x302c), primaryFunctionRva, primaryFunctionRva + 0x10,
                        0x3000);
        const auto continuationCodeOffset = FileOffset(continuationRva);
        std::fill(peBytes.begin() + continuationCodeOffset,
                  peBytes.begin() + continuationCodeOffset + 0x10, 0xcc);
        const std::array<uint8_t, 5> registerSaveBytes{0x48, 0x89, 0x5c, 0x24, 0x20};
        std::copy(registerSaveBytes.begin(), registerSaveBytes.end(),
                  peBytes.begin() + continuationCodeOffset);
        DirectBranch(peBytes, continuationRva + 5, targetFunctionRva, 0xe8);
        peBytes[FileOffset(continuationRva + 10)] = 0xc3;
        const auto peModule = symfind::PeModule::FromMemory(peBytes, preferredImageBase);
        ASSERT_TRUE(peModule.has_value());
        EXPECT_EQ(peModule->CanonicalFunctionRva(continuationRva + 5), primaryFunctionRva);
        const auto* primaryFunctionBounds = BoundsAt(*peModule, primaryFunctionRva);
        ASSERT_NE(primaryFunctionBounds, nullptr);
        EXPECT_EQ(primaryFunctionBounds->ranges.size(), 2);
    }

    TEST(ChainedUnwind, LoopBackEdgeMustReachAnOwnedRange)
    {
        for (const uint32_t backEdgeTargetRva : {primaryFunctionRva + 5, independentFunctionRva})
        {
            SCOPED_TRACE(backEdgeTargetRva);
            auto peBytes = MakeChainedPe();
            std::fill(peBytes.begin() + FileOffset(continuationRva + 5),
                      peBytes.begin() + FileOffset(continuationRva) + 0x10, 0xcc);
            DirectBranch(peBytes, continuationRva + 5, backEdgeTargetRva, 0xe9);
            const auto peModule = symfind::PeModule::FromMemory(peBytes, preferredImageBase);
            ASSERT_TRUE(peModule.has_value());
            const auto analysisDatabase = symfind::AnalysisDb::Analyze(*peModule);
            const auto* primaryFunction = analysisDatabase.FunctionAt(primaryFunctionRva);
            ASSERT_NE(primaryFunction, nullptr);
            EXPECT_EQ(primaryFunction->hasLoop, backEdgeTargetRva == primaryFunctionRva + 5);
        }
    }

    TEST(ChainedUnwind, InvalidChainsCannotAssignContinuationToUnrelatedPrimary)
    {
        for (const std::string_view invalidChainCase :
             {"cycle", "wrong-end", "wrong-unwind", "missing-parent", "different-frame",
              "handler-and-chain"})
        {
            SCOPED_TRACE(invalidChainCase);
            auto peBytes = MakeChainedPe();
            if (invalidChainCase == "cycle")
            {
                peBytes[FileOffset(0x3000)] = 0x21;
                RuntimeFunction(peBytes, FileOffset(0x3004), continuationRva,
                                continuationRva + 0x10, 0x3020);
            }
            else if (invalidChainCase == "wrong-end")
            {
                Put(peBytes, FileOffset(0x3028), primaryFunctionRva + 0x11, 4);
            }
            else if (invalidChainCase == "wrong-unwind")
            {
                Put(peBytes, FileOffset(0x302c), 0x3004, 4);
            }
            else if (invalidChainCase == "missing-parent")
            {
                RuntimeFunction(peBytes, FileOffset(0x3024), 0x1080, 0x1090, 0x3000);
            }
            else if (invalidChainCase == "different-frame")
            {
                peBytes[FileOffset(0x3023)] = 0x13;
            }
            else
            {
                peBytes[FileOffset(0x3020)] = 0x29; // CHAININFO cannot coexist with EHANDLER.
            }

            const auto peModule = symfind::PeModule::FromMemory(peBytes, preferredImageBase);
            ASSERT_TRUE(peModule.has_value());
            const auto* primaryBounds = BoundsAt(*peModule, primaryFunctionRva);
            const auto* continuationBounds = BoundsAt(*peModule, continuationRva);
            ASSERT_NE(primaryBounds, nullptr);
            ASSERT_NE(continuationBounds, nullptr);
            EXPECT_EQ(primaryBounds->ranges.size(), 1);
            EXPECT_EQ(continuationBounds->ranges.size(), 1);
            EXPECT_EQ(peModule->CanonicalFunctionRva(continuationRva + 5), continuationRva);
        }
    }

    TEST(ChainedUnwind, InvalidRuntimeBoundsAreNotClaimedByPrimary)
    {
        for (const uint32_t invalidFunctionEndRva : {continuationRva - 1, 0x5001u})
        {
            SCOPED_TRACE(invalidFunctionEndRva);
            auto peBytes = MakeChainedPe();
            Put(peBytes, 0x800 + 2 * 12 + 4, invalidFunctionEndRva, 4);
            const auto peModule = symfind::PeModule::FromMemory(peBytes, preferredImageBase);
            ASSERT_TRUE(peModule.has_value());
            EXPECT_EQ(BoundsAt(*peModule, continuationRva), nullptr);
            EXPECT_FALSE(peModule->CanonicalFunctionRva(continuationRva + 5).has_value());
            const auto* primaryBounds = BoundsAt(*peModule, primaryFunctionRva);
            ASSERT_NE(primaryBounds, nullptr);
            EXPECT_EQ(primaryBounds->ranges.size(), 1);
        }
    }
} // namespace
