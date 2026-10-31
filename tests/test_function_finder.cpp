#include "spdlog/spdlog.h"

#include <gtest/gtest.h>

#include "ntdll_symbol_rules.h"
#include "symfind/analysis_db.h"
#include "symfind/dsl_matcher.h"
#include "symfind/dsl_parser.h"
#include "symfind/function_finder.h"

#include <algorithm>
#include <string>
#include <vector>

#include <Windows.h>

namespace
{
    std::vector<uint8_t> ReadFileFromDisk(const std::wstring& filePath)
    {
        const auto fileHandle =
            ::CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                          FILE_ATTRIBUTE_NORMAL, nullptr);
        if (fileHandle == INVALID_HANDLE_VALUE)
        {
            return {};
        }

        LARGE_INTEGER fileSize{};
        if (!::GetFileSizeEx(fileHandle, &fileSize))
        {
            ::CloseHandle(fileHandle);
            return {};
        }

        std::vector<uint8_t> fileBytes(static_cast<size_t>(fileSize.QuadPart));
        DWORD bytesRead = 0;
        const auto readSucceeded =
            ::ReadFile(fileHandle, fileBytes.data(), static_cast<DWORD>(fileBytes.size()),
                       &bytesRead, nullptr);
        ::CloseHandle(fileHandle);

        if (!readSucceeded || bytesRead != fileBytes.size())
        {
            return {};
        }

        return fileBytes;
    }
} // namespace

TEST(FunctionFinder, SearchFunctionsByExceptionsParsingInNtdll)
{
    auto ntdllModule = symfind::PeModule::FromFile(R"(C:\Windows\System32\ntdll.dll)");
    ASSERT_TRUE(ntdllModule.has_value());

    std::vector<symfind::Function> discoveredFunctions;
    symfind::FunctionFinder::FromExceptionDirectory(*ntdllModule, discoveredFunctions);

    EXPECT_GT(discoveredFunctions.size(), 10);
}

TEST(FunctionFinder, SearchFunctionsByDisassemblingCodeSections)
{
    auto ntdllModule = symfind::PeModule::FromFile(R"(C:\Windows\System32\ntdll.dll)");
    ASSERT_TRUE(ntdllModule.has_value());

    std::vector<symfind::Function> discoveredFunctions;
    const symfind::Disassembler disassembler;
    symfind::FunctionFinder::FromCallTargets(*ntdllModule, disassembler, discoveredFunctions);

    EXPECT_GT(discoveredFunctions.size(), 10);
}

TEST(AnalysisIntegration, FindLdrpInitializeInRealNtdll)
{
    auto ntdllModule = symfind::PeModule::FromFile(R"(C:\Windows\System32\ntdll.dll)");
    ASSERT_TRUE(ntdllModule.has_value());

    auto analysisDatabase = symfind::AnalysisDb::Analyze(*ntdllModule);
    EXPECT_GT(analysisDatabase.Functions().size(), 100u);

    // LdrInitializeThunk should have at least one callee
    const auto* initializationThunk = analysisDatabase.FunctionByName("LdrInitializeThunk");
    ASSERT_NE(initializationThunk, nullptr);
    EXPECT_GT(initializationThunk->callees.size(), 0u);

    // Run our DSL rule
    auto symbolRule =
        symfind::dsl::DslParser::Parse(symfind::validation::NtdllRuleFor("LdrpInitialize"));
    ASSERT_TRUE(symbolRule.has_value());

    auto matchedSymbols = symfind::dsl::DslMatcher::Match(analysisDatabase, *symbolRule);
    ASSERT_GE(matchedSymbols.size(), 1u);

    // The match should be inside .text
    SPDLOG_INFO("Found LdrpInitialize candidate at RVA 0x{:X}", matchedSymbols[0].rva);
}

TEST(CollectDataRefs, FindsLeaInRtlDecompressBuffer)
{
    const auto ntdllModule = symfind::PeModule::FromFile(R"(C:\Windows\System32\ntdll.dll)");
    ASSERT_TRUE(ntdllModule.has_value());

    const auto decompressionFunctionRva = ntdllModule->ExportRva("RtlDecompressBuffer");
    ASSERT_TRUE(decompressionFunctionRva.has_value());

    // We need the function size - easiest is to run FromExceptionDirectory
    std::vector<symfind::Function> discoveredFunctions;
    symfind::FunctionFinder::FromExceptionDirectory(*ntdllModule, discoveredFunctions);

    auto decompressionFunctionIterator =
        std::find_if(discoveredFunctions.begin(), discoveredFunctions.end(),
                     [&](const symfind::Function& candidateFunction)
                     {
                         return candidateFunction.rva == *decompressionFunctionRva;
                     });
    ASSERT_NE(decompressionFunctionIterator, discoveredFunctions.end());

    const symfind::Disassembler disassembler;
    const auto dataReferences =
        symfind::CollectDataRefs(*ntdllModule, disassembler, decompressionFunctionIterator->rva,
                                 decompressionFunctionIterator->size);

    // RtlDecompressBuffer has at least one DataRef (lea rdi, RtlDecompressBufferProcs)
    ASSERT_GE(dataReferences.size(), 1u);
    bool hasAddressReference =
        std::any_of(dataReferences.begin(), dataReferences.end(),
                    [](const symfind::Xref& dataReference)
                    {
                        return dataReference.type == symfind::XrefType::DataRef;
                    });
    EXPECT_TRUE(hasAddressReference);
}

TEST(FunctionFinder, SearchFunctionsByExceptionsParsingInNtdllFromMemory)
{
    const auto fileBytes = ReadFileFromDisk(LR"(C:\Windows\System32\ntdll.dll)");
    ASSERT_FALSE(fileBytes.empty());

    const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(fileBytes.data());
    const auto* ntHeaders =
        reinterpret_cast<const IMAGE_NT_HEADERS64*>(fileBytes.data() + dosHeader->e_lfanew);
    const uint64_t preferredImageBase = ntHeaders->OptionalHeader.ImageBase;

    auto ntdllModule = symfind::PeModule::FromMemory(fileBytes, preferredImageBase);
    ASSERT_TRUE(ntdllModule.has_value());
    std::vector<symfind::Function> discoveredFunctions;
    symfind::FunctionFinder::FromExceptionDirectory(*ntdllModule, discoveredFunctions);
    EXPECT_GT(discoveredFunctions.size(), 10);
}

TEST(FunctionFinder, SearchFunctionsByDisassemblingCodeSectionsFromMemory)
{
    const auto fileBytes = ReadFileFromDisk(LR"(C:\Windows\System32\ntdll.dll)");
    ASSERT_FALSE(fileBytes.empty());

    const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(fileBytes.data());
    const auto* ntHeaders =
        reinterpret_cast<const IMAGE_NT_HEADERS64*>(fileBytes.data() + dosHeader->e_lfanew);
    const uint64_t preferredImageBase = ntHeaders->OptionalHeader.ImageBase;

    auto ntdllModule = symfind::PeModule::FromMemory(fileBytes, preferredImageBase);
    ASSERT_TRUE(ntdllModule.has_value());
    std::vector<symfind::Function> discoveredFunctions;
    const symfind::Disassembler disassembler;
    symfind::FunctionFinder::FromCallTargets(*ntdllModule, disassembler, discoveredFunctions);
    EXPECT_GT(discoveredFunctions.size(), 10);
}

TEST(AnalysisIntegration, FindLdrpInitializeInRealNtdllFromMemory)
{
    const auto fileBytes = ReadFileFromDisk(LR"(C:\Windows\System32\ntdll.dll)");
    ASSERT_FALSE(fileBytes.empty());

    const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(fileBytes.data());
    const auto* ntHeaders =
        reinterpret_cast<const IMAGE_NT_HEADERS64*>(fileBytes.data() + dosHeader->e_lfanew);
    const uint64_t preferredImageBase = ntHeaders->OptionalHeader.ImageBase;

    auto ntdllModule = symfind::PeModule::FromMemory(fileBytes, preferredImageBase);
    ASSERT_TRUE(ntdllModule.has_value());
    auto analysisDatabase = symfind::AnalysisDb::Analyze(*ntdllModule);
    EXPECT_GT(analysisDatabase.Functions().size(), 100u);
    const auto* initializationThunk = analysisDatabase.FunctionByName("LdrInitializeThunk");
    ASSERT_NE(initializationThunk, nullptr);
    EXPECT_GT(initializationThunk->callees.size(), 0u);
    auto symbolRule =
        symfind::dsl::DslParser::Parse(symfind::validation::NtdllRuleFor("LdrpInitialize"));
    ASSERT_TRUE(symbolRule.has_value());
    auto matchedSymbols = symfind::dsl::DslMatcher::Match(analysisDatabase, *symbolRule);
    ASSERT_GE(matchedSymbols.size(), 1u);
    SPDLOG_INFO("Found LdrpInitialize candidate at RVA 0x{:X} (from_memory)",
                matchedSymbols[0].rva);
}

TEST(CollectDataRefs, FindsLeaInRtlDecompressBufferFromMemory)
{
    const auto fileBytes = ReadFileFromDisk(LR"(C:\Windows\System32\ntdll.dll)");
    ASSERT_FALSE(fileBytes.empty());

    const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(fileBytes.data());
    const auto* ntHeaders =
        reinterpret_cast<const IMAGE_NT_HEADERS64*>(fileBytes.data() + dosHeader->e_lfanew);
    const uint64_t preferredImageBase = ntHeaders->OptionalHeader.ImageBase;

    auto ntdllModule = symfind::PeModule::FromMemory(fileBytes, preferredImageBase);
    ASSERT_TRUE(ntdllModule.has_value());
    const auto decompressionFunctionRva = ntdllModule->ExportRva("RtlDecompressBuffer");
    ASSERT_TRUE(decompressionFunctionRva.has_value());
    std::vector<symfind::Function> discoveredFunctions;
    symfind::FunctionFinder::FromExceptionDirectory(*ntdllModule, discoveredFunctions);
    auto decompressionFunctionIterator =
        std::find_if(discoveredFunctions.begin(), discoveredFunctions.end(),
                     [&](const symfind::Function& candidateFunction)
                     {
                         return candidateFunction.rva == *decompressionFunctionRva;
                     });
    ASSERT_NE(decompressionFunctionIterator, discoveredFunctions.end());
    const symfind::Disassembler disassembler;
    const auto dataReferences =
        symfind::CollectDataRefs(*ntdllModule, disassembler, decompressionFunctionIterator->rva,
                                 decompressionFunctionIterator->size);
    ASSERT_GE(dataReferences.size(), 1u);
    bool hasAddressReference =
        std::any_of(dataReferences.begin(), dataReferences.end(),
                    [](const symfind::Xref& dataReference)
                    {
                        return dataReference.type == symfind::XrefType::DataRef;
                    });
    EXPECT_TRUE(hasAddressReference);
}
