#include "spdlog/spdlog.h"

#include <gtest/gtest.h>

#include "ntdll_symbol_rules.h"
#include "symfind/analysis_db.h"
#include "symfind/dsl_matcher.h"
#include "symfind/dsl_parser.h"
#include "symfind/function_finder.h"

namespace
{
    std::vector<uint8_t> ReadFileFromDisk(const std::wstring& pathToFile)
    {
        const auto hFile = ::CreateFileW(
            pathToFile.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (hFile == INVALID_HANDLE_VALUE)
        {
            return {};
        }

        LARGE_INTEGER fileSize{};
        if (!::GetFileSizeEx(hFile, &fileSize))
        {
            ::CloseHandle(hFile);
            return {};
        }

        std::vector<uint8_t> buffer(static_cast<size_t>(fileSize.QuadPart));
        DWORD bytesRead = 0;
        const auto ok = ::ReadFile(
            hFile,
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            &bytesRead,
            nullptr);
        ::CloseHandle(hFile);

        if (!ok || bytesRead != buffer.size())
        {
            return {};
        }

        return buffer;
    }
} // namespace

TEST(FunctionFinder, Search_functions_by_exceptions_parsing_in_ntdll)
{
    auto module = symfind::PeModule::from_file(R"(C:\Windows\System32\ntdll.dll)");
    ASSERT_TRUE(module.has_value());

    std::vector<symfind::Function> functions;
    symfind::FunctionFinder::from_exception_directory(*module, functions);

    EXPECT_GT(functions.size(), 10);
}

TEST(FunctionFinder, Search_functions_by_disassembling_code_sections)
{
    auto module = symfind::PeModule::from_file(R"(C:\Windows\System32\ntdll.dll)");
    ASSERT_TRUE(module.has_value());

    std::vector<symfind::Function> functions;
    const symfind::Disassembler disassembler;
    symfind::FunctionFinder::from_call_targets(*module, disassembler, functions);

    EXPECT_GT(functions.size(), 10);
}

TEST(AnalysisIntegration, FindLdrpInitializeInRealNtdll)
{
    auto module = symfind::PeModule::from_file(R"(C:\Windows\System32\ntdll.dll)");
    ASSERT_TRUE(module.has_value());

    auto db = symfind::AnalysisDb::analyze(*module);
    EXPECT_GT(db.functions().size(), 100u);

    // LdrInitializeThunk should have at least one callee
    const auto* thunk = db.function_by_name("LdrInitializeThunk");
    ASSERT_NE(thunk, nullptr);
    EXPECT_GT(thunk->callees.size(), 0u);

    // Run our DSL rule
    auto rule = symfind::dsl::DslParser::parse(
        symfind::validation::ntdll_rule_for("LdrpInitialize"));
    ASSERT_TRUE(rule.has_value());

    auto results = symfind::dsl::DslMatcher::match(db, *rule);
    ASSERT_GE(results.size(), 1u);

    // The match should be inside .text
    SPDLOG_INFO("Found LdrpInitialize candidate at RVA 0x{:X}", results[0].rva);
}

TEST(CollectDataRefs, FindsLeaInRtlDecompressBuffer)
{
    const auto module = symfind::PeModule::from_file(R"(C:\Windows\System32\ntdll.dll)");
    ASSERT_TRUE(module.has_value());

    const auto rtl_decompress = module->export_rva("RtlDecompressBuffer");
    ASSERT_TRUE(rtl_decompress.has_value());

    // We need the function size - easiest is to run from_exception_directory
    std::vector<symfind::Function> functions;
    symfind::FunctionFinder::from_exception_directory(*module, functions);

    auto it = std::find_if(functions.begin(), functions.end(),
                           [&](const symfind::Function& f)
                           {
                               return f.rva == *rtl_decompress;
                           });
    ASSERT_NE(it, functions.end());

    const symfind::Disassembler disassembler;
    const auto refs = symfind::collect_data_refs(*module, disassembler, it->rva, it->size);

    // RtlDecompressBuffer has at least one DataRef (lea rdi, RtlDecompressBufferProcs)
    ASSERT_GE(refs.size(), 1u);
    bool has_lea = std::any_of(refs.begin(), refs.end(),
                               [](const symfind::Xref& x)
                               {
                                   return x.type == symfind::XrefType::DataRef;
                               });
    EXPECT_TRUE(has_lea);
}

TEST(FunctionFinder, Search_functions_by_exceptions_parsing_in_ntdll_from_memory)
{
    const auto buffer = ReadFileFromDisk(LR"(C:\Windows\System32\ntdll.dll)");
    ASSERT_FALSE(buffer.empty());

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer.data());
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        buffer.data() + dos->e_lfanew);
    const uint64_t ntdll_preferred_base = nt->OptionalHeader.ImageBase;

    auto module = symfind::PeModule::from_memory(buffer, ntdll_preferred_base);
    ASSERT_TRUE(module.has_value());
    std::vector<symfind::Function> functions;
    symfind::FunctionFinder::from_exception_directory(*module, functions);
    EXPECT_GT(functions.size(), 10);
}

TEST(FunctionFinder, Search_functions_by_disassembling_code_sections_from_memory)
{
    const auto buffer = ReadFileFromDisk(LR"(C:\Windows\System32\ntdll.dll)");
    ASSERT_FALSE(buffer.empty());

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer.data());
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        buffer.data() + dos->e_lfanew);
    const uint64_t ntdll_preferred_base = nt->OptionalHeader.ImageBase;

    auto module = symfind::PeModule::from_memory(buffer, ntdll_preferred_base);
    ASSERT_TRUE(module.has_value());
    std::vector<symfind::Function> functions;
    const symfind::Disassembler disassembler;
    symfind::FunctionFinder::from_call_targets(*module, disassembler, functions);
    EXPECT_GT(functions.size(), 10);
}

TEST(AnalysisIntegration, FindLdrpInitializeInRealNtdll_from_memory)
{
    const auto buffer = ReadFileFromDisk(LR"(C:\Windows\System32\ntdll.dll)");
    ASSERT_FALSE(buffer.empty());

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer.data());
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        buffer.data() + dos->e_lfanew);
    const uint64_t ntdll_preferred_base = nt->OptionalHeader.ImageBase;

    auto module = symfind::PeModule::from_memory(buffer, ntdll_preferred_base);
    ASSERT_TRUE(module.has_value());
    auto db = symfind::AnalysisDb::analyze(*module);
    EXPECT_GT(db.functions().size(), 100u);
    const auto* thunk = db.function_by_name("LdrInitializeThunk");
    ASSERT_NE(thunk, nullptr);
    EXPECT_GT(thunk->callees.size(), 0u);
    auto rule = symfind::dsl::DslParser::parse(
        symfind::validation::ntdll_rule_for("LdrpInitialize"));
    ASSERT_TRUE(rule.has_value());
    auto results = symfind::dsl::DslMatcher::match(db, *rule);
    ASSERT_GE(results.size(), 1u);
    SPDLOG_INFO("Found LdrpInitialize candidate at RVA 0x{:X} (from_memory)", results[0].rva);
}

TEST(CollectDataRefs, FindsLeaInRtlDecompressBuffer_from_memory)
{
    const auto buffer = ReadFileFromDisk(LR"(C:\Windows\System32\ntdll.dll)");
    ASSERT_FALSE(buffer.empty());

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer.data());
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        buffer.data() + dos->e_lfanew);
    const uint64_t ntdll_preferred_base = nt->OptionalHeader.ImageBase;

    auto module = symfind::PeModule::from_memory(buffer, ntdll_preferred_base);
    ASSERT_TRUE(module.has_value());
    const auto rtl_decompress = module->export_rva("RtlDecompressBuffer");
    ASSERT_TRUE(rtl_decompress.has_value());
    std::vector<symfind::Function> functions;
    symfind::FunctionFinder::from_exception_directory(*module, functions);
    auto it = std::find_if(functions.begin(), functions.end(),
                           [&](const symfind::Function& f)
                           {
                               return f.rva == *rtl_decompress;
                           });
    ASSERT_NE(it, functions.end());
    const symfind::Disassembler disassembler;
    const auto refs = symfind::collect_data_refs(*module, disassembler, it->rva, it->size);
    ASSERT_GE(refs.size(), 1u);
    bool has_lea = std::any_of(refs.begin(), refs.end(),
                               [](const symfind::Xref& x)
                               {
                                   return x.type == symfind::XrefType::DataRef;
                               });
    EXPECT_TRUE(has_lea);
}
