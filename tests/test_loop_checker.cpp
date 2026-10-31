#include "spdlog/spdlog.h"
#include "symfind/function_finder.h"

#include <gtest/gtest.h>

TEST(DetectLoops, BackwardJumpIsLoop)
{
    symfind::Disassembler disassembler;
    // Layout starting at 0x1000:
    //   0x1000: mov eax, 0
    //   0x1005: inc eax
    //   0x1007: cmp eax, 10
    //   0x100A: jl 0x1005  (back-edge)
    //   0x100C: ret
    std::vector<uint8_t> functionBodyBytes = {
        0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0
        0xFF, 0xC0,                   // inc eax
        0x83, 0xF8, 0x0A,             // cmp eax, 10
        0x7C, 0xF9,                   // jl -7 (back to 0x1005)
        0xC3                          // ret
    };
    bool containsLoop = symfind::DetectLoopsInBody(disassembler, functionBodyBytes, 0x1000,
                                                   functionBodyBytes.size());
    EXPECT_TRUE(containsLoop);
}

TEST(DetectLoops, ForwardJumpIsNotLoop)
{
    symfind::Disassembler disassembler;
    //   0x1000: cmp eax, 0
    //   0x1003: je 0x100A
    //   0x1005: nop
    //   0x1006: nop
    //   0x1007: nop
    //   0x1008: nop
    //   0x1009: nop
    //   0x100A: ret
    std::vector<uint8_t> functionBodyBytes = {
        0x83, 0xF8, 0x00,             // cmp eax, 0
        0x74, 0x05,                   // je +5
        0x90, 0x90, 0x90, 0x90, 0x90, // 5x nop
        0xC3                          // ret
    };
    bool containsLoop = symfind::DetectLoopsInBody(disassembler, functionBodyBytes, 0x1000,
                                                   functionBodyBytes.size());
    EXPECT_FALSE(containsLoop);
}

TEST(DetectLoops, TailCallToEarlierFunctionIsNotLoop)
{
    symfind::Disassembler disassembler;
    // jmp -0x100  (target outside this function)
    // Function at 0x2000, target would be 0x1F00
    std::vector<uint8_t> functionBodyBytes = {
        0xE9, 0xFB, 0xFE, 0xFF, 0xFF // jmp rel32 = -0x105
        // from 0x2000+5 = 0x2005, target = 0x1F00
    };
    bool containsLoop = symfind::DetectLoopsInBody(disassembler, functionBodyBytes, 0x2000,
                                                   functionBodyBytes.size());
    EXPECT_FALSE(containsLoop);
}

TEST(DetectLoops, IndirectJumpIsIgnored)
{
    symfind::Disassembler disassembler;
    // jmp rax - indirect, no branchTarget
    std::vector<uint8_t> functionBodyBytes = {0xFF, 0xE0};
    bool containsLoop = symfind::DetectLoopsInBody(disassembler, functionBodyBytes, 0x1000,
                                                   functionBodyBytes.size());
    EXPECT_FALSE(containsLoop);
}

TEST(DetectLoops, EmptyBodyIsNotLoop)
{
    symfind::Disassembler disassembler;
    std::vector<uint8_t> functionBodyBytes;
    bool containsLoop = symfind::DetectLoopsInBody(disassembler, functionBodyBytes, 0x1000, 0);
    EXPECT_FALSE(containsLoop);
}

TEST(DetectLoops, NoBranchesIsNotLoop)
{
    symfind::Disassembler disassembler;
    // mov eax, 0 ; ret
    std::vector<uint8_t> functionBodyBytes = {0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3};
    bool containsLoop = symfind::DetectLoopsInBody(disassembler, functionBodyBytes, 0x1000,
                                                   functionBodyBytes.size());
    EXPECT_FALSE(containsLoop);
}

TEST(AnalysisIntegration, SomeFunctionsHaveLoopsInNtdll)
{
    const auto ntdllModule = symfind::PeModule::FromFile(R"(C:\Windows\System32\ntdll.dll)");
    ASSERT_TRUE(ntdllModule.has_value());

    const auto analysisDatabase = symfind::AnalysisDb::Analyze(*ntdllModule);

    // ntdll has plenty of looping functions (string scanning, list traversal)
    // - we expect a non-trivial fraction to have hasLoop = true
    int functionsWithLoops = 0;
    int substantialFunctionCount = 0;
    for (const auto& function : analysisDatabase.Functions())
    {
        if (function.size > 64)
        {
            // skip tiny functions
            ++substantialFunctionCount;
            if (function.hasLoop)
            {
                ++functionsWithLoops;
            }
        }
    }
    ASSERT_GT(substantialFunctionCount, 0);
    EXPECT_GT(functionsWithLoops, 0) << "Expected at least some looping functions in ntdll";
    SPDLOG_INFO("ntdll: {}/{} substantial functions have loops", functionsWithLoops,
                substantialFunctionCount);
}