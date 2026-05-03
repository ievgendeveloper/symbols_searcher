#include "symfind/analysis_db.h"
#include "symfind/disassembler.h"
#include "symfind/function_finder.h"

#include <gtest/gtest.h>

TEST(ComputeStackFrameSize, RecognizesSubRspImm8)
{
    symfind::Disassembler disassembler;
    // sub rsp, 0x40 ; ret
    std::vector<uint8_t> body = {0x48, 0x83, 0xEC, 0x40, 0xC3};
    const auto size = compute_stack_frame_size_in_body(disassembler, body, 0x1000);
    EXPECT_EQ(size, 0x40u);
}

TEST(ComputeStackFrameSize, RecognizesSubRspImm32)
{
    symfind::Disassembler disassembler;
    // sub rsp, 0x100 ; ret
    std::vector<uint8_t> body = {0x48, 0x81, 0xEC, 0x00, 0x01, 0x00, 0x00, 0xC3};
    const auto size = compute_stack_frame_size_in_body(disassembler, body, 0x1000);
    EXPECT_EQ(size, 0x100u);
}

TEST(ComputeStackFrameSize, SkipsPushesBeforeSubRsp)
{
    symfind::Disassembler disassembler;
    // push rbx ; push rdi ; sub rsp, 0x20 ; ret
    std::vector<uint8_t> body = {0x53, 0x57, 0x48, 0x83, 0xEC, 0x20, 0xC3};
    const auto size = compute_stack_frame_size_in_body(disassembler, body, 0x1000);
    EXPECT_EQ(size, 0x20u);
}

TEST(ComputeStackFrameSize, ReturnsZeroForLeafFunction)
{
    symfind::Disassembler disassembler;
    // mov eax, 1 ; ret  (no stack manipulation)
    std::vector<uint8_t> body = {0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3};
    const auto size = compute_stack_frame_size_in_body(disassembler, body, 0x1000);
    EXPECT_EQ(size, 0u);
}

TEST(ComputeStackFrameSize, IgnoresSubRspNotInPrologue)
{
    symfind::Disassembler disassembler;
    // Many NOPs followed by sub rsp - beyond our scan limit
    std::vector<uint8_t> body(20, 0x90); // 20 NOPs
    body.insert(body.end(), {0x48, 0x83, 0xEC, 0x40, 0xC3});
    const auto size = compute_stack_frame_size_in_body(disassembler, body, 0x1000);
    EXPECT_EQ(size, 0u); // sub rsp is past the prologue scan limit
}

TEST(AnalysisIntegration, StackFrameSizesAreReasonableInNtdll)
{
    const auto module = symfind::PeModule::from_file(R"(C:\Windows\System32\ntdll.dll)");
    ASSERT_TRUE(module.has_value());

    const auto database = symfind::AnalysisDb::analyze(*module);

    // Most non-trivial functions should have a stack frame
    int with_frame = 0;
    int total = 0;
    for (const auto& analyzedFunction : database.functions())
    {
        if (analyzedFunction.size > 32)
        {
            // skip stubs and tiny functions
            ++total;

            if (analyzedFunction.stack_frame_size > 0)
            {
                ++with_frame;
            }
        }
    }

    // Rough sanity check: at least half of substantial functions
    // have a stack frame
    ASSERT_GT(total, 0);
    EXPECT_GT(with_frame * 2, total);
}