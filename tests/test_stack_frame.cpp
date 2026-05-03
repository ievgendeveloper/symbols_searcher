#include "symfind/analysis_db.h"
#include "symfind/disassembler.h"

#include <gtest/gtest.h>

[[nodiscard]] uint32_t compute_stack_frame_size_in_body(
    const symfind::Disassembler& disasm,
    std::span<const uint8_t> body,
    uint64_t base_address)
{
    constexpr int kPrologueScanLimit = 16;

    uint32_t frame_size = 0;
    int instr_count = 0;

    disasm.disassemble_cb(body, base_address, [&](const symfind::Instruction& instr)
    {
        if (instr.is_sub_rsp_imm)
        {
            frame_size = static_cast<uint32_t>(instr.imm_value);
            return false; // stop - found it
        }

        // Stop scanning once we leave the prologue
        if (++instr_count >= kPrologueScanLimit)
            return false;
        return true;
    });

    return frame_size;
}

TEST(ComputeStackFrameSize, RecognizesSubRspImm8)
{
    symfind::Disassembler d;
    // sub rsp, 0x40 ; ret
    std::vector<uint8_t> body = {0x48, 0x83, 0xEC, 0x40, 0xC3};
    uint32_t size = compute_stack_frame_size_in_body(d, body, 0x1000);
    EXPECT_EQ(size, 0x40u);
}

TEST(ComputeStackFrameSize, RecognizesSubRspImm32)
{
    symfind::Disassembler d;
    // sub rsp, 0x100 ; ret
    std::vector<uint8_t> body = {0x48, 0x81, 0xEC, 0x00, 0x01, 0x00, 0x00, 0xC3};
    uint32_t size = compute_stack_frame_size_in_body(d, body, 0x1000);
    EXPECT_EQ(size, 0x100u);
}

TEST(ComputeStackFrameSize, SkipsPushesBeforeSubRsp)
{
    symfind::Disassembler d;
    // push rbx ; push rdi ; sub rsp, 0x20 ; ret
    std::vector<uint8_t> body = {0x53, 0x57, 0x48, 0x83, 0xEC, 0x20, 0xC3};
    uint32_t size = compute_stack_frame_size_in_body(d, body, 0x1000);
    EXPECT_EQ(size, 0x20u);
}

TEST(ComputeStackFrameSize, ReturnsZeroForLeafFunction)
{
    symfind::Disassembler d;
    // mov eax, 1 ; ret  (no stack manipulation)
    std::vector<uint8_t> body = {0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3};
    uint32_t size = compute_stack_frame_size_in_body(d, body, 0x1000);
    EXPECT_EQ(size, 0u);
}

TEST(ComputeStackFrameSize, IgnoresSubRspNotInPrologue)
{
    symfind::Disassembler d;
    // Many NOPs followed by sub rsp - beyond our scan limit
    std::vector<uint8_t> body(20, 0x90); // 20 NOPs
    body.insert(body.end(), {0x48, 0x83, 0xEC, 0x40, 0xC3});
    uint32_t size = compute_stack_frame_size_in_body(d, body, 0x1000);
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