#include "symfind/disassembler.h"
#include <gtest/gtest.h>

#include <cstdint>
#include <nonstd/span.hpp>
#include <vector>

namespace
{
    /// Helper: construct a span over a byte literal.
    nonstd::span<const uint8_t> SpanOf(const std::vector<uint8_t>& instructionBytes)
    {
        return nonstd::span<const uint8_t>(instructionBytes.data(), instructionBytes.size());
    }

} // namespace

// ─── Smoke tests ────────────────────────────────────

TEST(Disassembler, DecodesEmptyInput)
{
    const symfind::Disassembler disassembler;
    std::vector<uint8_t> emptyInstructionBytes;
    auto decodedInstructions = disassembler.Disassemble(SpanOf(emptyInstructionBytes), 0x1000);
    EXPECT_TRUE(decodedInstructions.empty());
}

TEST(Disassembler, DecodesSingleNop)
{
    const symfind::Disassembler disassembler;
    // 0x90 = NOP
    std::vector<uint8_t> instructionBytes = {0x90};
    auto decodedInstructions = disassembler.Disassemble(SpanOf(instructionBytes), 0x1000);

    ASSERT_EQ(decodedInstructions.size(), 1u);
    EXPECT_EQ(decodedInstructions[0].address, 0x1000u);
    EXPECT_EQ(decodedInstructions[0].length, 1u);
    EXPECT_FALSE(decodedInstructions[0].isCall);
    EXPECT_FALSE(decodedInstructions[0].isJump);
    EXPECT_FALSE(decodedInstructions[0].isRet);
}

TEST(Disassembler, DecodesMultipleInstructions)
{
    const symfind::Disassembler disassembler;
    // Three NOPs in a row
    std::vector<uint8_t> instructionBytes = {0x90, 0x90, 0x90};
    auto decodedInstructions = disassembler.Disassemble(SpanOf(instructionBytes), 0x2000);

    ASSERT_EQ(decodedInstructions.size(), 3u);
    EXPECT_EQ(decodedInstructions[0].address, 0x2000u);
    EXPECT_EQ(decodedInstructions[1].address, 0x2001u);
    EXPECT_EQ(decodedInstructions[2].address, 0x2002u);
}

// ─── Branch target resolution ───────────────────────

TEST(Disassembler, ResolvesDirectCallTarget)
{
    const symfind::Disassembler disassembler;
    // E8 XX XX XX XX = CALL rel32
    // CALL 0x1234 from address 0x1000:
    //   target = next_instr_addr (0x1005) + rel32
    //   want target = 0x1234, so rel32 = 0x1234 - 0x1005 = 0x22F
    //   little-endian: 2F 02 00 00
    std::vector<uint8_t> instructionBytes = {0xE8, 0x2F, 0x02, 0x00, 0x00};
    auto decodedInstructions = disassembler.Disassemble(SpanOf(instructionBytes), 0x1000);

    ASSERT_EQ(decodedInstructions.size(), 1u);
    EXPECT_TRUE(decodedInstructions[0].isCall);
    EXPECT_FALSE(decodedInstructions[0].isJump);
    EXPECT_EQ(decodedInstructions[0].branchTarget, 0x1234u);
}

TEST(Disassembler, ResolvesUnconditionalJump)
{
    const symfind::Disassembler disassembler;
    // EB XX = JMP rel8
    // JMP from 0x1000 to 0x100A:
    //   rel8 = 0x100A - (0x1000 + 2) = 0x08
    std::vector<uint8_t> instructionBytes = {0xEB, 0x08};
    auto decodedInstructions = disassembler.Disassemble(SpanOf(instructionBytes), 0x1000);

    ASSERT_EQ(decodedInstructions.size(), 1u);
    EXPECT_TRUE(decodedInstructions[0].isJump);
    EXPECT_FALSE(decodedInstructions[0].isConditional);
    EXPECT_EQ(decodedInstructions[0].branchTarget, 0x100Au);
}

TEST(Disassembler, ResolvesConditionalJump)
{
    const symfind::Disassembler disassembler;
    // 74 XX = JE rel8
    // JE from 0x1000 to 0x1010, rel8 = 0x10 - 2 = 0x0E
    std::vector<uint8_t> instructionBytes = {0x74, 0x0E};
    auto decodedInstructions = disassembler.Disassemble(SpanOf(instructionBytes), 0x1000);

    ASSERT_EQ(decodedInstructions.size(), 1u);
    EXPECT_TRUE(decodedInstructions[0].isJump);
    EXPECT_TRUE(decodedInstructions[0].isConditional);
    EXPECT_EQ(decodedInstructions[0].branchTarget, 0x1010u);
}

TEST(Disassembler, IndirectCallHasNoBranchTarget)
{
    const symfind::Disassembler disassembler;
    // FF D0 = CALL RAX (indirect call)
    std::vector<uint8_t> instructionBytes = {0xFF, 0xD0};
    auto decodedInstructions = disassembler.Disassemble(SpanOf(instructionBytes), 0x1000);

    ASSERT_EQ(decodedInstructions.size(), 1u);
    EXPECT_TRUE(decodedInstructions[0].isCall);
    EXPECT_EQ(decodedInstructions[0].branchTarget, 0u)
        << "Indirect calls should have branch_target = 0";
}

// ─── RIP-relative addressing ────────────────────────

TEST(Disassembler, ResolvesLeaRipRelative)
{
    const symfind::Disassembler disassembler;
    // 48 8D 0D XX XX XX XX = LEA RCX, [rip + disp32]
    // LEA RCX, [rip + 0x100] from address 0x1000:
    //   instruction length = 7
    //   target = 0x1000 + 7 + 0x100 = 0x1107
    std::vector<uint8_t> instructionBytes = {0x48, 0x8D, 0x0D, 0x00, 0x01, 0x00, 0x00};
    auto decodedInstructions = disassembler.Disassemble(SpanOf(instructionBytes), 0x1000);

    ASSERT_EQ(decodedInstructions.size(), 1u);
    EXPECT_TRUE(decodedInstructions[0].isLea);
    EXPECT_FALSE(decodedInstructions[0].isMemRead); // LEA computes address, doesn't read
    EXPECT_FALSE(decodedInstructions[0].isMemWrite);
    EXPECT_EQ(decodedInstructions[0].memAbsolute, 0x1107u);
}

TEST(Disassembler, ResolvesRipRelativeRead)
{
    const symfind::Disassembler disassembler;
    // 48 8B 0D XX XX XX XX = MOV RCX, [rip + disp32]
    // MOV RCX, [rip + 0x200] from 0x1000:
    //   target = 0x1000 + 7 + 0x200 = 0x1207
    std::vector<uint8_t> instructionBytes = {0x48, 0x8B, 0x0D, 0x00, 0x02, 0x00, 0x00};
    auto decodedInstructions = disassembler.Disassemble(SpanOf(instructionBytes), 0x1000);

    ASSERT_EQ(decodedInstructions.size(), 1u);
    EXPECT_FALSE(decodedInstructions[0].isLea);
    EXPECT_TRUE(decodedInstructions[0].isMemRead);
    EXPECT_FALSE(decodedInstructions[0].isMemWrite);
    EXPECT_EQ(decodedInstructions[0].memAbsolute, 0x1207u);
}

TEST(Disassembler, ResolvesRipRelativeWrite)
{
    const symfind::Disassembler disassembler;
    // 48 89 0D XX XX XX XX = MOV [rip + disp32], RCX
    // MOV [rip + 0x300], RCX from 0x1000:
    //   target = 0x1000 + 7 + 0x300 = 0x1307
    std::vector<uint8_t> instructionBytes = {0x48, 0x89, 0x0D, 0x00, 0x03, 0x00, 0x00};
    auto decodedInstructions = disassembler.Disassemble(SpanOf(instructionBytes), 0x1000);

    ASSERT_EQ(decodedInstructions.size(), 1u);
    EXPECT_FALSE(decodedInstructions[0].isMemRead);
    EXPECT_TRUE(decodedInstructions[0].isMemWrite);
    EXPECT_EQ(decodedInstructions[0].memAbsolute, 0x1307u);
}

// ─── Return / classification ────────────────────────

TEST(Disassembler, RecognizesReturn)
{
    const symfind::Disassembler disassembler;
    // C3 = RET
    std::vector<uint8_t> instructionBytes = {0xC3};
    auto decodedInstructions = disassembler.Disassemble(SpanOf(instructionBytes), 0x1000);

    ASSERT_EQ(decodedInstructions.size(), 1u);
    EXPECT_TRUE(decodedInstructions[0].isRet);
    EXPECT_FALSE(decodedInstructions[0].isCall);
    EXPECT_FALSE(decodedInstructions[0].isJump);
}

// ─── Realistic prologue ─────────────────────────────

TEST(Disassembler, DecodesTypicalFunctionPrologue)
{
    const symfind::Disassembler disassembler;
    // Typical x64 prologue:
    //   53                push rbx
    //   48 83 EC 20       sub rsp, 0x20
    //   48 8B D9          mov rbx, rcx
    //   C3                ret
    std::vector<uint8_t> instructionBytes = {0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xD9, 0xC3};
    auto decodedInstructions = disassembler.Disassemble(SpanOf(instructionBytes), 0x4000);

    ASSERT_EQ(decodedInstructions.size(), 4u);
    EXPECT_EQ(decodedInstructions[0].length, 1u); // push rbx
    EXPECT_EQ(decodedInstructions[1].length, 4u); // sub rsp, 0x20
    EXPECT_EQ(decodedInstructions[2].length, 3u); // mov rbx, rcx
    EXPECT_EQ(decodedInstructions[3].length, 1u); // ret
    EXPECT_TRUE(decodedInstructions[3].isRet);
}

// ─── Stop-on-invalid behavior ───────────────────────

TEST(Disassembler, StopsOnInvalidByte)
{
    const symfind::Disassembler disassembler;
    // NOP, then 0x06 — invalid in x64 long mode (was PUSH ES in 32-bit)
    std::vector<uint8_t> instructionBytes = {0x90, 0x06};
    auto decodedInstructions = disassembler.Disassemble(SpanOf(instructionBytes), 0x1000);

    // We should get the NOP, then stop at the invalid byte
    ASSERT_GE(decodedInstructions.size(), 1u);
    EXPECT_EQ(decodedInstructions[0].address, 0x1000u);
    // No more decoded instructions after the invalid one
    EXPECT_LE(decodedInstructions.size(), 1u);
}

// ─── Callback variant ───────────────────────────────

TEST(Disassembler, CallbackCanStopEarly)
{
    const symfind::Disassembler disassembler;
    std::vector<uint8_t> instructionBytes = {0x90, 0x90, 0x90, 0x90};

    int visitedInstructionCount = 0;
    disassembler.DisassembleCb(SpanOf(instructionBytes), 0x1000,
                               [&](const symfind::Instruction&)
                               {
                                   visitedInstructionCount++;
                                   return visitedInstructionCount < 2; // stop after 2 instructions
                               });
    EXPECT_EQ(visitedInstructionCount, 2);
}
