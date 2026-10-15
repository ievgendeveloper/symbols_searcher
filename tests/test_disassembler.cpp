#include "symfind/disassembler.h"
#include <gtest/gtest.h>

#include <cstdint>
#include <span>
#include <vector>

using namespace symfind;

namespace
{
    /// Helper: construct a span over a byte literal.
    std::span<const uint8_t> span_of(const std::vector<uint8_t>& bytes)
    {
        return {bytes.data(), bytes.size()};
    }

} // namespace

// ─── Smoke tests ────────────────────────────────────

TEST(Disassembler, DecodesEmptyInput)
{
    const Disassembler disasm;
    std::vector<uint8_t> empty;
    auto result = disasm.disassemble(span_of(empty), 0x1000);
    EXPECT_TRUE(result.empty());
}

TEST(Disassembler, DecodesSingleNop)
{
    const Disassembler disasm;
    // 0x90 = NOP
    std::vector<uint8_t> bytes = {0x90};
    auto result = disasm.disassemble(span_of(bytes), 0x1000);

    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0].address, 0x1000u);
    EXPECT_EQ(result[0].length, 1u);
    EXPECT_FALSE(result[0].is_call);
    EXPECT_FALSE(result[0].is_jump);
    EXPECT_FALSE(result[0].is_ret);
}

TEST(Disassembler, DecodesMultipleInstructions)
{
    const Disassembler disasm;
    // Three NOPs in a row
    std::vector<uint8_t> bytes = {0x90, 0x90, 0x90};
    auto result = disasm.disassemble(span_of(bytes), 0x2000);

    ASSERT_EQ(result.size(), 3u);
    EXPECT_EQ(result[0].address, 0x2000u);
    EXPECT_EQ(result[1].address, 0x2001u);
    EXPECT_EQ(result[2].address, 0x2002u);
}

// ─── Branch target resolution ───────────────────────

TEST(Disassembler, ResolvesDirectCallTarget)
{
    const Disassembler disasm;
    // E8 XX XX XX XX = CALL rel32
    // CALL 0x1234 from address 0x1000:
    //   target = next_instr_addr (0x1005) + rel32
    //   want target = 0x1234, so rel32 = 0x1234 - 0x1005 = 0x22F
    //   little-endian: 2F 02 00 00
    std::vector<uint8_t> bytes = {0xE8, 0x2F, 0x02, 0x00, 0x00};
    auto result = disasm.disassemble(span_of(bytes), 0x1000);

    ASSERT_EQ(result.size(), 1u);
    EXPECT_TRUE(result[0].is_call);
    EXPECT_FALSE(result[0].is_jump);
    EXPECT_EQ(result[0].branch_target, 0x1234u);
}

TEST(Disassembler, ResolvesUnconditionalJump)
{
    const Disassembler disasm;
    // EB XX = JMP rel8
    // JMP from 0x1000 to 0x100A:
    //   rel8 = 0x100A - (0x1000 + 2) = 0x08
    std::vector<uint8_t> bytes = {0xEB, 0x08};
    auto result = disasm.disassemble(span_of(bytes), 0x1000);

    ASSERT_EQ(result.size(), 1u);
    EXPECT_TRUE(result[0].is_jump);
    EXPECT_FALSE(result[0].is_conditional);
    EXPECT_EQ(result[0].branch_target, 0x100Au);
}

TEST(Disassembler, ResolvesConditionalJump)
{
    const Disassembler disasm;
    // 74 XX = JE rel8
    // JE from 0x1000 to 0x1010, rel8 = 0x10 - 2 = 0x0E
    std::vector<uint8_t> bytes = {0x74, 0x0E};
    auto result = disasm.disassemble(span_of(bytes), 0x1000);

    ASSERT_EQ(result.size(), 1u);
    EXPECT_TRUE(result[0].is_jump);
    EXPECT_TRUE(result[0].is_conditional);
    EXPECT_EQ(result[0].branch_target, 0x1010u);
}

TEST(Disassembler, IndirectCallHasNoBranchTarget)
{
    const Disassembler disasm;
    // FF D0 = CALL RAX (indirect call)
    std::vector<uint8_t> bytes = {0xFF, 0xD0};
    auto result = disasm.disassemble(span_of(bytes), 0x1000);

    ASSERT_EQ(result.size(), 1u);
    EXPECT_TRUE(result[0].is_call);
    EXPECT_EQ(result[0].branch_target, 0u)
        << "Indirect calls should have branch_target = 0";
}

// ─── RIP-relative addressing ────────────────────────

TEST(Disassembler, ResolvesLeaRipRelative)
{
    const Disassembler disasm;
    // 48 8D 0D XX XX XX XX = LEA RCX, [rip + disp32]
    // LEA RCX, [rip + 0x100] from address 0x1000:
    //   instruction length = 7
    //   target = 0x1000 + 7 + 0x100 = 0x1107
    std::vector<uint8_t> bytes = {0x48, 0x8D, 0x0D, 0x00, 0x01, 0x00, 0x00};
    auto result = disasm.disassemble(span_of(bytes), 0x1000);

    ASSERT_EQ(result.size(), 1u);
    EXPECT_TRUE(result[0].is_lea);
    EXPECT_FALSE(result[0].is_mem_read); // LEA computes address, doesn't read
    EXPECT_FALSE(result[0].is_mem_write);
    EXPECT_EQ(result[0].mem_absolute, 0x1107u);
}

TEST(Disassembler, ResolvesRipRelativeRead)
{
    const Disassembler disasm;
    // 48 8B 0D XX XX XX XX = MOV RCX, [rip + disp32]
    // MOV RCX, [rip + 0x200] from 0x1000:
    //   target = 0x1000 + 7 + 0x200 = 0x1207
    std::vector<uint8_t> bytes = {0x48, 0x8B, 0x0D, 0x00, 0x02, 0x00, 0x00};
    auto result = disasm.disassemble(span_of(bytes), 0x1000);

    ASSERT_EQ(result.size(), 1u);
    EXPECT_FALSE(result[0].is_lea);
    EXPECT_TRUE(result[0].is_mem_read);
    EXPECT_FALSE(result[0].is_mem_write);
    EXPECT_EQ(result[0].mem_absolute, 0x1207u);
}

TEST(Disassembler, ResolvesRipRelativeWrite)
{
    const Disassembler disasm;
    // 48 89 0D XX XX XX XX = MOV [rip + disp32], RCX
    // MOV [rip + 0x300], RCX from 0x1000:
    //   target = 0x1000 + 7 + 0x300 = 0x1307
    std::vector<uint8_t> bytes = {0x48, 0x89, 0x0D, 0x00, 0x03, 0x00, 0x00};
    auto result = disasm.disassemble(span_of(bytes), 0x1000);

    ASSERT_EQ(result.size(), 1u);
    EXPECT_FALSE(result[0].is_mem_read);
    EXPECT_TRUE(result[0].is_mem_write);
    EXPECT_EQ(result[0].mem_absolute, 0x1307u);
}

// ─── Return / classification ────────────────────────

TEST(Disassembler, RecognizesReturn)
{
    const Disassembler disasm;
    // C3 = RET
    std::vector<uint8_t> bytes = {0xC3};
    auto result = disasm.disassemble(span_of(bytes), 0x1000);

    ASSERT_EQ(result.size(), 1u);
    EXPECT_TRUE(result[0].is_ret);
    EXPECT_FALSE(result[0].is_call);
    EXPECT_FALSE(result[0].is_jump);
}

// ─── Realistic prologue ─────────────────────────────

TEST(Disassembler, DecodesTypicalFunctionPrologue)
{
    const Disassembler disasm;
    // Typical x64 prologue:
    //   53                push rbx
    //   48 83 EC 20       sub rsp, 0x20
    //   48 8B D9          mov rbx, rcx
    //   C3                ret
    std::vector<uint8_t> bytes = {
        0x53,
        0x48, 0x83, 0xEC, 0x20,
        0x48, 0x8B, 0xD9,
        0xC3};
    auto result = disasm.disassemble(span_of(bytes), 0x4000);

    ASSERT_EQ(result.size(), 4u);
    EXPECT_EQ(result[0].length, 1u); // push rbx
    EXPECT_EQ(result[1].length, 4u); // sub rsp, 0x20
    EXPECT_EQ(result[2].length, 3u); // mov rbx, rcx
    EXPECT_EQ(result[3].length, 1u); // ret
    EXPECT_TRUE(result[3].is_ret);
}

// ─── Stop-on-invalid behavior ───────────────────────

TEST(Disassembler, StopsOnInvalidByte)
{
    const Disassembler disasm;
    // NOP, then 0x06 — invalid in x64 long mode (was PUSH ES in 32-bit)
    std::vector<uint8_t> bytes = {0x90, 0x06};
    auto result = disasm.disassemble(span_of(bytes), 0x1000);

    // We should get the NOP, then stop at the invalid byte
    ASSERT_GE(result.size(), 1u);
    EXPECT_EQ(result[0].address, 0x1000u);
    // No more decoded instructions after the invalid one
    EXPECT_LE(result.size(), 1u);
}

// ─── Callback variant ───────────────────────────────

TEST(Disassembler, CallbackCanStopEarly)
{
    const Disassembler disasm;
    std::vector<uint8_t> bytes = {0x90, 0x90, 0x90, 0x90};

    int count = 0;
    disasm.disassemble_cb(span_of(bytes), 0x1000,
                          [&](const Instruction&)
                          {
                              count++;
                              return count < 2; // stop after 2 instructions
                          });
    EXPECT_EQ(count, 2);
}