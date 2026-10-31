#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <nonstd/span.hpp>
#include <vector>

namespace symfind
{
    /// A decoded instruction.
    struct Instruction
    {
            uint64_t address = 0;
            uint8_t length = 0;
            bool isCall = false;
            bool isJump = false;
            bool isRet = false;
            bool isConditional = false;

            /// For call/jump — absolute target address (0 if indirect/unknown).
            uint64_t branchTarget = 0;

            /// For RIP-relative memory operands (lea, mov) — absolute address.
            /// Zero if not applicable.
            uint64_t memAbsolute = 0;

            /// True if this is a LEA instruction (address reference, not memory read).
            bool isLea = false;

            /// True if instruction reads from memory (mov reg, [addr]).
            bool isMemRead = false;

            /// True if instruction writes to memory (mov [addr], reg).
            bool isMemWrite = false;

            /// True if instruction is `sub rsp, <imm>`.
            bool isSubRspImm = false;

            /// Immediate value for instructions where it's meaningful
            /// (currently: sub rsp, imm).
            int64_t immValue = 0;
    };

    /// Thin wrapper around Zydis for linear disassembly.
    class Disassembler
    {
        public:
            Disassembler();
            ~Disassembler();

            /// Disassemble a block of code starting at `baseAddress`.
            /// Stops at the first invalid instruction or end of `codeBytes`.
            [[nodiscard]] std::vector<Instruction> Disassemble(
                nonstd::span<const uint8_t> codeBytes, uint64_t baseAddress) const;

            /// Disassemble with a callback — avoids allocating a vector.
            /// Return false from instructionCallback to stop.
            void DisassembleCb(
                nonstd::span<const uint8_t> codeBytes, uint64_t baseAddress,
                const std::function<bool(const Instruction&)>& instructionCallback) const;

        private:
            struct Implementation;
            std::unique_ptr<Implementation> m_impl;
    };

} // namespace symfind