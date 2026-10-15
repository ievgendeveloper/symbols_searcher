#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <vector>

namespace symfind
{
    /// A decoded instruction.
    struct Instruction
    {
            uint64_t address = 0;
            uint8_t length = 0;
            bool is_call = false;
            bool is_jump = false;
            bool is_ret = false;
            bool is_conditional = false;

            /// For call/jump — absolute target address (0 if indirect/unknown).
            uint64_t branch_target = 0;

            /// For RIP-relative memory operands (lea, mov) — absolute address.
            /// Zero if not applicable.
            uint64_t mem_absolute = 0;

            /// True if this is a LEA instruction (address reference, not memory read).
            bool is_lea = false;

            /// True if instruction reads from memory (mov reg, [addr]).
            bool is_mem_read = false;

            /// True if instruction writes to memory (mov [addr], reg).
            bool is_mem_write = false;

            /// True if instruction is `sub rsp, <imm>`.
            bool is_sub_rsp_imm = false;

            /// Immediate value for instructions where it's meaningful
            /// (currently: sub rsp, imm).
            int64_t imm_value = 0;
    };

    /// Thin wrapper around Zydis for linear disassembly.
    class Disassembler
    {
        public:
            Disassembler();
            ~Disassembler();

            /// Disassemble a block of code starting at `base_address`.
            /// Stops at the first invalid instruction or end of `code`.
            [[nodiscard]] std::vector<Instruction> disassemble(std::span<const uint8_t> code,
                                                               uint64_t base_address) const;

            /// Disassemble with a callback — avoids allocating a vector.
            /// Return false from callback to stop.
            void disassemble_cb(std::span<const uint8_t> code,
                                uint64_t base_address,
                                const std::function<bool(const Instruction&)>& callback) const;

        private:
            struct Implementation;
            std::unique_ptr<Implementation> impl_;
    };

} // namespace symfind