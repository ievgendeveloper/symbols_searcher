#include "symfind/disassembler.h"

#include <Zydis/Zydis.h>
#include <spdlog/spdlog.h>

namespace symfind {

struct Disassembler::Impl {
    ZydisDecoder decoder;
};

Disassembler::Disassembler() : impl_(std::make_unique<Impl>()) {
    ZydisDecoderInit(&impl_->decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
}

Disassembler::~Disassembler() = default;

std::vector<Instruction> Disassembler::disassemble(std::span<const uint8_t> code,
                                                    uint64_t base_address) const {
    std::vector<Instruction> result;

    disassemble_cb(code, base_address, [&](const Instruction& instr) {
        result.push_back(instr);
        return true;
    });

    return result;
}

void Disassembler::disassemble_cb(std::span<const uint8_t> code,
                                   uint64_t base_address,
                                   const std::function<bool(const Instruction&)>& callback) const {
    ZydisDecodedInstruction zinstr;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    size_t offset = 0;

    while (offset < code.size()) {
        auto status = ZydisDecoderDecodeFull(
            &impl_->decoder,
            code.data() + offset,
            code.size() - offset,
            &zinstr,
            operands);

        if (!ZYAN_SUCCESS(status)) break;

        Instruction instr;
        instr.address = base_address + offset;
        instr.length = zinstr.length;

        // Classify instruction
        const auto cat = zinstr.meta.category;
        instr.is_call = (cat == ZYDIS_CATEGORY_CALL);
        instr.is_ret  = (cat == ZYDIS_CATEGORY_RET);
        instr.is_jump = (cat == ZYDIS_CATEGORY_COND_BR || cat == ZYDIS_CATEGORY_UNCOND_BR);
        instr.is_conditional = (cat == ZYDIS_CATEGORY_COND_BR);
        instr.is_lea  = (zinstr.mnemonic == ZYDIS_MNEMONIC_LEA);

        // Resolve branch target for direct call/jmp
        if ((instr.is_call || instr.is_jump) &&
            operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            ZyanU64 target = 0;
            ZydisCalcAbsoluteAddress(&zinstr, &operands[0], instr.address, &target);
            instr.branch_target = target;
        }

        // Resolve RIP-relative memory operands
        for (int i = 0; i < zinstr.operand_count; ++i) {
            if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                operands[i].mem.base == ZYDIS_REGISTER_RIP) {
                ZyanU64 addr = 0;
                ZydisCalcAbsoluteAddress(&zinstr, &operands[i], instr.address, &addr);
                instr.mem_absolute = addr;

                if (instr.is_lea) {
                    // lea = address reference, not read/write
                } else if (operands[i].actions & ZYDIS_OPERAND_ACTION_READ) {
                    instr.is_mem_read = true;
                } else if (operands[i].actions & ZYDIS_OPERAND_ACTION_WRITE) {
                    instr.is_mem_write = true;
                }
                break;
            }
        }

        if (!callback(instr)) break;
        offset += zinstr.length;
    }
}

} // namespace symfind
