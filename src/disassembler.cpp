#include "symfind/disassembler.h"

#include <Zydis/Zydis.h>
#include <spdlog/spdlog.h>

namespace symfind
{
    struct Disassembler::Implementation
    {
        ZydisDecoder decoder;
    };

    Disassembler::Disassembler() : impl_(std::make_unique<Implementation>())
    {
        ZydisDecoderInit(&impl_->decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    }

    Disassembler::~Disassembler() = default;

    std::vector<Instruction> Disassembler::disassemble(std::span<const uint8_t> code,
                                                       uint64_t base_address) const
    {
        std::vector<Instruction> result;

        disassemble_cb(code, base_address, [&](const Instruction& instr)
        {
            result.push_back(instr);
            return true;
        });

        return result;
    }

    void Disassembler::disassemble_cb(std::span<const uint8_t> code,
                                      uint64_t base_address,
                                      const std::function<bool(const Instruction&)>& callback) const
    {
        ZydisDecodedInstruction zydisInstruction{};
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
        size_t offset = 0;

        while (offset < code.size())
        {
            const auto status = ZydisDecoderDecodeFull(
                &impl_->decoder,
                code.data() + offset,
                code.size() - offset,
                &zydisInstruction,
                operands);

            if (!ZYAN_SUCCESS(status))
            {
                break;
            }

            Instruction instruction;
            instruction.address = base_address + offset;
            instruction.length = zydisInstruction.length;

            // Classify instruction
            const auto cat = zydisInstruction.meta.category;
            instruction.is_call = (cat == ZYDIS_CATEGORY_CALL);
            instruction.is_ret = (cat == ZYDIS_CATEGORY_RET);
            instruction.is_jump = (cat == ZYDIS_CATEGORY_COND_BR || cat == ZYDIS_CATEGORY_UNCOND_BR);
            instruction.is_conditional = (cat == ZYDIS_CATEGORY_COND_BR);
            instruction.is_lea = (zydisInstruction.mnemonic == ZYDIS_MNEMONIC_LEA);

            // Resolve branch target for direct call/jmp
            if ((instruction.is_call || instruction.is_jump) &&
                operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                ZyanU64 target = 0;
                ZydisCalcAbsoluteAddress(&zydisInstruction, &operands[0], instruction.address, &target);
                instruction.branch_target = target;
            }

            // Resolve RIP-relative memory operands
            for (size_t i = 0; i < zydisInstruction.operand_count; ++i)
            {
                if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    operands[i].mem.base == ZYDIS_REGISTER_RIP)
                {
                    ZyanU64 absoluteAddress = 0;
                    ZydisCalcAbsoluteAddress(&zydisInstruction, &operands[i], instruction.address, &absoluteAddress);
                    instruction.mem_absolute = absoluteAddress;

                    if (instruction.is_lea)
                    {
                        // lea = address reference, not read/write
                    }
                    else if (operands[i].actions & ZYDIS_OPERAND_ACTION_READ)
                    {
                        instruction.is_mem_read = true;
                    }
                    else if (operands[i].actions & ZYDIS_OPERAND_ACTION_WRITE)
                    {
                        instruction.is_mem_write = true;
                    }
                    break;
                }
            }

            if (!callback(instruction))
            {
                break;
            }

            offset += zydisInstruction.length;
        }
    }

} // namespace symfind