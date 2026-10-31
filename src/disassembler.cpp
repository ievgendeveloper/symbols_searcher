#include "symfind/disassembler.h"

#include <Zydis/Zydis.h>
#include <spdlog/spdlog.h>

namespace symfind
{
    struct Disassembler::Implementation
    {
            ZydisDecoder decoder;
    };

    Disassembler::Disassembler() : m_impl(std::make_unique<Implementation>())
    {
        ZydisDecoderInit(&m_impl->decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    }

    Disassembler::~Disassembler() = default;

    std::vector<Instruction> Disassembler::Disassemble(nonstd::span<const uint8_t> codeBytes,
                                                       uint64_t baseAddress) const
    {
        std::vector<Instruction> decodedInstructions;

        DisassembleCb(codeBytes, baseAddress,
                      [&](const Instruction& instruction)
                      {
                          decodedInstructions.push_back(instruction);
                          return true;
                      });

        return decodedInstructions;
    }

    void Disassembler::DisassembleCb(
        nonstd::span<const uint8_t> codeBytes, uint64_t baseAddress,
        const std::function<bool(const Instruction&)>& instructionCallback) const
    {
        ZydisDecodedInstruction decodedInstruction{};
        ZydisDecodedOperand decodedOperands[ZYDIS_MAX_OPERAND_COUNT]{};
        size_t instructionOffset = 0;

        while (instructionOffset < codeBytes.size())
        {
            const auto decodeStatus = ZydisDecoderDecodeFull(
                &m_impl->decoder, codeBytes.data() + instructionOffset,
                codeBytes.size() - instructionOffset, &decodedInstruction, decodedOperands);

            if (!ZYAN_SUCCESS(decodeStatus))
            {
                break;
            }

            Instruction instruction;
            instruction.address = baseAddress + instructionOffset;
            instruction.length = decodedInstruction.length;

            // Classify instruction
            const auto instructionCategory = decodedInstruction.meta.category;
            instruction.isCall = (instructionCategory == ZYDIS_CATEGORY_CALL);
            instruction.isRet = (instructionCategory == ZYDIS_CATEGORY_RET);
            instruction.isJump = (instructionCategory == ZYDIS_CATEGORY_COND_BR ||
                                  instructionCategory == ZYDIS_CATEGORY_UNCOND_BR);
            instruction.isConditional = (instructionCategory == ZYDIS_CATEGORY_COND_BR);
            instruction.isLea = (decodedInstruction.mnemonic == ZYDIS_MNEMONIC_LEA);

            // Resolve branch target for direct call/jmp
            if ((instruction.isCall || instruction.isJump) &&
                decodedOperands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                ZyanU64 branchTargetAddress = 0;
                ZydisCalcAbsoluteAddress(&decodedInstruction, &decodedOperands[0],
                                         instruction.address, &branchTargetAddress);
                instruction.branchTarget = branchTargetAddress;
            }

            // Detect `sub rsp, imm`
            if (decodedInstruction.mnemonic == ZYDIS_MNEMONIC_SUB &&
                decodedInstruction.operand_count >= 2 &&
                decodedOperands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                decodedOperands[0].reg.value == ZYDIS_REGISTER_RSP &&
                decodedOperands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                instruction.isSubRspImm = true;
                instruction.immValue = decodedOperands[1].imm.value.s; // signed immediate
            }

            // Resolve RIP-relative memory operands
            for (size_t operandIndex = 0; operandIndex < decodedInstruction.operand_count;
                 ++operandIndex)
            {
                if (decodedOperands[operandIndex].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    decodedOperands[operandIndex].mem.base == ZYDIS_REGISTER_RIP)
                {
                    ZyanU64 memoryOperandAddress = 0;
                    ZydisCalcAbsoluteAddress(&decodedInstruction, &decodedOperands[operandIndex],
                                             instruction.address, &memoryOperandAddress);
                    instruction.memAbsolute = memoryOperandAddress;

                    if (instruction.isLea)
                    {
                        // lea = address reference, not read/write
                    }
                    else if (decodedOperands[operandIndex].actions & ZYDIS_OPERAND_ACTION_READ)
                    {
                        instruction.isMemRead = true;
                    }
                    else if (decodedOperands[operandIndex].actions & ZYDIS_OPERAND_ACTION_WRITE)
                    {
                        instruction.isMemWrite = true;
                    }
                    break;
                }
            }

            if (!instructionCallback(instruction))
            {
                break;
            }

            instructionOffset += decodedInstruction.length;
        }
    }

} // namespace symfind