#pragma once

#include <array>
#include <string_view>

namespace symfind::validation
{
    struct NamedRule
    {
            std::string_view symbol;
            std::string_view script;
    };

    // Shared rules for matcher tests and independent PDB validation.
    inline constexpr std::array ntdllSymbolRules = {
        NamedRule{"LdrpInitialize", R"(
            find function in "ntdll" where
                called_by "LdrInitializeThunk";
                not exported;
                take first;
        )"},
        NamedRule{"LdrpLoadDll", R"(
            find function in "ntdll" where
                called_by "LdrLoadDll";
                not exported;
                stack_frame_size >= 0x80;
                stack_frame_size <= 0x200;
                calls_count >= 4;
        )"},
        NamedRule{"RtlDecompressBufferProcs", R"(
            find global in "ntdll" where
                referenced_by "RtlDecompressBuffer";
                take first;
        )"},
    };

    [[nodiscard]] constexpr std::string_view NtdllRuleFor(std::string_view symbolName)
    {
        for (const auto& symbolRule : ntdllSymbolRules)
        {
            if (symbolRule.symbol == symbolName)
            {
                return symbolRule.script;
            }
        }
        return {};
    }
} // namespace symfind::validation
