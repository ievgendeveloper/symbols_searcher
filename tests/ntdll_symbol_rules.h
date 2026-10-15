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
    inline constexpr std::array ntdll_symbol_rules = {
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

    [[nodiscard]] constexpr std::string_view ntdll_rule_for(std::string_view symbol)
    {
        for (const auto& rule : ntdll_symbol_rules)
            if (rule.symbol == symbol)
                return rule.script;
        return {};
    }
} // namespace symfind::validation
