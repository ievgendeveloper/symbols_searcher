#pragma once

#include <string_view>

namespace symfind
{
    inline bool StartsWith(std::string_view text, std::string_view prefix) noexcept
    {
        return text.size() >= prefix.size() && text.compare(0, prefix.size(), prefix) == 0;
    }

    inline bool EndsWith(std::string_view text, std::string_view suffix) noexcept
    {
        return text.size() >= suffix.size() &&
               text.compare(text.size() - suffix.size(), suffix.size(), suffix) == 0;
    }
} // namespace symfind
