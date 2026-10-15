#pragma once

#include "pdb_stuff/fixtures.h"

#include <span>
#include <string_view>

namespace pdb_stuff
{
    // Inspects PA30 bytes as data, optionally relating their target MD5 to a
    // Winbindex metadata document. Also accepts Windows Update's CRC prefix.
    [[nodiscard]] Json inspect_delta(std::span<const uint8_t> patch,
                                     const Json& winbindex = Json{});

    // Reconstructs bytes without loading or executing the resulting image.
    // A supplied SHA256 pin must match before any result is returned.
    [[nodiscard]] Bytes apply_delta(std::span<const uint8_t> source,
                                    std::span<const uint8_t> patch,
                                    std::string_view expected_sha256 = {});
} // namespace pdb_stuff
