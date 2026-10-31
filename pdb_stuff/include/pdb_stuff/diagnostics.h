#pragma once

#include "pdb_stuff/fixtures.h"

#include <nonstd/span.hpp>
#include <string_view>

namespace pdbStuff
{
    // Inspects PA30 bytes as data, optionally relating their target MD5 to a
    // Winbindex metadata document. Also accepts Windows Update's CRC prefix.
    [[nodiscard]] Json InspectDelta(nonstd::span<const uint8_t> patch,
                                    const Json& winbindex = Json{});

    // Reconstructs bytes without loading or executing the resulting image.
    // A supplied SHA256 pin must match before any result is returned.
    [[nodiscard]] Bytes ApplyDeltaPatch(nonstd::span<const uint8_t> source,
                                        nonstd::span<const uint8_t> patch,
                                        std::string_view expectedSha256 = {});
} // namespace pdbStuff
