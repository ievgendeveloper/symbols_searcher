#pragma once

#include "pdb_stuff/fixtures.h"

#include <cstddef>
#include <filesystem>
#include <string_view>

namespace pdbStuff
{
    // These operations never write fixture files. Core validates hashes and
    // publishes the returned data atomically after successful validation.
    [[nodiscard]] bool IsSupportedDownloadUrl(std::string_view url);
    [[nodiscard]] Bytes Download(std::string_view url, bool allowNetwork);
    [[nodiscard]] Bytes GzipDecompress(const Bytes& data);

    // Stream a tar.gz and return one exact regular-file member, without
    // extracting filesystem paths. Both expansion and payload are bounded.
    [[nodiscard]] Bytes ReadArchiveMember(const std::filesystem::path& archive,
                                          std::string_view exactMember,
                                          std::size_t maxPayload = 16 * 1024 * 1024,
                                          std::size_t maxScan = 1024ull * 1024 * 1024);
} // namespace pdbStuff
