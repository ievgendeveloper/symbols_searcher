#pragma once

#include "pdb_stuff/fixtures.h"

#include <cstddef>
#include <filesystem>
#include <string_view>

namespace pdb_stuff
{
    // These operations never write fixture files. Core validates hashes and
    // publishes the returned data atomically after successful validation.
    [[nodiscard]] bool is_supported_download_url(std::string_view url);
    [[nodiscard]] Bytes download(std::string_view url, bool allow_network);
    [[nodiscard]] Bytes gzip_decompress(const Bytes& data);

    // Stream a tar.gz and return one exact regular-file member, without
    // extracting filesystem paths. Both expansion and payload are bounded.
    [[nodiscard]] Bytes read_archive_member(
        const std::filesystem::path& archive, std::string_view exact_member,
        std::size_t max_payload = 16 * 1024 * 1024,
        std::size_t max_scan = 1024ull * 1024 * 1024);
} // namespace pdb_stuff
