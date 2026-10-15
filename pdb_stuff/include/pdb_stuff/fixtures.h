#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

namespace pdb_stuff
{

    using Bytes = std::vector<std::uint8_t>;
    using Json = nlohmann::json;
    using FileValidator = std::function<Json(std::span<const std::uint8_t>)>;
    using DownloadFn = std::function<Bytes(std::string_view, bool)>;

    inline constexpr std::string_view symbol_server = "https://msdl.microsoft.com/download/symbols";
    inline constexpr std::string_view winbindex_url =
        "https://winbindex.m417z.com/data/by_filename_compressed/ntdll.dll.json.gz";
    inline constexpr std::size_t max_download_bytes = 256u * 1024u * 1024u;
    inline constexpr std::size_t max_dll_bytes = 16u * 1024u * 1024u;
    inline constexpr std::size_t max_archive_unpacked_bytes = 1024u * 1024u * 1024u;

    class FixtureError : public std::runtime_error
    {
        public:
            using std::runtime_error::runtime_error;
    };

    class NetworkDisabled : public FixtureError
    {
        public:
            using FixtureError::FixtureError;
    };

    // All executable files are parsed as bytes; none are loaded or executed.
    std::string sha256(std::span<const std::uint8_t> data);
    Json parse_pe(std::span<const std::uint8_t> data);
    Json parse_pdb_identity(std::span<const std::uint8_t> data);
    Json validate_pe(std::span<const std::uint8_t> data, const Json& expected);
    Json validate_pdb(std::span<const std::uint8_t> data, const Json& image_identity,
                      std::string_view expected_hash = {});
    std::string dll_url(const Json& identity);
    std::string pdb_url(const Json& identity);

    Bytes read_file(const std::filesystem::path& path, std::size_t max_bytes = max_download_bytes);
    Json read_json(const std::filesystem::path& path);
    Json atomic_write(const std::filesystem::path& path, std::span<const std::uint8_t> data,
                      const FileValidator& validator = {});
    void write_json(const std::filesystem::path& path, const Json& value);

    Json ensure_file(const std::filesystem::path& path, std::string_view url,
                     const FileValidator& validator, bool allow_network,
                     const DownloadFn& downloader = {});
    void validate_archive_config(const Json& archive);
    Json validate_archive(std::span<const std::uint8_t> data, const Json& archive);
    Json ensure_image_file(const std::filesystem::path& path, const Json& expected,
                           const Json& archive, const std::filesystem::path& output_root,
                           bool allow_network, const DownloadFn& downloader = {});

    Json process_fixture(const Json& entry, const std::filesystem::path& output_root,
                         bool allow_network,
                         const std::optional<std::filesystem::path>& source_dll = {},
                         const std::optional<std::filesystem::path>& source_pdb = {},
                         const DownloadFn& downloader = {});
    // Metadata is the original gzip JSON; its SHA256 is recorded as provenance.
    void refresh_client_pins(Json& manifest, std::span<const std::uint8_t> metadata);

    struct FetchOptions
    {
            std::filesystem::path manifest_path;
            std::filesystem::path output_root;
            std::vector<std::string> labels;
            bool allow_network = false;
            bool allow_missing = false;
            std::optional<std::filesystem::path> source_dll;
            std::optional<std::filesystem::path> source_pdb;
            std::string source_url;
            std::string os;
            bool refresh_winbindex = false;
            std::optional<std::filesystem::path> winbindex_metadata;
            DownloadFn download;
    };

    struct FetchResult
    {
            Json fixtures = Json::array(); // Selected results; previous aggregate entries are preserved on disk.
            bool successful = false;
    };

    FetchResult process_manifest(const FetchOptions& options);

} // namespace pdb_stuff
