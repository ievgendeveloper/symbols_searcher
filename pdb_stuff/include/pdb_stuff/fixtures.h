#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <nonstd/span.hpp>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

namespace pdbStuff
{

    using Bytes = std::vector<std::uint8_t>;
    using Json = nlohmann::json;
    using FileValidator = std::function<Json(nonstd::span<const std::uint8_t>)>;
    using DownloadFn = std::function<Bytes(std::string_view, bool)>;

    inline constexpr std::string_view symbolServer = "https://msdl.microsoft.com/download/symbols";
    inline constexpr std::string_view winbindexUrl =
        "https://winbindex.m417z.com/data/by_filename_compressed/ntdll.dll.json.gz";
    inline constexpr std::size_t maxDownloadBytes = 256u * 1024u * 1024u;
    inline constexpr std::size_t maxDllBytes = 16u * 1024u * 1024u;
    inline constexpr std::size_t maxArchiveUnpackedBytes = 1024u * 1024u * 1024u;

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
    std::string Sha256(nonstd::span<const std::uint8_t> data);
    Json ParsePe(nonstd::span<const std::uint8_t> data);
    Json ParsePdbIdentity(nonstd::span<const std::uint8_t> data);
    Json ValidatePe(nonstd::span<const std::uint8_t> data, const Json& expected);
    Json ValidatePdb(nonstd::span<const std::uint8_t> data, const Json& imageIdentity,
                     std::string_view expectedHash = {});
    std::string DllUrl(const Json& identity);
    std::string PdbUrl(const Json& identity);

    Bytes ReadFile(const std::filesystem::path& path, std::size_t maxBytes = maxDownloadBytes);
    Json ReadJson(const std::filesystem::path& path);
    Json AtomicWrite(const std::filesystem::path& path, nonstd::span<const std::uint8_t> data,
                     const FileValidator& validator = {});
    void WriteJson(const std::filesystem::path& path, const Json& value);

    Json EnsureFile(const std::filesystem::path& path, std::string_view url,
                    const FileValidator& validator, bool allowNetwork,
                    const DownloadFn& downloader = {});
    void ValidateArchiveConfig(const Json& archive);
    Json ValidateArchive(nonstd::span<const std::uint8_t> data, const Json& archive);
    Json EnsureImageFile(const std::filesystem::path& path, const Json& expected,
                         const Json& archive, const std::filesystem::path& outputRoot,
                         bool allowNetwork, const DownloadFn& downloader = {});

    Json ProcessFixture(const Json& entry, const std::filesystem::path& outputRoot,
                        bool allowNetwork,
                        const std::optional<std::filesystem::path>& sourceDll = {},
                        const std::optional<std::filesystem::path>& sourcePdb = {},
                        const DownloadFn& downloader = {});
    // Metadata is the original gzip JSON; its SHA256 is recorded as provenance.
    void RefreshClientPins(Json& manifest, nonstd::span<const std::uint8_t> metadata);

    struct FetchOptions
    {
            std::filesystem::path manifestPath;
            std::filesystem::path outputRoot;
            std::vector<std::string> labels;
            bool allowNetwork = false;
            bool allowMissing = false;
            std::optional<std::filesystem::path> sourceDll;
            std::optional<std::filesystem::path> sourcePdb;
            std::string sourceUrl;
            std::string os;
            bool refreshWinbindex = false;
            std::optional<std::filesystem::path> winbindexMetadata;
            DownloadFn download;
    };

    struct FetchResult
    {
            Json fixtures = Json::array(); // Selected results; previous aggregate entries are
                                           // preserved on disk.
            bool successful = false;
    };

    FetchResult ProcessManifest(const FetchOptions& options);

} // namespace pdbStuff
