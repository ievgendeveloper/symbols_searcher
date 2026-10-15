#pragma once

#include "pdb_stuff/fixtures.h"

namespace pdb_stuff
{
    struct CorpusResult
    {
            Json fixtures = Json::array();
            bool successful = false;
            bool provisioned = false;
            std::string reason;
            std::filesystem::path staging_root;
            std::filesystem::path report_manifest;
    };

    // Validate all required pins without changing cached bytes or metadata.
    // Invalid existing pinned data throws FixtureError; absent data requires
    // explicit network opt-in. Downloads and publication failures return a
    // retained staging/report path and never replace an existing live file.
    [[nodiscard]] CorpusResult ensure_corpus(
        const std::filesystem::path& manifest_path,
        const std::filesystem::path& corpus_root,
        bool allow_network = false, const DownloadFn& downloader = {});

    // Download every manifest entry into a new empty run, with its own corpus
    // and archives. Related live/check paths are rejected after canonicalizing
    // existing symlinks. Both successful and failed runs remain inspectable.
    [[nodiscard]] CorpusResult verify_fresh_corpus(
        const std::filesystem::path& manifest_path,
        const std::filesystem::path& check_root,
        const std::filesystem::path& protected_corpus_root,
        bool allow_network = false, const DownloadFn& downloader = {});
} // namespace pdb_stuff
