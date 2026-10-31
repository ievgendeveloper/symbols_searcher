#pragma once

#include "pdb_stuff/fixtures.h"

namespace pdbStuff
{
    struct CorpusResult
    {
            Json fixtures = Json::array();
            bool successful = false;
            bool provisioned = false;
            std::string reason;
            std::filesystem::path stagingRoot;
            std::filesystem::path reportManifest;
    };

    // Validate all required pins without changing cached bytes or metadata.
    // Invalid existing pinned data throws FixtureError; absent data requires
    // explicit network opt-in. Downloads and publication failures return a
    // retained staging/report path and never replace an existing live file.
    [[nodiscard]] CorpusResult EnsureCorpus(const std::filesystem::path& manifestPath,
                                            const std::filesystem::path& corpusRoot,
                                            bool allowNetwork = false,
                                            const DownloadFn& downloader = {});

    // Download every manifest entry into a new empty run, with its own corpus
    // and archives. Related live/check paths are rejected after canonicalizing
    // existing symlinks. Both successful and failed runs remain inspectable.
    [[nodiscard]] CorpusResult VerifyFreshCorpus(const std::filesystem::path& manifestPath,
                                                 const std::filesystem::path& checkRoot,
                                                 const std::filesystem::path& protectedCorpusRoot,
                                                 bool allowNetwork = false,
                                                 const DownloadFn& downloader = {});
} // namespace pdbStuff
