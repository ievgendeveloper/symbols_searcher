#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include <span>
#include <optional>

namespace symfind {

/// Represents an exported symbol from a PE module.
struct ExportEntry {
    std::string name;
    uint64_t    rva = 0;       ///< Relative virtual address
    uint16_t    ordinal = 0;
};

/// Represents a PE section.
struct Section {
    std::string name;
    uint64_t    virtual_address = 0;
    uint64_t    virtual_size = 0;
    uint64_t    raw_offset = 0;
    uint64_t    raw_size = 0;
    bool        executable = false;
    bool        readable = false;
    bool        writable = false;
};

/// Wraps a PE module (loaded from file or memory).
/// Uses LIEF internally for PE parsing.
class PeModule {
public:
    /// Load from file on disk.
    [[nodiscard]] static std::optional<PeModule> from_file(const std::string& path);

    /// Load from raw bytes already in memory.
    [[nodiscard]] static std::optional<PeModule> from_memory(std::span<const uint8_t> data,
                                                              uint64_t base_address = 0);

    /// Module name (e.g. "ntdll.dll").
    [[nodiscard]] const std::string& name() const;

    /// Image base address.
    [[nodiscard]] uint64_t image_base() const;

    /// All exports.
    [[nodiscard]] const std::vector<ExportEntry>& exports() const;

    /// All sections.
    [[nodiscard]] const std::vector<Section>& sections() const;

    /// Check if an RVA belongs to an exported symbol.
    [[nodiscard]] bool is_exported(uint64_t rva) const;

    /// Look up export by name. Returns RVA or nullopt.
    [[nodiscard]] std::optional<uint64_t> export_rva(const std::string& name) const;

    /// Read bytes at a given RVA from the mapped image.
    [[nodiscard]] std::span<const uint8_t> read_at(uint64_t rva, size_t length) const;

    /// Get the raw mapped image bytes.
    [[nodiscard]] std::span<const uint8_t> raw_image() const;

private:
    struct Impl;
    std::shared_ptr<Impl> impl_;
};

} // namespace symfind
