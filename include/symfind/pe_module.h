#pragma once

#include <cstdint>
#include <memory>
#include <nonstd/span.hpp>
#include <optional>
#include <string>
#include <vector>

namespace symfind
{
    /// One actual code span; gaps between spans do not belong to the function.
    struct FunctionRange
    {
            uint64_t rva = 0;
            uint64_t size = 0;
    };

    struct FunctionBounds
    {
            uint64_t rva;
            uint64_t size; ///< Size of the primary contiguous span, not the sum of ranges.
            std::vector<FunctionRange> ranges; ///< Primary and verified chained-unwind spans.
    };

    /// Represents an exported symbol from a PE module.
    struct ExportEntry
    {
            std::string name;
            uint64_t rva = 0; ///< Relative virtual address
            uint16_t ordinal = 0;
    };

    /// Represents a PE section.
    struct Section
    {
            std::string name;
            uint64_t virtualAddress = 0;
            uint64_t virtualSize = 0;
            uint64_t rawOffset = 0;
            uint64_t rawSize = 0;
            bool executable = false;
            bool readable = false;
            bool writable = false;
    };

    /// Wraps a PE module (loaded from file or memory).
    /// Uses LIEF internally for PE parsing.
    class PeModule
    {
        public:
            /// Load from file on disk.
            [[nodiscard]] static std::optional<PeModule> FromFile(const std::string& filePath);

            /// Load from raw bytes already in memory.
            [[nodiscard]] static std::optional<PeModule> FromMemory(
                nonstd::span<const uint8_t> peBytes, uint64_t baseAddress = 0);

            /// PE export-directory DLL basename (e.g. "ntdll.dll").
            /// Files without this identity use the input filename; memory-only
            /// modules without an export-directory name have an empty name.
            [[nodiscard]] const std::string& Name() const;

            /// Image base address.
            [[nodiscard]] uint64_t ImageBase() const;

            /// All exports.
            [[nodiscard]] const std::vector<ExportEntry>& Exports() const;

            /// All sections.
            [[nodiscard]] const std::vector<Section>& Sections() const;

            /// Check if an RVA belongs to an exported symbol.
            [[nodiscard]] bool IsExported(uint64_t symbolRva) const;

            /// Look up export by name. Returns RVA or nullopt.
            [[nodiscard]] std::optional<uint64_t> ExportRva(const std::string& exportName) const;

            /// Read bytes at a given RVA from the mapped image.
            [[nodiscard]] nonstd::span<const uint8_t> ReadAt(uint64_t startRva,
                                                             size_t byteCount) const;

            /// Get the raw mapped image bytes.
            [[nodiscard]] nonstd::span<const uint8_t> RawImage() const;

            /**
             * @brief Get the full enumeration of RVA of function addresses and the size of
             * functions
             * @return the vector of structs with rva of the beginning and size of function
             */
            [[nodiscard]] const std::vector<FunctionBounds>& ExceptionFunctions() const;

            /// Canonical procedure entry for an address in a verified code span.
            /// Ranges are end-exclusive; unknown/ambiguous addresses return nullopt.
            [[nodiscard]] std::optional<uint64_t> CanonicalFunctionRva(
                uint64_t instructionRva) const;

        private:
            struct Impl;
            std::shared_ptr<Impl> m_impl;
    };

} // namespace symfind
