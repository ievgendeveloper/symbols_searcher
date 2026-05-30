#include "symfind/pe_module.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <LIEF/PE.hpp>
#include <spdlog/spdlog.h>
#include <unordered_map>
#include <unordered_set>
#include <set>

namespace symfind
{
    struct PeModule::Impl
    {
        std::string fullPath;
        uint64_t image_base = 0;
        std::vector<ExportEntry> exports;
        std::vector<Section> sections;
        std::vector<uint8_t> raw_data;
        std::unordered_map<std::string, uint64_t> export_map;
        std::unordered_set<uint64_t> export_rvas;
        std::vector<FunctionBounds> m_exception_functions;
    };

    static std::vector<uint8_t> map_image(LIEF::PE::Binary& pe,
                                          std::span<const uint8_t> raw_pe)
    {
        // Find the highest virtual offset to size the buffer
        uint64_t imageSize = 0;
        for (const auto& section : pe.sections())
        {
            const uint64_t end = section.virtual_address() + section.virtual_size();
            imageSize = std::max(end, imageSize);
        }
        imageSize = LIEF::align(imageSize, pe.optional_header().section_alignment());
        std::vector<uint8_t> buffer(imageSize, 0);

        // Copy PE headers directly from raw bytes (no file IO)
        const size_t hdr_size = pe.sizeof_headers();
        const size_t copy_size = std::min(hdr_size, raw_pe.size());
        std::memcpy(buffer.data(), raw_pe.data(), copy_size);

        // Copy each section's content to its virtual_address - unchanged
        for (const auto& section : pe.sections())
        {
            const auto content = section.content();
            const auto sizeOfCopy = std::min<size_t>(content.size(), section.virtual_size());
            std::memcpy(buffer.data() + section.virtual_address(),
                        content.data(),
                        sizeOfCopy);
        }
        return buffer;
    }

    static std::vector<uint8_t> map_image(LIEF::PE::Binary& pe, const std::string& path)
    {
        // Find the highest virtual offset to size the buffer
        uint64_t imageSize = 0;
        for (const auto& section : pe.sections())
        {
            const uint64_t end = section.virtual_address() + section.virtual_size();
            imageSize = std::max(end, imageSize);
        }

        // Round up to section alignment to be safe
        imageSize = LIEF::align(imageSize, pe.optional_header().section_alignment());

        std::vector<uint8_t> buffer(imageSize, 0);

        // Copy the PE Headers from file to memory buffer
        {
            std::ifstream file(path, std::ios::binary);
            if (file)
            {
                const size_t hdr_size = pe.sizeof_headers();
                file.read(reinterpret_cast<char*>(buffer.data()),
                          static_cast<std::streamsize>(hdr_size));
            }
        }

        // Copy each section's raw bytes to its virtual_address offset
        for (const auto& section : pe.sections())
        {
            const auto content = section.content(); // returns std::span<const uint8_t>
            const auto sizeOfCopy = std::min<size_t>(content.size(), section.virtual_size());
            std::memcpy(buffer.data() + section.virtual_address(),
                        content.data(),
                        sizeOfCopy);
            // Bytes beyond raw_size up to virtual_size remain zero - already initialized
        }

        return buffer;
    }

    std::optional<PeModule> PeModule::from_file(const std::string& path)
    {
        auto config = LIEF::PE::ParserConfig::default_conf();
        config.parse_exceptions = true; // should be done if we want to extract information about function from exception directory
        config.parse_arm64x_binary = false; // should not be used (here is forced explicitly) because the project is not about arm
        config.parse_signature = false; // have some bugs during parsing signature in ntdll.dll of win11

        auto pe = LIEF::PE::Parser::parse(path, config);
        if (!pe)
        {
            SPDLOG_ERROR("Failed to parse PE file: {}", path);
            return std::nullopt;
        }

        PeModule module;
        module.impl_ = std::make_shared<Impl>();
        module.impl_->fullPath = std::filesystem::canonical(path).string();
        module.impl_->image_base = pe->imagebase();

        // Collect exports
        if (pe->has_exports())
        {
            for (const auto& exp : pe->get_export()->entries())
            {
                ExportEntry entry;
                entry.name = exp.name();
                entry.rva = exp.address();
                entry.ordinal = exp.ordinal();
                module.impl_->exports.push_back(entry);
                module.impl_->export_map[entry.name] = entry.rva;
                module.impl_->export_rvas.insert(entry.rva);
            }
        }

        // Collect sections
        for (const auto& sec : pe->sections())
        {
            Section s;
            s.name = sec.name();
            s.virtual_address = sec.virtual_address();
            s.virtual_size = sec.virtual_size();
            s.raw_offset = sec.offset();
            s.raw_size = sec.size();

            const auto chars = sec.characteristics();
            s.executable = (chars & static_cast<uint64_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_EXECUTE)) != 0;
            s.readable = (chars & static_cast<uint64_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_READ)) != 0;
            s.writable = (chars & static_cast<uint64_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_WRITE)) != 0;

            module.impl_->sections.push_back(s);
        }

        // Store raw content (still not clear what to do with overlay, let's keep it for now as is)
        auto raw = pe->overlay();
        module.impl_->raw_data = map_image(*pe, module.impl_->fullPath);

        for (const auto& exceptionFunction : pe->exception_functions())
        {
            module.impl_->m_exception_functions.emplace_back(exceptionFunction.address(), exceptionFunction.size());
        }

        SPDLOG_INFO("Loaded PE module '{}': base=0x{:X}, {} exports, {} sections",
                    module.impl_->fullPath, module.impl_->image_base,
                    module.impl_->exports.size(), module.impl_->sections.size());

        return module;
    }

    std::optional<PeModule> PeModule::from_memory(std::span<const uint8_t> data,
                                                  uint64_t base_address)
    {
        auto config = LIEF::PE::ParserConfig::default_conf();
        config.parse_exceptions = true;     // should be done if we want to extract information about function from exception directory
        config.parse_arm64x_binary = false; // should not be used (here is forced explicitly) because the project is not about arm
        config.parse_signature = false;     // have some bugs during parsing signature in ntdll.dll of win11

        auto pe = LIEF::PE::Parser::parse(data.data(), data.size(), config);
        if (!pe)
        {
            SPDLOG_ERROR("Failed to parse PE from memory at base 0x{:X}, size={}",
                          base_address, data.size());
            return std::nullopt;
        }

        PeModule mod;
        mod.impl_ = std::make_shared<Impl>();
        mod.impl_->image_base = base_address;

        // Collect exports
        if (pe->has_exports())
        {
            for (const auto& exp : pe->get_export()->entries())
            {
                ExportEntry entry;
                entry.name = exp.name();
                entry.rva = exp.address();
                entry.ordinal = exp.ordinal();
                mod.impl_->exports.push_back(entry);
                mod.impl_->export_map[entry.name] = entry.rva;
                mod.impl_->export_rvas.insert(entry.rva);
            }
        }

        // Collect sections
        for (const auto& peSection : pe->sections())
        {
            Section section;
            section.name = peSection.name();
            section.virtual_address = peSection.virtual_address();
            section.virtual_size = peSection.virtual_size();
            section.raw_offset = peSection.offset();
            section.raw_size = peSection.size();

            const auto charactirestics = peSection.characteristics();
            section.executable = (charactirestics & static_cast<uint64_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_EXECUTE)) != 0;
            section.readable = (charactirestics & static_cast<uint64_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_READ)) != 0;
            section.writable = (charactirestics & static_cast<uint64_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_WRITE)) != 0;

            mod.impl_->sections.push_back(section);
        }

        // Store raw content (still not clear what to do with overlay, let's keep it for now as is)
        auto raw = pe->overlay();
        mod.impl_->raw_data = map_image(*pe, data);

        for (const auto& exceptionFunction : pe->exception_functions())
        {
            mod.impl_->m_exception_functions.emplace_back(exceptionFunction.address(), exceptionFunction.size());
        }

        SPDLOG_INFO("Loaded PE module: base=0x{:X}, {} exports, {} sections",
                    mod.impl_->image_base,
                    mod.impl_->exports.size(), mod.impl_->sections.size());

        return mod;
    }

    const std::string& PeModule::name() const
    {
        return impl_->fullPath;
    }

    uint64_t PeModule::image_base() const
    {
        return impl_->image_base;
    }

    const std::vector<ExportEntry>& PeModule::exports() const
    {
        return impl_->exports;
    }

    const std::vector<Section>& PeModule::sections() const
    {
        return impl_->sections;
    }

    bool PeModule::is_exported(uint64_t rva) const
    {
        return impl_->export_rvas.contains(rva);
    }

    std::optional<uint64_t> PeModule::export_rva(const std::string& name) const
    {
        auto it = impl_->export_map.find(name);
        if (it != impl_->export_map.end())
            return it->second;
        return std::nullopt;
    }

    std::span<const uint8_t> PeModule::read_at(uint64_t rva, size_t length) const
    {
        if (rva + length > impl_->raw_data.size())
        {
            return {};
        }

        return {impl_->raw_data.data() + rva, length};
    }

    std::span<const uint8_t> PeModule::raw_image() const
    {
        return impl_->raw_data;
    }

    const std::vector<FunctionBounds>& PeModule::exception_functions() const
    {
        return impl_->m_exception_functions;
    }

} // namespace symfind