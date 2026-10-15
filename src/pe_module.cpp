#include "symfind/pe_module.h"

#include <LIEF/PE.hpp>
#include <LIEF/PE/exceptions_info/RuntimeFunctionX64.hpp>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <set>
#include <spdlog/spdlog.h>
#include <tuple>
#include <unordered_map>
#include <unordered_set>

namespace symfind
{
    namespace
    {
        struct FunctionRangeOwner
        {
                uint64_t rva;
                uint64_t size;
                uint64_t primary;
        };

        struct ExceptionFunctions
        {
                std::vector<FunctionBounds> functions;
                std::vector<FunctionRangeOwner> owners;
        };

        ExceptionFunctions collect_exception_functions(const LIEF::PE::Binary& pe,
                                                       std::span<const uint8_t> image,
                                                       const std::vector<Section>& sections)
        {
            // Keep the full RUNTIME_FUNCTION identity. LIEF's chained pointer is
            // resolved by BeginAddress alone; raw EndAddress/UnwindData must also
            // match before a continuation is assigned to another procedure.
            using RuntimeKey = std::tuple<uint32_t, uint32_t, uint32_t>;
            struct RuntimeNode
            {
                    uint32_t begin, end, unwind;
                    bool header_valid = false;
                    bool chained = false;
                    bool conflicted = false;
                    uint8_t frame = 0;
                    std::optional<RuntimeKey> parent;
            };

            const auto readable = [&](uint64_t rva, uint64_t size)
            {
                return rva <= image.size() && size <= image.size() - rva;
            };
            const auto read_u32 = [&](uint64_t rva)
            {
                uint32_t value = 0;
                for (size_t i = 0; i < 4; ++i)
                    value |= static_cast<uint32_t>(image[static_cast<size_t>(rva) + i]) << (i * 8);
                return value;
            };
            const auto executable_range = [&](uint32_t begin, uint32_t end)
            {
                if (end <= begin || !readable(begin, static_cast<uint64_t>(end) - begin))
                    return false;
                return std::any_of(sections.begin(), sections.end(), [&](const Section& section)
                                   { return section.executable && begin >= section.virtual_address &&
                                            begin - section.virtual_address <= section.virtual_size &&
                                            static_cast<uint64_t>(end) - begin <= section.virtual_size - (begin - section.virtual_address); });
            };

            std::vector<RuntimeNode> nodes;
            std::map<RuntimeKey, size_t> by_identity;
            for (const auto& exception : pe.exceptions())
            {
                const auto* runtime = exception.as<LIEF::PE::RuntimeFunctionX64>();
                if (!runtime || !executable_range(runtime->rva_start(), runtime->rva_end()))
                    continue;
                const RuntimeKey key{runtime->rva_start(), runtime->rva_end(), runtime->unwind_rva()};
                if (by_identity.contains(key))
                    continue; // Identical duplicate metadata adds no additional code.
                by_identity.emplace(key, nodes.size());
                RuntimeNode node{runtime->rva_start(), runtime->rva_end(), runtime->unwind_rva()};
                if (readable(node.unwind, 4))
                {
                    const auto version = image[node.unwind] & 7;
                    const auto flags = image[node.unwind] >> 3;
                    const auto count = image[node.unwind + 2];
                    node.frame = image[node.unwind + 3];
                    node.chained = (flags & 4) != 0;
                    const auto tail = static_cast<uint64_t>(node.unwind) + 4 + ((count + 1u) & ~1u) * 2;
                    node.header_valid = (version == 1 || version == 2) && (flags & ~7) == 0 &&
                                        !(node.chained && (flags & 3)) &&
                                        readable(node.unwind, tail - node.unwind);
                    if (node.header_valid && node.chained)
                    {
                        node.header_valid = readable(tail, 12);
                        if (node.header_valid)
                            node.parent = RuntimeKey{read_u32(tail), read_u32(tail + 4), read_u32(tail + 8)};
                    }
                    else if (node.header_valid && (flags & 3))
                        node.header_valid = readable(tail, 4);
                }
                nodes.push_back(std::move(node));
            }

            // An overlapping runtime table cannot establish unique ownership.
            // Mark all affected nodes once, without quadratic work on malformed
            // tables, and keep their bounds independent rather than guessing.
            std::vector<size_t> ordered;
            ordered.reserve(nodes.size());
            for (size_t i = 0; i < nodes.size(); ++i)
                ordered.push_back(i);
            std::sort(ordered.begin(), ordered.end(), [&](size_t a, size_t b)
                      { return nodes[a].begin < nodes[b].begin; });
            std::multimap<uint32_t, size_t> active_ends;
            std::set<size_t> unmarked_active;
            for (const auto index : ordered)
            {
                while (!active_ends.empty() && active_ends.begin()->first <= nodes[index].begin)
                {
                    unmarked_active.erase(active_ends.begin()->second);
                    active_ends.erase(active_ends.begin());
                }
                if (!active_ends.empty())
                {
                    nodes[index].conflicted = true;
                    for (const auto active : unmarked_active)
                        nodes[active].conflicted = true;
                    unmarked_active.clear();
                }
                else
                    unmarked_active.insert(index);
                active_ends.emplace(nodes[index].end, index);
            }

            const auto primary_for = [&](size_t initial)
            {
                size_t current = initial;
                std::set<size_t> visited;
                constexpr size_t max_chain_depth = 64;
                while (visited.size() < max_chain_depth && visited.insert(current).second)
                {
                    const auto& node = nodes[current];
                    if (!node.header_valid || node.conflicted)
                        return initial;
                    if (!node.chained)
                        return current;
                    if (!node.parent)
                        return initial;
                    const auto target = by_identity.find(*node.parent);
                    if (target == by_identity.end() || nodes[target->second].frame != node.frame)
                        return initial;
                    current = target->second;
                }
                return initial; // Cycle, malformed parent, or unsupported depth.
            };

            std::map<size_t, FunctionBounds> groups;
            ExceptionFunctions result;
            for (size_t i = 0; i < nodes.size(); ++i)
            {
                const auto primary = primary_for(i);
                const auto& root = nodes[primary];
                const auto group = groups.try_emplace(primary,
                                                      FunctionBounds{root.begin, static_cast<uint64_t>(root.end) - root.begin, {}})
                                       .first;
                const auto& node = nodes[i];
                const FunctionRange range{node.begin, static_cast<uint64_t>(node.end) - node.begin};
                group->second.ranges.push_back(range);
                if (!node.conflicted)
                    result.owners.push_back({range.rva, range.size, root.begin});
            }
            for (auto& [_, bounds] : groups)
            {
                std::sort(bounds.ranges.begin(), bounds.ranges.end(), [](const FunctionRange& a, const FunctionRange& b)
                          { return a.rva < b.rva; });
                result.functions.push_back(std::move(bounds));
            }
            std::sort(result.functions.begin(), result.functions.end(), [](const FunctionBounds& a, const FunctionBounds& b)
                      { return a.rva < b.rva; });
            std::sort(result.owners.begin(), result.owners.end(), [](const FunctionRangeOwner& a, const FunctionRangeOwner& b)
                      { return a.rva < b.rva; });
            return result;
        }
    } // namespace

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
            std::vector<FunctionRangeOwner> function_range_owners;
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
        config.parse_exceptions = true;     // should be done if we want to extract information about function from exception directory
        config.parse_arm64x_binary = false; // should not be used (here is forced explicitly) because the project is not about arm
        config.parse_signature = false;     // have some bugs during parsing signature in ntdll.dll of win11

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

        auto exceptions = collect_exception_functions(*pe, module.impl_->raw_data, module.impl_->sections);
        module.impl_->m_exception_functions = std::move(exceptions.functions);
        module.impl_->function_range_owners = std::move(exceptions.owners);

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

        auto exceptions = collect_exception_functions(*pe, mod.impl_->raw_data, mod.impl_->sections);
        mod.impl_->m_exception_functions = std::move(exceptions.functions);
        mod.impl_->function_range_owners = std::move(exceptions.owners);

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
        if (rva > impl_->raw_data.size() || length > impl_->raw_data.size() - rva)
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

    std::optional<uint64_t> PeModule::canonical_function_rva(uint64_t address) const
    {
        const auto& ranges = impl_->function_range_owners;
        const auto after = std::upper_bound(ranges.begin(), ranges.end(), address,
                                            [](uint64_t value, const FunctionRangeOwner& range)
                                            { return value < range.rva; });
        if (after == ranges.begin())
            return std::nullopt;
        const auto& range = *std::prev(after);
        if (address - range.rva >= range.size)
            return std::nullopt;
        return range.primary;
    }

} // namespace symfind
