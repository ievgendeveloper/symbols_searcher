#include "symfind/pe_module.h"

#include <filesystem>
#include <LIEF/PE.hpp>
#include <spdlog/spdlog.h>
#include <unordered_map>
#include <unordered_set>

namespace symfind {

struct PeModule::Impl {
    std::string name;
    uint64_t    image_base = 0;
    std::vector<ExportEntry> exports;
    std::vector<Section> sections;
    std::vector<uint8_t> raw_data;
    std::unordered_map<std::string, uint64_t> export_map;
    std::unordered_set<uint64_t> export_rvas;
};

std::optional<PeModule> PeModule::from_file(const std::string& path) {
    auto pe = LIEF::PE::Parser::parse(path);
    if (!pe) {
        spdlog::error("Failed to parse PE file: {}", path);
        return std::nullopt;
    }

    PeModule mod;
    mod.impl_ = std::make_shared<Impl>();
    mod.impl_->name = pe->has_exports() ? pe->get_export()->name() : std::filesystem::path(path).filename().string();
    mod.impl_->image_base = pe->imagebase();

    // Collect exports
    if (pe->has_exports()) {
        for (const auto& exp : pe->get_export()->entries()) {
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
    for (const auto& sec : pe->sections()) {
        Section s;
        s.name = sec.name();
        s.virtual_address = sec.virtual_address();
        s.virtual_size = sec.virtual_size();
        s.raw_offset = sec.offset();
        s.raw_size = sec.size();

        const auto chars = sec.characteristics();
        s.executable = (chars & static_cast<uint64_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_EXECUTE)) != 0;
        s.readable   = (chars & static_cast<uint64_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_READ)) != 0;
        s.writable   = (chars & static_cast<uint64_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_WRITE)) != 0;

        mod.impl_->sections.push_back(s);
    }

    // Store raw content
    auto raw = pe->overlay();
    // TODO: map sections properly for RVA-based access

    spdlog::info("Loaded PE module '{}': base=0x{:X}, {} exports, {} sections",
                 mod.impl_->name, mod.impl_->image_base,
                 mod.impl_->exports.size(), mod.impl_->sections.size());

    return mod;
}

std::optional<PeModule> PeModule::from_memory(std::span<const uint8_t> data,
                                               uint64_t base_address) {
    // TODO: implement
    spdlog::warn("PeModule::from_memory() not yet implemented");
    return std::nullopt;
}

const std::string& PeModule::name() const { return impl_->name; }
uint64_t PeModule::image_base() const { return impl_->image_base; }
const std::vector<ExportEntry>& PeModule::exports() const { return impl_->exports; }
const std::vector<Section>& PeModule::sections() const { return impl_->sections; }

bool PeModule::is_exported(uint64_t rva) const {
    return impl_->export_rvas.contains(rva);
}

std::optional<uint64_t> PeModule::export_rva(const std::string& name) const {
    auto it = impl_->export_map.find(name);
    if (it != impl_->export_map.end()) return it->second;
    return std::nullopt;
}

std::span<const uint8_t> PeModule::read_at(uint64_t rva, size_t length) const {
    // TODO: implement RVA-to-file-offset translation
    return {};
}

std::span<const uint8_t> PeModule::raw_image() const {
    return impl_->raw_data;
}

} // namespace symfind
