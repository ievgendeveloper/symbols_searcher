#include <gtest/gtest.h>
#include "symfind/pe_module.h"

#include <algorithm>
#include <cstring>

using namespace symfind;

namespace
{
    constexpr const char* NTDLL_PATH = R"(C:\Windows\System32\ntdll.dll)";

    /// Helper: load ntdll once per test. If unavailable on this machine
    /// (e.g. running on Linux CI), the tests using this helper are skipped.
    std::optional<PeModule> load_ntdll()
    {
        return PeModule::from_file(NTDLL_PATH);
    }

} // namespace

// ─── Basic loading ──────────────────────────────────

TEST(PeModuleMapping, LoadsRealModule)
{
    auto module = load_ntdll();
    ASSERT_TRUE(module.has_value());
    EXPECT_FALSE(module->name().empty());
    EXPECT_GT(module->image_base(), 0u);
    EXPECT_GT(module->sections().size(), 0u);
    EXPECT_GT(module->exports().size(), 0u);
}

TEST(PeModuleMapping, RawImageNonEmpty)
{
    auto module = load_ntdll();
    ASSERT_TRUE(module.has_value());

    auto image = module->raw_image();
    EXPECT_GT(image.size(), 0u);
    // PE images start with "MZ" magic at RVA 0
    ASSERT_GE(image.size(), 2u);
    EXPECT_EQ(image[0], 'M');
    EXPECT_EQ(image[1], 'Z');
}

// ─── read_at correctness ────────────────────────────

TEST(PeModuleMapping, ReadAtZeroReturnsMzHeader)
{
    auto module = load_ntdll();
    ASSERT_TRUE(module.has_value());

    // First 64 bytes — the IMAGE_DOS_HEADER. First two bytes are "MZ".
    auto header = module->read_at(0, 64);
    ASSERT_EQ(header.size(), 64u);
    EXPECT_EQ(header[0], 'M');
    EXPECT_EQ(header[1], 'Z');
}

TEST(PeModuleMapping, ReadAtBeyondImageReturnsEmpty)
{
    auto module = load_ntdll();
    ASSERT_TRUE(module.has_value());

    auto image = module->raw_image();
    // Try to read past the end — should return empty span
    auto past_end = module->read_at(image.size() + 0x1000, 16);
    EXPECT_EQ(past_end.size(), 0u);
}

TEST(PeModuleMapping, ReadAtSectionStartContainsExpectedBytes)
{
    auto module = load_ntdll();
    ASSERT_TRUE(module.has_value());

    // Find the .text section
    const Section* text_section = nullptr;
    for (const auto& sec : module->sections())
    {
        if (sec.name == ".text")
        {
            text_section = &sec;
            break;
        }
    }
    ASSERT_NE(text_section, nullptr) << ".text section must exist in ntdll";
    EXPECT_TRUE(text_section->executable);

    // Reading the first 16 bytes of .text via read_at should match
    // the first 16 bytes from the raw image at the same offset.
    auto via_read_at = module->read_at(text_section->virtual_address, 16);
    auto raw_image = module->raw_image();

    ASSERT_EQ(via_read_at.size(), 16u);
    ASSERT_GE(raw_image.size(), text_section->virtual_address + 16);

    EXPECT_EQ(0, std::memcmp(via_read_at.data(),
                  raw_image.data() + text_section->virtual_address,
                  16));
}

// ─── Export lookup consistency ──────────────────────

TEST(PeModuleMapping, KnownExportRvaIsExecutable)
{
    auto module = load_ntdll();
    ASSERT_TRUE(module.has_value());

    // RtlGetCurrentServiceSessionId is a well-known ntdll export
    auto rva = module->export_rva("RtlGetCurrentServiceSessionId");
    ASSERT_TRUE(rva.has_value()) << "Expected ntdll to export this function";

    // The RVA should fall inside an executable section
    bool in_exec_section = false;
    for (const auto& sec : module->sections())
    {
        if (sec.executable &&
            *rva >= sec.virtual_address &&
            *rva < sec.virtual_address + sec.virtual_size)
        {
            in_exec_section = true;
            break;
        }
    }
    EXPECT_TRUE(in_exec_section)
        << "Export RVA 0x" << std::hex << *rva
        << " is not in any executable section";
}

TEST(PeModuleMapping, ReadAtExportEntryPointReturnsCode)
{
    auto module = load_ntdll();
    ASSERT_TRUE(module.has_value());

    auto rva = module->export_rva("RtlGetCurrentServiceSessionId");
    ASSERT_TRUE(rva.has_value());

    // Read 16 bytes from the function entry point — should be valid
    // code bytes (not a hole of zeros, not out of bounds).
    auto code = module->read_at(*rva, 16);
    ASSERT_EQ(code.size(), 16u);

    // We can't assert on specific bytes because the prologue varies
    // between Windows versions, but we can sanity-check that it isn't
    // all zeros (which would indicate we read into a hole).
    bool all_zero = std::all_of(code.begin(), code.end(),
                                [](uint8_t b) { return b == 0; });
    EXPECT_FALSE(all_zero) << "Function entry point should not be all zeros";
}

// ─── Cross-check: every section is reachable via read_at ─

TEST(PeModuleMapping, EverySectionIsReadable)
{
    auto module = load_ntdll();
    ASSERT_TRUE(module.has_value());

    for (const auto& sec : module->sections())
    {
        if (sec.virtual_size == 0)
            continue;

        // Read first few bytes of each section
        const size_t to_read = std::min<size_t>(sec.virtual_size, 16);
        auto bytes = module->read_at(sec.virtual_address, to_read);

        EXPECT_EQ(bytes.size(), to_read)
            << "Section '" << sec.name
            << "' at RVA 0x" << std::hex << sec.virtual_address
            << " could not be read";
    }
}