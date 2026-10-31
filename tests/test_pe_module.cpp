#include "symfind/pe_module.h"
#include <gtest/gtest.h>

#include <algorithm>
#include <cstring>

namespace
{
    constexpr const char* ntdllPath = R"(C:\Windows\System32\ntdll.dll)";

    /// Helper: load ntdll once per test. If unavailable on this machine
    /// (e.g. running on Linux CI), the tests using this helper are skipped.
    std::optional<symfind::PeModule> LoadNtdll()
    {
        return symfind::PeModule::FromFile(ntdllPath);
    }

} // namespace

// ─── Basic loading ──────────────────────────────────

TEST(PeModuleMapping, LoadsRealModule)
{
    auto ntdllModule = LoadNtdll();
    ASSERT_TRUE(ntdllModule.has_value());
    EXPECT_FALSE(ntdllModule->Name().empty());
    EXPECT_EQ(ntdllModule->Name().find_first_of("/\\"), std::string::npos);
    EXPECT_GT(ntdllModule->ImageBase(), 0u);
    EXPECT_GT(ntdllModule->Sections().size(), 0u);
    EXPECT_GT(ntdllModule->Exports().size(), 0u);
}

TEST(PeModuleMapping, RawImageNonEmpty)
{
    auto ntdllModule = LoadNtdll();
    ASSERT_TRUE(ntdllModule.has_value());

    auto imageBytes = ntdllModule->RawImage();
    EXPECT_GT(imageBytes.size(), 0u);
    // PE images start with "MZ" magic at RVA 0
    ASSERT_GE(imageBytes.size(), 2u);
    EXPECT_EQ(imageBytes[0], 'M');
    EXPECT_EQ(imageBytes[1], 'Z');
}

// ─── ReadAt correctness ────────────────────────────

TEST(PeModuleMapping, ReadAtZeroReturnsMzHeader)
{
    auto ntdllModule = LoadNtdll();
    ASSERT_TRUE(ntdllModule.has_value());

    // First 64 bytes — the IMAGE_DOS_HEADER. First two bytes are "MZ".
    auto dosHeaderBytes = ntdllModule->ReadAt(0, 64);
    ASSERT_EQ(dosHeaderBytes.size(), 64u);
    EXPECT_EQ(dosHeaderBytes[0], 'M');
    EXPECT_EQ(dosHeaderBytes[1], 'Z');
}

TEST(PeModuleMapping, ReadAtBeyondImageReturnsEmpty)
{
    auto ntdllModule = LoadNtdll();
    ASSERT_TRUE(ntdllModule.has_value());

    auto imageBytes = ntdllModule->RawImage();
    // Try to read past the end — should return empty span
    auto outOfBoundsBytes = ntdllModule->ReadAt(imageBytes.size() + 0x1000, 16);
    EXPECT_EQ(outOfBoundsBytes.size(), 0u);
}

TEST(PeModuleMapping, ReadAtSectionStartContainsExpectedBytes)
{
    auto ntdllModule = LoadNtdll();
    ASSERT_TRUE(ntdllModule.has_value());

    // Find the .text section
    const symfind::Section* textSection = nullptr;
    for (const auto& section : ntdllModule->Sections())
    {
        if (section.name == ".text")
        {
            textSection = &section;
            break;
        }
    }
    ASSERT_NE(textSection, nullptr) << ".text section must exist in ntdll";
    EXPECT_TRUE(textSection->executable);

    // Reading the first 16 bytes of .text via ReadAt should match
    // the first 16 bytes from the raw image at the same offset.
    auto sectionBytes = ntdllModule->ReadAt(textSection->virtualAddress, 16);
    auto rawImageBytes = ntdllModule->RawImage();

    ASSERT_EQ(sectionBytes.size(), 16u);
    ASSERT_GE(rawImageBytes.size(), textSection->virtualAddress + 16);

    EXPECT_EQ(0, std::memcmp(sectionBytes.data(),
                             rawImageBytes.data() + textSection->virtualAddress, 16));
}

// ─── Export lookup consistency ──────────────────────

TEST(PeModuleMapping, KnownExportRvaIsExecutable)
{
    auto ntdllModule = LoadNtdll();
    ASSERT_TRUE(ntdllModule.has_value());

    // RtlGetCurrentServiceSessionId is a well-known ntdll export
    auto exportedFunctionRva = ntdllModule->ExportRva("RtlGetCurrentServiceSessionId");
    ASSERT_TRUE(exportedFunctionRva.has_value()) << "Expected ntdll to export this function";

    // The RVA should fall inside an executable section
    bool exportIsExecutable = false;
    for (const auto& section : ntdllModule->Sections())
    {
        if (section.executable && *exportedFunctionRva >= section.virtualAddress &&
            *exportedFunctionRva < section.virtualAddress + section.virtualSize)
        {
            exportIsExecutable = true;
            break;
        }
    }
    EXPECT_TRUE(exportIsExecutable) << "Export RVA 0x" << std::hex << *exportedFunctionRva
                                    << " is not in any executable section";
}

TEST(PeModuleMapping, ReadAtExportEntryPointReturnsCode)
{
    auto ntdllModule = LoadNtdll();
    ASSERT_TRUE(ntdllModule.has_value());

    auto exportedFunctionRva = ntdllModule->ExportRva("RtlGetCurrentServiceSessionId");
    ASSERT_TRUE(exportedFunctionRva.has_value());

    // Read 16 bytes from the function entry point — should be valid
    // code bytes (not a hole of zeros, not out of bounds).
    auto entryPointBytes = ntdllModule->ReadAt(*exportedFunctionRva, 16);
    ASSERT_EQ(entryPointBytes.size(), 16u);

    // We can't assert on specific bytes because the prologue varies
    // between Windows versions, but we can sanity-check that it isn't
    // all zeros (which would indicate we read into a hole).
    bool entryPointIsAllZero = std::all_of(entryPointBytes.begin(), entryPointBytes.end(),
                                           [](uint8_t byte)
                                           {
                                               return byte == 0;
                                           });
    EXPECT_FALSE(entryPointIsAllZero) << "Function entry point should not be all zeros";
}

// ─── Cross-check: every section is reachable via ReadAt ─

TEST(PeModuleMapping, EverySectionIsReadable)
{
    auto ntdllModule = LoadNtdll();
    ASSERT_TRUE(ntdllModule.has_value());

    for (const auto& section : ntdllModule->Sections())
    {
        if (section.virtualSize == 0)
        {
            continue;
        }

        // Read first few bytes of each section
        const size_t bytesToRead = std::min<size_t>(section.virtualSize, 16);
        auto sectionBytes = ntdllModule->ReadAt(section.virtualAddress, bytesToRead);

        EXPECT_EQ(sectionBytes.size(), bytesToRead)
            << "Section '" << section.name << "' at RVA 0x" << std::hex << section.virtualAddress
            << " could not be read";
    }
}
