#include "symfind/analysis_db.h"
#include "symfind/dsl_matcher.h"
#include "symfind/dsl_parser.h"
#include "symfind/function_finder.h"
#include "symfind/pe_module.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <climits>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

#include <Windows.h>

namespace
{
    using Bytes = std::vector<uint8_t>;
    constexpr uint64_t image_base = 0x140000000;
    constexpr uint32_t primary = 0x1000;
    constexpr uint32_t independent = 0x1100;
    constexpr uint32_t continuation = 0x1200;
    constexpr uint32_t target = 0x1300;
    constexpr uint32_t gap_target = 0x1340;
    constexpr uint32_t anchor = 0x1380;
    constexpr uint32_t owned_data = 0x4120;
    constexpr uint32_t gap_data = 0x4110;
    constexpr size_t optional_offset = 0x98;

    struct SectionFixture
    {
            std::string_view name;
            uint32_t rva, raw, size, flags;
    };

    constexpr uint32_t file_alignment = 0x200;
    constexpr uint32_t section_alignment = 0x1000;
    constexpr uint32_t headers_size = 2 * file_alignment;
    constexpr uint32_t initialized_data_flags = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
    constexpr SectionFixture text_section{".text", section_alignment, headers_size, 2 * file_alignment,
                                          IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ};
    constexpr SectionFixture pdata_section{".pdata", text_section.rva + section_alignment, text_section.raw + text_section.size,
                                           file_alignment, initialized_data_flags};
    constexpr SectionFixture xdata_section{".xdata", pdata_section.rva + section_alignment, pdata_section.raw + pdata_section.size,
                                           file_alignment, initialized_data_flags};
    constexpr SectionFixture edata_section{".edata", xdata_section.rva + section_alignment, xdata_section.raw + xdata_section.size,
                                           file_alignment, initialized_data_flags};
    constexpr std::array sections{text_section, pdata_section, xdata_section, edata_section};

    constexpr uint32_t relative_branch_size = sizeof(uint8_t) + sizeof(int32_t);
    constexpr uint8_t rex_w_prefix = 0x48;
    constexpr uint8_t lea_opcode = 0x8d;
    constexpr uint8_t modrm_rax_rip_relative = 0x05; // mod=00, reg=RAX, r/m=RIP+disp32.
    constexpr std::array lea_rax_rip_prefix{rex_w_prefix, lea_opcode, modrm_rax_rip_relative};
    constexpr uint32_t rip_relative_lea_size = lea_rax_rip_prefix.size() + sizeof(int32_t);

    void put(Bytes& bytes, size_t offset, uint64_t value, size_t width)
    {
        if (offset > bytes.size() || width > bytes.size() - offset || width > sizeof(value))
        {
            throw std::runtime_error("Synthetic PE write is out of bounds");
        }

        for (size_t i = 0; i < width; ++i)
        {
            bytes[offset + i] = static_cast<uint8_t>(value >> (i * CHAR_BIT));
        }
    }

    void put_text(Bytes& bytes, size_t offset, std::string_view text)
    {
        if (offset > bytes.size() || text.size() > bytes.size() - offset)
        {
            throw std::runtime_error("Synthetic PE text is out of bounds");
        }

        std::copy(text.begin(), text.end(), bytes.begin() + static_cast<uint32_t>(offset));
    }

    auto file_offset(uint32_t rva)
    {
        for (const auto& section : sections)
        {
            if (rva >= section.rva && rva - section.rva < section.size)
                return section.raw + rva - section.rva;
        }

        throw std::runtime_error("Synthetic PE RVA is outside a section");
    }

    void runtime_function(Bytes& bytes, size_t offset, uint32_t begin, uint32_t end, uint32_t unwind)
    {
        put(bytes, offset + offsetof(IMAGE_RUNTIME_FUNCTION_ENTRY, BeginAddress), begin, sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY::BeginAddress));
        put(bytes, offset + offsetof(IMAGE_RUNTIME_FUNCTION_ENTRY, EndAddress), end, sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY::EndAddress));
        put(bytes, offset + offsetof(IMAGE_RUNTIME_FUNCTION_ENTRY, UnwindInfoAddress), unwind, sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY::UnwindInfoAddress));
    }

    void direct_branch(Bytes& bytes, uint32_t from, uint32_t to, uint8_t opcode)
    {
        const auto offset = file_offset(from);
        bytes[offset] = opcode;
        const auto displacement = static_cast<int64_t>(to) - from - relative_branch_size;
        put(bytes, offset + sizeof(opcode), static_cast<uint32_t>(displacement), sizeof(int32_t));
    }

    void lea_data(Bytes& bytes, uint32_t from, uint32_t to)
    {
        const auto offset = file_offset(from);
        std::copy(lea_rax_rip_prefix.begin(), lea_rax_rip_prefix.end(), bytes.begin() + offset);
        const auto displacement = static_cast<int64_t>(to) - from - rip_relative_lea_size;
        put(bytes, offset + lea_rax_rip_prefix.size(), static_cast<uint32_t>(displacement), sizeof(int32_t));
    }

    // Raw PE bytes, never loaded as an executable. The gap contains a separate
    // function so widening the primary span would produce a false call edge.
    Bytes make_chained_pe()
    {
        // The SDK exposes RUNTIME_FUNCTION and its flags, but not this x64 header.
        struct UnwindInfoHeader
        {
                uint8_t version_and_flags, prolog_size, code_count, frame_register_and_offset;
        };
        constexpr uint8_t unwind_version = 1;
        constexpr unsigned unwind_version_bits = 3;
        constexpr uint32_t unwind_slot_size = sizeof(UnwindInfoHeader) + sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
        constexpr uint32_t primary_unwind = xdata_section.rva;
        constexpr uint32_t continuation_unwind = primary_unwind + 2 * unwind_slot_size;
        constexpr uint32_t standard_function_size = 0x10;
        struct FunctionFixture
        {
                uint32_t begin, size, unwind;
        };
        constexpr std::array functions{
            FunctionFixture{primary, standard_function_size, primary_unwind},
            FunctionFixture{independent, 2 * standard_function_size, primary_unwind + unwind_slot_size},
            FunctionFixture{continuation, standard_function_size, continuation_unwind},
            FunctionFixture{target, standard_function_size, continuation_unwind + 2 * unwind_slot_size},
            FunctionFixture{gap_target, standard_function_size, continuation_unwind + 3 * unwind_slot_size},
            FunctionFixture{anchor, standard_function_size, continuation_unwind + 4 * unwind_slot_size},
        };

        // These placements are part of the fixture: tests below patch the tables.
        constexpr uint32_t export_directory_size = 0x180;
        constexpr uint32_t export_functions_rva = edata_section.rva + 0x40;
        constexpr uint32_t module_name_rva = edata_section.rva + 0x80;
        constexpr uint32_t loader_name_rva = edata_section.rva + 0x98;
        constexpr uint32_t anchor_name_rva = edata_section.rva + 0xa8;
        constexpr std::array<DWORD, 2> exported_functions{primary, anchor};
        constexpr std::array<DWORD, exported_functions.size()> exported_names{anchor_name_rva, loader_name_rva};
        constexpr std::array<WORD, exported_names.size()> exported_ordinals{1, 0};
        constexpr uint32_t export_names_rva = export_functions_rva + sizeof(exported_functions);
        constexpr uint32_t export_ordinals_rva = export_names_rva + sizeof(exported_names);

        Bytes bytes(edata_section.raw + edata_section.size);
        const auto write_structure = [&bytes](size_t offset, const auto& structure)
        {
            put_text(bytes, offset, {reinterpret_cast<const char*>(&structure), sizeof(structure)});
        };

        constexpr size_t nt_headers_offset = optional_offset - offsetof(IMAGE_NT_HEADERS64, OptionalHeader);
        IMAGE_DOS_HEADER dos{};
        dos.e_magic = IMAGE_DOS_SIGNATURE;
        dos.e_lfanew = static_cast<LONG>(nt_headers_offset);
        write_structure(0, dos);

        IMAGE_NT_HEADERS64 nt{};
        nt.Signature = IMAGE_NT_SIGNATURE;
        nt.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
        nt.FileHeader.NumberOfSections = static_cast<WORD>(sections.size());
        nt.FileHeader.TimeDateStamp = 1;
        nt.FileHeader.SizeOfOptionalHeader = sizeof(nt.OptionalHeader);
        nt.FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE_DLL;
        auto& optional = nt.OptionalHeader;
        optional.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        optional.SizeOfCode = text_section.size;
        optional.SizeOfInitializedData = pdata_section.size + xdata_section.size + edata_section.size;
        optional.AddressOfEntryPoint = primary;
        optional.BaseOfCode = text_section.rva;
        optional.ImageBase = image_base;
        optional.SectionAlignment = section_alignment;
        optional.FileAlignment = file_alignment;
        optional.MajorOperatingSystemVersion = 6;
        optional.MajorSubsystemVersion = optional.MajorOperatingSystemVersion;
        optional.SizeOfImage = edata_section.rva + section_alignment;
        optional.SizeOfHeaders = headers_size;
        optional.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
        optional.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA | IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
                                      IMAGE_DLLCHARACTERISTICS_NX_COMPAT | IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE;
        optional.SizeOfStackReserve = optional.SizeOfHeapReserve = static_cast<ULONGLONG>(1024 * 1024);
        optional.SizeOfStackCommit = optional.SizeOfHeapCommit = section_alignment;
        optional.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] = {edata_section.rva, export_directory_size};
        optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION] = {
            pdata_section.rva, static_cast<DWORD>(functions.size() * sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY))};
        write_structure(nt_headers_offset, nt);

        constexpr auto section_table_offset = nt_headers_offset + sizeof(nt);
        for (size_t i = 0; i < sections.size(); ++i)
        {
            IMAGE_SECTION_HEADER section{};
            std::copy(sections[i].name.begin(), sections[i].name.end(), section.Name);
            section.Misc.VirtualSize = sections[i].size;
            section.VirtualAddress = sections[i].rva;
            section.SizeOfRawData = sections[i].size;
            section.PointerToRawData = sections[i].raw;
            section.Characteristics = sections[i].flags;
            write_structure(section_table_offset + i * sizeof(section), section);
        }

        constexpr uint8_t int3_opcode = 0xcc;
        constexpr uint8_t jmp_rel32_opcode = 0xe9;
        constexpr uint8_t call_rel32_opcode = 0xe8;
        constexpr uint8_t ret_opcode = 0xc3;
        std::fill(bytes.begin() + text_section.raw, bytes.begin() + text_section.raw + text_section.size, int3_opcode);
        direct_branch(bytes, primary, continuation, jmp_rel32_opcode); // JMP is not a call.
        direct_branch(bytes, independent, gap_target, call_rel32_opcode);
        direct_branch(bytes, independent + relative_branch_size, continuation, call_rel32_opcode);
        lea_data(bytes, independent + 2 * relative_branch_size, gap_data);
        bytes[file_offset(independent + 2 * relative_branch_size + rip_relative_lea_size)] = ret_opcode;
        direct_branch(bytes, continuation, target, call_rel32_opcode);
        lea_data(bytes, continuation + relative_branch_size, owned_data);
        bytes[file_offset(continuation + relative_branch_size + rip_relative_lea_size)] = ret_opcode;
        direct_branch(bytes, target, anchor, call_rel32_opcode);
        bytes[file_offset(target + relative_branch_size)] = ret_opcode;
        bytes[file_offset(gap_target)] = ret_opcode;
        bytes[file_offset(anchor)] = ret_opcode;

        constexpr UnwindInfoHeader leaf_unwind{unwind_version, 0, 0, 0};
        for (size_t i = 0; i < functions.size(); ++i)
        {
            const auto& function = functions[i];
            runtime_function(bytes, pdata_section.raw + i * sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY),
                             function.begin, function.begin + function.size, function.unwind);
            write_structure(file_offset(function.unwind), leaf_unwind);
        }
        constexpr UnwindInfoHeader chained_unwind{unwind_version | (UNW_FLAG_CHAININFO << unwind_version_bits), 
            0, 0, 0};
        write_structure(file_offset(continuation_unwind), chained_unwind);
        runtime_function(bytes, file_offset(continuation_unwind) + sizeof(UnwindInfoHeader),
                         primary, primary + standard_function_size, primary_unwind);

        IMAGE_EXPORT_DIRECTORY exports{};
        exports.Name = module_name_rva;
        exports.Base = 1;
        exports.NumberOfFunctions = static_cast<DWORD>(exported_functions.size());
        exports.NumberOfNames = static_cast<DWORD>(exported_names.size());
        exports.AddressOfFunctions = export_functions_rva;
        exports.AddressOfNames = export_names_rva;
        exports.AddressOfNameOrdinals = export_ordinals_rva;
        write_structure(file_offset(edata_section.rva), exports);
        write_structure(file_offset(export_functions_rva), exported_functions);
        write_structure(file_offset(export_names_rva), exported_names);
        write_structure(file_offset(export_ordinals_rva), exported_ordinals);
        put_text(bytes, file_offset(module_name_rva), "chain-fixture.dll");
        put_text(bytes, file_offset(loader_name_rva), "TestLoader");
        put_text(bytes, file_offset(anchor_name_rva), "TestAnchor");
        return bytes;
    }

    const symfind::FunctionBounds* bounds_at(const symfind::PeModule& module, uint64_t rva)
    {
        const auto& functions = module.exception_functions();
        const auto found = 
            std::find_if(functions.begin(), functions.end(), [rva](const auto& function)
                                        { return function.rva == rva; });
        return found == functions.end() ? nullptr : &*found;
    }

    std::vector<std::pair<uint64_t, uint64_t>> ranges_of(const std::vector<symfind::FunctionRange>& ranges)
    {
        std::vector<std::pair<uint64_t, uint64_t>> result;
        result.reserve(ranges.size());
        for (const auto& range : ranges)
        {
            result.emplace_back(range.rva, range.size);
        }
        return result;
    }

    bool contains(const std::vector<uint64_t>& values, uint64_t rva)
    {
        return std::find(values.begin(), values.end(), rva) != values.end();
    }

    class TemporaryPe
    {
        public:
            explicit TemporaryPe(const Bytes& bytes)
            {
                static std::atomic<uint64_t> sequence{0};
                const auto tick = std::chrono::steady_clock::now().time_since_epoch().count();
                m_path = std::filesystem::temp_directory_path() / ("symfind-chain-" + std::to_string(tick) + 
                    "-" + std::to_string(sequence.fetch_add(1)) + ".dll");
                if (std::filesystem::exists(m_path))
                {
                    throw std::runtime_error("Synthetic PE temporary path already exists");
                }

                std::ofstream stream(m_path, std::ios::binary | std::ios::trunc);
                stream.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
                if (!stream)
                {
                    throw std::runtime_error("Cannot save synthetic PE fixture");
                }
            }

            ~TemporaryPe()
            {
                std::error_code ignored;
                std::filesystem::remove(m_path, ignored);
            }

            TemporaryPe(const TemporaryPe&) = delete;
            TemporaryPe& operator=(const TemporaryPe&) = delete;

            std::filesystem::path m_path;
    };

    TEST(ChainedUnwind, MemoryLoaderKeepsSparseRangesAndCanonicalOwner)
    {
        const auto module = symfind::PeModule::from_memory(make_chained_pe(), image_base);
        ASSERT_TRUE(module.has_value());
        ASSERT_EQ(module->exception_functions().size(), 5);
        const auto* function = bounds_at(*module, primary);
        ASSERT_NE(function, nullptr);
        EXPECT_EQ(function->size, 0x10);
        EXPECT_EQ(ranges_of(function->ranges), 
            (std::vector<std::pair<uint64_t, uint64_t>>{{primary, 0x10}, {continuation, 0x10}}));
        EXPECT_EQ(bounds_at(*module, continuation), nullptr);
        EXPECT_NE(bounds_at(*module, independent), nullptr);
        EXPECT_EQ(module->canonical_function_rva(primary + 5), primary);
        EXPECT_EQ(module->canonical_function_rva(continuation), primary);
        EXPECT_EQ(module->canonical_function_rva(continuation + 5), primary);
        EXPECT_EQ(module->canonical_function_rva(independent + 5), independent);
        EXPECT_FALSE(module->canonical_function_rva(continuation + 0x10).has_value());
        EXPECT_FALSE(module->canonical_function_rva(0x1150).has_value());
    }

    TEST(ChainedUnwind, FileAndMemoryLoadersProduceSameOwnership)
    {
        const auto bytes = make_chained_pe();
        const TemporaryPe file(bytes);
        const auto memory = symfind::PeModule::from_memory(bytes, image_base);
        const auto disk = symfind::PeModule::from_file(file.m_path.string());
        ASSERT_TRUE(memory.has_value());
        ASSERT_TRUE(disk.has_value());
        ASSERT_EQ(memory->exception_functions().size(), disk->exception_functions().size());
        for (const auto& expected : memory->exception_functions())
        {
            const auto* actual = bounds_at(*disk, expected.rva);
            ASSERT_NE(actual, nullptr);
            EXPECT_EQ(actual->size, expected.size);
            EXPECT_EQ(ranges_of(actual->ranges), ranges_of(expected.ranges));
        }
        EXPECT_EQ(disk->canonical_function_rva(continuation + 5), primary);
        const auto db = symfind::AnalysisDb::analyze(*disk);
        const auto* caller = db.function_by_name("TestLoader");
        ASSERT_NE(caller, nullptr);
        EXPECT_EQ(caller->callees, (std::vector<uint64_t>{target}));
    }

    TEST(ChainedUnwind, ContinuationCallRepairsCallerEdgeWithoutClaimingGap)
    {
        const auto module = symfind::PeModule::from_memory(make_chained_pe(), image_base);
        ASSERT_TRUE(module.has_value());
        const auto db = symfind::AnalysisDb::analyze(*module);
        const auto* caller = db.function_by_name("TestLoader");
        const auto* callee = db.function_at(target);
        const auto* gap_function = db.function_at(independent);
        ASSERT_NE(caller, nullptr);
        ASSERT_NE(callee, nullptr);
        ASSERT_NE(gap_function, nullptr);
        EXPECT_EQ(caller->rva, primary);
        EXPECT_EQ(caller->size, 0x10);
        EXPECT_EQ(caller->ranges.size(), 2);
        EXPECT_EQ(caller->callees, (std::vector<uint64_t>{target}));
        EXPECT_EQ(caller->call_count, 1);
        EXPECT_FALSE(contains(caller->callees, gap_target));
        EXPECT_FALSE(contains(caller->callees, continuation)); // A JMP does not become a CALL.
        EXPECT_TRUE(contains(callee->callers, primary));
        EXPECT_FALSE(contains(callee->callers, continuation));
        EXPECT_TRUE(contains(gap_function->callees, primary)); // Incoming call to a continuation is canonicalized.
        EXPECT_TRUE(contains(gap_function->callees, gap_target));
        EXPECT_EQ(db.function_at(continuation), nullptr);
        const auto rule = symfind::dsl::DslParser::parse(R"(
            find function in "chain-fixture" where
                called_by "TestLoader";
                not exported;
                calls "TestAnchor";
        )");
        ASSERT_TRUE(rule.has_value());
        const auto matches = symfind::dsl::DslMatcher::match(db, *rule);
        ASSERT_EQ(matches.size(), 1);
        EXPECT_EQ(matches.front().rva, target);
    }

    TEST(ChainedUnwind, ExportAliasesKeepNameLookupAndNamedCallPredicates)
    {
        for (const uint32_t alias_entry : {primary, continuation})
        {
            SCOPED_TRACE(alias_entry);
            auto bytes = make_chained_pe();
            // TestAnchor becomes another export of TestLoader's procedure,
            // either at the exact entry or at an owned continuation entry.
            put(bytes, file_offset(0x4044), alias_entry, 4);
            const auto module = symfind::PeModule::from_memory(bytes, image_base);
            ASSERT_TRUE(module.has_value());
            const auto db = symfind::AnalysisDb::analyze(*module);
            const auto* first = db.function_by_name("TestLoader");
            const auto* second = db.function_by_name("TestAnchor");
            ASSERT_NE(first, nullptr);
            ASSERT_NE(second, nullptr);
            EXPECT_EQ(first, second);
            EXPECT_EQ(first->rva, primary);
            for (const std::string_view alias : {"TestLoader", "TestAnchor"})
            {
                SCOPED_TRACE(alias);
                for (const std::string_view predicate : {"calls", "called_by"})
                {
                    SCOPED_TRACE(predicate);
                    const auto script = std::string("find function in \"chain-fixture\" where ") +
                                        std::string(predicate) + " \"" + std::string(alias) + "\"; not exported;";
                    const auto rule = symfind::dsl::DslParser::parse(script);
                    ASSERT_TRUE(rule.has_value());
                    const auto matches = symfind::dsl::DslMatcher::match(db, *rule);
                    ASSERT_EQ(matches.size(), 1);
                    EXPECT_EQ(matches.front().rva, predicate == "calls" ? independent : target);
                }
            }
        }
    }

    TEST(ChainedUnwind, RepeatedCallsInContinuationRemainSeparateInstructions)
    {
        auto bytes = make_chained_pe();
        std::fill_n(bytes.begin() + file_offset(continuation), 0x10, 0xcc);
        direct_branch(bytes, continuation, target, 0xe8);
        direct_branch(bytes, continuation + 5, target, 0xe8);
        bytes[file_offset(continuation + 10)] = 0xc3;
        const auto module = symfind::PeModule::from_memory(bytes, image_base);
        ASSERT_TRUE(module.has_value());
        const auto db = symfind::AnalysisDb::analyze(*module);
        const auto* function = db.function_at(primary);
        ASSERT_NE(function, nullptr);
        EXPECT_EQ(function->call_count, 2);
        EXPECT_TRUE(contains(function->callees, target));
    }

    TEST(ChainedUnwind, ContinuationDataReferenceBelongsToPrimaryAndGapRemainsIndependent)
    {
        const auto module = symfind::PeModule::from_memory(make_chained_pe(), image_base);
        ASSERT_TRUE(module.has_value());
        const auto db = symfind::AnalysisDb::analyze(*module);
        const auto* function = db.function_at(primary);
        ASSERT_NE(function, nullptr);
        ASSERT_EQ(function->data_refs.size(), 1);
        EXPECT_EQ(function->data_refs.front().from_rva, continuation + 5);
        EXPECT_EQ(function->data_refs.front().from_func, primary);
        EXPECT_EQ(function->data_refs.front().to_rva, owned_data);
        const auto* gap = db.function_at(independent);
        ASSERT_NE(gap, nullptr);
        ASSERT_EQ(gap->data_refs.size(), 1);
        EXPECT_EQ(gap->data_refs.front().from_func, independent);
        EXPECT_EQ(gap->data_refs.front().to_rva, gap_data);
        const auto* global = db.global_at(owned_data);
        ASSERT_NE(global, nullptr);
        ASSERT_EQ(global->refs.size(), 1);
        EXPECT_EQ(global->refs.front().from_func, primary);
    }

    TEST(ChainedUnwind, OddUnwindCodeCountAlignsChainedRuntimeFunction)
    {
        auto bytes = make_chained_pe();
        const auto head = file_offset(0x3000);
        bytes[head + 1] = 4;
        bytes[head + 2] = 1;
        bytes[head + 4] = 4;
        bytes[head + 5] = 0x72; // UWOP_ALLOC_SMALL: 64-byte primary frame.
        const auto head_code = file_offset(primary);
        const std::array<uint8_t, 4> allocate{0x48, 0x83, 0xec, 0x40};
        std::copy(allocate.begin(), allocate.end(), bytes.begin() + head_code);
        direct_branch(bytes, primary + 4, continuation, 0xe9);

        const auto tail = file_offset(0x3020);
        bytes[tail + 1] = 5;
        bytes[tail + 2] = 3; // SAVE_NONVOL_FAR consumes three UNWIND_CODE slots.
        bytes[tail + 4] = 5;
        bytes[tail + 5] = 0x35; // Save RBX at RSP + 0x20 in the inherited frame.
        put(bytes, tail + 6, 0x20, 4);
        put(bytes, tail + 10, 0, 2); // Pad the odd count to an even slot count.
        runtime_function(bytes, file_offset(0x302c), primary, primary + 0x10, 0x3000);
        const auto tail_code = file_offset(continuation);
        std::fill(bytes.begin() + tail_code, bytes.begin() + tail_code + 0x10, 0xcc);
        const std::array<uint8_t, 5> save{0x48, 0x89, 0x5c, 0x24, 0x20};
        std::copy(save.begin(), save.end(), bytes.begin() + tail_code);
        direct_branch(bytes, continuation + 5, target, 0xe8);
        bytes[file_offset(continuation + 10)] = 0xc3;
        const auto module = symfind::PeModule::from_memory(bytes, image_base);
        ASSERT_TRUE(module.has_value());
        EXPECT_EQ(module->canonical_function_rva(continuation + 5), primary);
        const auto* function = bounds_at(*module, primary);
        ASSERT_NE(function, nullptr);
        EXPECT_EQ(function->ranges.size(), 2);
    }

    TEST(ChainedUnwind, LoopBackEdgeMustReachAnOwnedRange)
    {
        for (const uint32_t destination : {primary + 5, independent})
        {
            SCOPED_TRACE(destination);
            auto bytes = make_chained_pe();
            std::fill(bytes.begin() + file_offset(continuation + 5), bytes.begin() + file_offset(continuation) + 0x10, 0xcc);
            direct_branch(bytes, continuation + 5, destination, 0xe9);
            const auto module = symfind::PeModule::from_memory(bytes, image_base);
            ASSERT_TRUE(module.has_value());
            const auto db = symfind::AnalysisDb::analyze(*module);
            const auto* function = db.function_at(primary);
            ASSERT_NE(function, nullptr);
            EXPECT_EQ(function->has_loop, destination == primary + 5);
        }
    }

    TEST(ChainedUnwind, InvalidChainsCannotAssignContinuationToUnrelatedPrimary)
    {
        for (const std::string_view mode : {"cycle", "wrong-end", "wrong-unwind", "missing-parent", "different-frame", "handler-and-chain"})
        {
            SCOPED_TRACE(mode);
            auto bytes = make_chained_pe();
            if (mode == "cycle")
            {
                bytes[file_offset(0x3000)] = 0x21;
                runtime_function(bytes, file_offset(0x3004), continuation, continuation + 0x10, 0x3020);
            }
            else if (mode == "wrong-end")
            {
                put(bytes, file_offset(0x3028), primary + 0x11, 4);
            }
            else if (mode == "wrong-unwind")
            {
                put(bytes, file_offset(0x302c), 0x3004, 4);
            }
            else if (mode == "missing-parent")
            {
                runtime_function(bytes, file_offset(0x3024), 0x1080, 0x1090, 0x3000);
            }
            else if (mode == "different-frame")
            {
                bytes[file_offset(0x3023)] = 0x13;
            }
            else
            {
                bytes[file_offset(0x3020)] = 0x29; // CHAININFO cannot coexist with EHANDLER.
            }

            const auto module = symfind::PeModule::from_memory(bytes, image_base);
            ASSERT_TRUE(module.has_value());
            const auto* head = bounds_at(*module, primary);
            const auto* tail = bounds_at(*module, continuation);
            ASSERT_NE(head, nullptr);
            ASSERT_NE(tail, nullptr);
            EXPECT_EQ(head->ranges.size(), 1);
            EXPECT_EQ(tail->ranges.size(), 1);
            EXPECT_EQ(module->canonical_function_rva(continuation + 5), continuation);
        }
    }

    TEST(ChainedUnwind, InvalidRuntimeBoundsAreNotClaimedByPrimary)
    {
        for (const uint32_t invalid_end : {continuation - 1, 0x5001u})
        {
            SCOPED_TRACE(invalid_end);
            auto bytes = make_chained_pe();
            put(bytes, 0x800 + 2 * 12 + 4, invalid_end, 4);
            const auto module = symfind::PeModule::from_memory(bytes, image_base);
            ASSERT_TRUE(module.has_value());
            EXPECT_EQ(bounds_at(*module, continuation), nullptr);
            EXPECT_FALSE(module->canonical_function_rva(continuation + 5).has_value());
            const auto* head = bounds_at(*module, primary);
            ASSERT_NE(head, nullptr);
            EXPECT_EQ(head->ranges.size(), 1);
        }
    }
} // namespace
