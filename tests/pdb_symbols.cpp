#include "pdb_symbols.h"
#include "ntdll_symbol_rules.h"

#include "symfind/symfind.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <DbgHelp.h>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <exception>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <mutex>
#include <sstream>
#include <stdexcept>

namespace symfind::validation
{
    namespace
    {
        template <class T>
        T read_object(std::span<const uint8_t> bytes, size_t offset)
        {
            if (offset > bytes.size() || sizeof(T) > bytes.size() - offset)
                throw std::runtime_error("Truncated PE metadata");
            T result{};
            std::memcpy(&result, bytes.data() + offset, sizeof(T));
            return result;
        }

        std::vector<uint8_t> read_file(const std::filesystem::path& path)
        {
            std::ifstream input(path, std::ios::binary | std::ios::ate);
            if (!input)
                throw std::runtime_error("Cannot open DLL: " + path.string());
            const auto length = input.tellg();
            if (length <= 0)
                throw std::runtime_error("Empty or unreadable DLL: " + path.string());
            std::vector<uint8_t> bytes(static_cast<size_t>(length));
            input.seekg(0);
            if (!input.read(reinterpret_cast<char*>(bytes.data()), length))
                throw std::runtime_error("Cannot read DLL: " + path.string());
            return bytes;
        }

        std::string win_error(std::string_view operation)
        {
            return std::string(operation) + " failed (Win32 error " +
                   std::to_string(GetLastError()) + ")";
        }

        std::mutex dbghelp_mutex;

        BOOL CALLBACK debug_symbols(HANDLE, ULONG action, ULONG64 data, ULONG64)
        {
            if (action == CBA_DEBUG_INFO)
                std::fputs(reinterpret_cast<const char*>(data), stderr);
            return FALSE;
        }

        // DbgHelp locates a PDB by its RSDS basename. Stage the explicitly
        // selected file alone so arbitrary input names work without searching
        // neighboring DLLs, embedded build paths or symbol-server settings.
        class StagedPdb
        {
            public:
                StagedPdb(const std::filesystem::path& source, const std::string& rsds_name)
                {
                    const std::filesystem::path basename = rsds_name;
                    if (basename.filename() != basename ||
                        _wcsicmp(basename.extension().c_str(), L".pdb") != 0)
                        throw std::runtime_error("DLL RSDS contains an invalid PDB basename");
                    static std::atomic<unsigned> counter{0};
                    for (unsigned attempt = 0; attempt < 100; ++attempt)
                    {
                        directory_ = std::filesystem::temp_directory_path() /
                                     ("symfind-pdb-" + std::to_string(GetCurrentProcessId()) + "-" +
                                      std::to_string(GetTickCount64()) + "-" + std::to_string(counter++));
                        if (std::filesystem::create_directory(directory_))
                            break;
                        directory_.clear();
                    }
                    if (directory_.empty())
                        throw std::runtime_error("Could not create isolated PDB search directory");
                    path = directory_ / basename;
                    try
                    {
                        std::filesystem::copy_file(source, path);
                    }
                    catch (...)
                    {
                        std::error_code ignored;
                        std::filesystem::remove_all(directory_, ignored);
                        throw;
                    }
                }

                ~StagedPdb()
                {
                    std::error_code ignored;
                    std::filesystem::remove_all(directory_, ignored);
                }

                StagedPdb(const StagedPdb&) = delete;
                StagedPdb& operator=(const StagedPdb&) = delete;
                std::filesystem::path path;

            private:
                std::filesystem::path directory_;
        };

        // DbgHelp has process-global options and is not thread-safe. The lock
        // covers option changes, initialization, enumeration and cleanup.
        class SymbolSession
        {
            public:
                explicit SymbolSession(const std::filesystem::path& pdb)
                    : lock_(dbghelp_mutex), old_options_(SymGetOptions())
                {
                    const auto debug = GetEnvironmentVariableW(L"SYMFIND_PDB_DEBUG", nullptr, 0) != 0;
                    SymSetOptions(SYMOPT_EXACT_SYMBOLS |
                                  SYMOPT_IGNORE_NT_SYMPATH | SYMOPT_FAIL_CRITICAL_ERRORS |
                                  SYMOPT_NO_PROMPTS | SYMOPT_NO_IMAGE_SEARCH |
                                  SYMOPT_IGNORE_CVREC | SYMOPT_IGNORE_IMAGEDIR |
                                  SYMOPT_DISABLE_SYMSRV_AUTODETECT | (debug ? SYMOPT_DEBUG : 0));
                    const auto search_path = pdb.parent_path().wstring();
                    if (!SymInitializeW(handle(), search_path.c_str(), FALSE))
                    {
                        const auto error = win_error("SymInitializeW");
                        SymSetOptions(old_options_);
                        throw std::runtime_error(error);
                    }
                    if (debug)
                        SymRegisterCallback64(handle(), debug_symbols, 0);
                }

                ~SymbolSession()
                {
                    SymCleanup(handle());
                    SymSetOptions(old_options_);
                }

                SymbolSession(const SymbolSession&) = delete;
                SymbolSession& operator=(const SymbolSession&) = delete;
                [[nodiscard]] HANDLE handle() { return reinterpret_cast<HANDLE>(this); }

            private:
                std::unique_lock<std::mutex> lock_;
                DWORD old_options_;
        };

        struct EnumerationContext
        {
                PdbSymbols& result;
                DWORD64 base;
                std::exception_ptr error;
        };

        BOOL CALLBACK collect_symbol(PSYMBOL_INFO symbol, ULONG, PVOID raw_context)
        {
            auto& context = *static_cast<EnumerationContext*>(raw_context);
            try
            {
                const std::string name(symbol->Name, symbol->NameLen);
                const auto it = context.result.rvas.find(name);
                if (it == context.result.rvas.end())
                    return TRUE;
                if ((symbol->Flags & SYMFLAG_EXPORT) != 0)
                    throw std::runtime_error("Export fallback rejected for " + name);
                if (symbol->ModBase != context.base || symbol->Address < context.base ||
                    symbol->Address - context.base >= context.result.identity.image_size)
                    throw std::runtime_error("PDB symbol is outside the DLL image: " + name);
                it->second.push_back(symbol->Address - context.base);
                return TRUE;
            }
            catch (...)
            {
                context.error = std::current_exception();
                return FALSE;
            }
        }

        void deduplicate(std::vector<uint64_t>& rvas)
        {
            std::sort(rvas.begin(), rvas.end());
            rvas.erase(std::unique(rvas.begin(), rvas.end()), rvas.end());
        }

        std::vector<uint64_t> match_rvas(const std::vector<dsl::MatchResult>& matches)
        {
            std::vector<uint64_t> result;
            result.reserve(matches.size());
            for (const auto& match : matches)
                result.push_back(match.rva);
            return result;
        }

        std::string format_rvas(const std::vector<uint64_t>& rvas)
        {
            std::ostringstream out;
            out << std::hex << std::uppercase;
            for (size_t i = 0; i < rvas.size(); ++i)
            {
                if (i != 0)
                    out << ';';
                out << "0x" << rvas[i];
            }
            return out.str();
        }

        std::string csv_cell(std::string_view text)
        {
            std::string result = "\"";
            for (const char character : text)
            {
                if (character == '"')
                    result += '"';
                result += character;
            }
            return result + '"';
        }
    } // namespace

    std::string PdbIdentity::key() const
    {
        // The symbol-server GUID spelling follows GUID fields, not memory byte order.
        GUID value{};
        std::memcpy(&value, guid.data(), sizeof(value));
        std::ostringstream out;
        out << std::hex << std::uppercase << std::setfill('0')
            << std::setw(8) << value.Data1 << std::setw(4) << value.Data2
            << std::setw(4) << value.Data3;
        for (const auto byte : value.Data4)
            out << std::setw(2) << static_cast<unsigned>(byte);
        out << age;
        return out.str();
    }

    PdbIdentity read_pe_identity(std::span<const uint8_t> bytes)
    {
        const auto dos = read_object<IMAGE_DOS_HEADER>(bytes, 0);
        if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0)
            throw std::runtime_error("Invalid DOS header");
        const auto nt_offset = static_cast<size_t>(dos.e_lfanew);
        if (read_object<DWORD>(bytes, nt_offset) != IMAGE_NT_SIGNATURE)
            throw std::runtime_error("Invalid PE signature");
        const auto coff = read_object<IMAGE_FILE_HEADER>(bytes, nt_offset + sizeof(DWORD));
        const auto optional_offset = nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
        if (coff.SizeOfOptionalHeader > bytes.size() ||
            optional_offset > bytes.size() - coff.SizeOfOptionalHeader)
            throw std::runtime_error("Truncated optional header");
        const auto magic = read_object<WORD>(bytes, optional_offset);
        PdbIdentity result;
        result.machine = coff.Machine;
        IMAGE_DATA_DIRECTORY debug{};
        uint32_t headers_size = 0;
        if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            if (coff.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64))
                throw std::runtime_error("Truncated PE32+ optional header");
            const auto optional = read_object<IMAGE_OPTIONAL_HEADER64>(bytes, optional_offset);
            if (optional.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_DEBUG)
                throw std::runtime_error("DLL has no debug directory");
            result.image_size = optional.SizeOfImage;
            headers_size = optional.SizeOfHeaders;
            debug = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        }
        else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            if (coff.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER32))
                throw std::runtime_error("Truncated PE32 optional header");
            const auto optional = read_object<IMAGE_OPTIONAL_HEADER32>(bytes, optional_offset);
            if (optional.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_DEBUG)
                throw std::runtime_error("DLL has no debug directory");
            result.image_size = optional.SizeOfImage;
            headers_size = optional.SizeOfHeaders;
            debug = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        }
        else
            throw std::runtime_error("Unsupported PE optional header");

        if (result.image_size == 0 || debug.VirtualAddress == 0 || debug.Size == 0 ||
            debug.Size % sizeof(IMAGE_DEBUG_DIRECTORY) != 0)
            throw std::runtime_error("DLL has no valid debug directory");

        const auto section_offset = optional_offset + coff.SizeOfOptionalHeader;
        if (section_offset > bytes.size() ||
            coff.NumberOfSections > (bytes.size() - section_offset) / sizeof(IMAGE_SECTION_HEADER))
            throw std::runtime_error("Truncated section headers");
        const auto rva_to_offset = [&](uint32_t rva, uint32_t length) -> size_t
        {
            if (rva < headers_size && length <= headers_size - rva)
            {
                if (rva > bytes.size() || length > bytes.size() - rva)
                    throw std::runtime_error("Debug directory is outside DLL file");
                return rva;
            }
            for (size_t i = 0; i < coff.NumberOfSections; ++i)
            {
                const auto section = read_object<IMAGE_SECTION_HEADER>(
                    bytes, section_offset + i * sizeof(IMAGE_SECTION_HEADER));
                if (rva >= section.VirtualAddress)
                {
                    const uint64_t delta = uint64_t{rva} - section.VirtualAddress;
                    if (delta < section.SizeOfRawData && length <= section.SizeOfRawData - delta)
                    {
                        const uint64_t offset = uint64_t{section.PointerToRawData} + delta;
                        if (offset > bytes.size() || length > bytes.size() - offset)
                            throw std::runtime_error("Debug directory is outside DLL file");
                        return static_cast<size_t>(offset);
                    }
                }
            }
            throw std::runtime_error("Debug directory RVA is not backed by file data");
        };

        const auto directory_offset = rva_to_offset(debug.VirtualAddress, debug.Size);
        bool found = false;
        for (size_t i = 0; i < debug.Size / sizeof(IMAGE_DEBUG_DIRECTORY); ++i)
        {
            const auto entry = read_object<IMAGE_DEBUG_DIRECTORY>(
                bytes, directory_offset + i * sizeof(IMAGE_DEBUG_DIRECTORY));
            if (entry.Type != IMAGE_DEBUG_TYPE_CODEVIEW || entry.SizeOfData < 25)
                continue;
            const size_t record_offset = entry.PointerToRawData;
            if (record_offset > bytes.size() || entry.SizeOfData > bytes.size() - record_offset)
                throw std::runtime_error("CodeView record is outside DLL file");
            const auto record = bytes.subspan(record_offset, entry.SizeOfData);
            if (std::memcmp(record.data(), "RSDS", 4) != 0)
                continue;
            if (found)
                throw std::runtime_error("Multiple RSDS records are unsupported");
            std::memcpy(result.guid.data(), record.data() + 4, result.guid.size());
            result.age = read_object<uint32_t>(record, 20);
            const auto terminator = std::find(record.begin() + 24, record.end(), uint8_t{0});
            if (terminator == record.end() || terminator == record.begin() + 24)
                throw std::runtime_error("Missing PDB name in RSDS record");
            const std::string embedded_name(record.begin() + 24, terminator);
            const auto separator = embedded_name.find_last_of("/\\");
            result.pdb_name = embedded_name.substr(separator == std::string::npos ? 0 : separator + 1);
            found = true;
        }
        if (!found)
            throw std::runtime_error("DLL has no RSDS PDB identity");
        return result;
    }

    PdbIdentity read_pe_identity(const std::filesystem::path& dll)
    {
        return read_pe_identity(read_file(dll));
    }

    PdbSymbols read_pdb_symbols(const std::filesystem::path& dll,
                                const std::filesystem::path& pdb,
                                std::span<const std::string_view> names)
    {
        PdbSymbols result{read_pe_identity(dll), {}};
        if (result.identity.machine != IMAGE_FILE_MACHINE_AMD64)
            throw std::runtime_error("PDB comparison currently supports AMD64 DLLs only");
        if (!std::filesystem::is_regular_file(pdb))
            throw std::runtime_error("Explicit PDB file is missing: " + pdb.string());
        const auto explicit_pdb = std::filesystem::canonical(pdb);
        if (_wcsicmp(explicit_pdb.extension().c_str(), L".pdb") != 0)
            throw std::runtime_error("Explicit symbol file must have a .pdb extension");
        for (const auto name : names)
            result.rvas.emplace(std::string(name), std::vector<uint64_t>{});

        const StagedPdb staged_pdb(explicit_pdb, result.identity.pdb_name);
        SymbolSession session(staged_pdb.path);
        constexpr DWORD64 base = 0x10000000;
        const auto explicit_dll = std::filesystem::canonical(dll);
        struct ImageHandle
        {
                HANDLE value;
                ~ImageHandle()
                {
                    if (value != INVALID_HANDLE_VALUE)
                        CloseHandle(value);
                }
        } image_file{CreateFileW(explicit_dll.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                 nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)};
        if (image_file.value == INVALID_HANDLE_VALUE)
            throw std::runtime_error(win_error("CreateFileW(DLL)"));
        const auto loaded_base = SymLoadModuleExW(
            session.handle(), image_file.value, explicit_dll.c_str(), nullptr,
            base, result.identity.image_size, nullptr, 0);
        if (loaded_base == 0)
            throw std::runtime_error(win_error("SymLoadModuleExW"));
        IMAGEHLP_MODULEW64 information{};
        information.SizeOfStruct = sizeof(information);
        if (!SymGetModuleInfoW64(session.handle(), loaded_base, &information))
            throw std::runtime_error(win_error("SymGetModuleInfoW64"));
        if (information.SymType != SymPdb || information.PdbUnmatched || information.DbgUnmatched)
            throw std::runtime_error("DbgHelp rejected explicit PDB for DLL RSDS GUID+age (export fallback rejected): SymType=" +
                                     std::to_string(information.SymType) + ", PdbUnmatched=" + std::to_string(information.PdbUnmatched) +
                                     ", DbgUnmatched=" + std::to_string(information.DbgUnmatched) +
                                     ", PdbAge=" + std::to_string(information.PdbAge));
        if (std::memcmp(&information.PdbSig70, result.identity.guid.data(), 16) != 0 ||
            information.PdbAge != result.identity.age)
            throw std::runtime_error("PDB GUID+age does not match DLL RSDS identity " + result.identity.key());
        if (information.LoadedPdbName[0] == L'\0' ||
            !std::filesystem::equivalent(staged_pdb.path, std::filesystem::path(information.LoadedPdbName)))
            throw std::runtime_error("DbgHelp loaded a different PDB than the explicit input");

        EnumerationContext context{result, loaded_base, {}};
        const auto enumerated = SymEnumSymbols(session.handle(), loaded_base, "*", collect_symbol, &context);
        if (context.error)
            std::rethrow_exception(context.error);
        if (!enumerated)
            throw std::runtime_error(win_error("SymEnumSymbols"));
        for (auto& [name, rvas] : result.rvas)
            deduplicate(rvas);
        return result;
    }

    std::string_view status_name(ComparisonStatus status)
    {
        switch (status)
        {
        case ComparisonStatus::Match:
            return "match";
        case ComparisonStatus::Mismatch:
            return "mismatch";
        case ComparisonStatus::MissingPdbSymbol:
            return "missing-pdb-symbol";
        case ComparisonStatus::NoMatch:
            return "no-match";
        }
        return "unknown";
    }

    bool SymbolComparison::ambiguous() const
    {
        return pdb_rvas.size() > 1 || candidate_rvas.size() > 1;
    }

    SymbolComparison compare_symbol(std::string_view symbol,
                                    std::vector<uint64_t> pdb_rvas,
                                    std::vector<uint64_t> selected_rvas,
                                    std::vector<uint64_t> candidate_rvas)
    {
        deduplicate(pdb_rvas);
        SymbolComparison result{std::string(symbol), std::move(pdb_rvas),
                                std::move(selected_rvas), std::move(candidate_rvas)};
        if (result.pdb_rvas.empty())
            result.status = ComparisonStatus::MissingPdbSymbol;
        else if (result.selected_rvas.empty())
            result.status = ComparisonStatus::NoMatch;
        else if (result.pdb_rvas.size() == 1 && result.selected_rvas.size() == 1 &&
                 result.pdb_rvas.front() == result.selected_rvas.front())
            result.status = ComparisonStatus::Match;
        else
            result.status = ComparisonStatus::Mismatch;
        return result;
    }

    bool ComparisonReport::successful() const
    {
        return !symbols.empty() && std::all_of(symbols.begin(), symbols.end(), [](const auto& symbol)
                                               { return symbol.status == ComparisonStatus::Match; });
    }

    ComparisonReport compare_ntdll_symbols(const std::filesystem::path& dll,
                                           const std::filesystem::path& pdb)
    {
        std::array<std::string_view, ntdll_symbol_rules.size()> names{};
        for (size_t i = 0; i < names.size(); ++i)
            names[i] = ntdll_symbol_rules[i].symbol;
        // The independent oracle is loaded first. It never adds names to AnalysisDb.
        const auto oracle = read_pdb_symbols(dll, pdb, names);
        const auto module = PeModule::from_file(dll.string());
        if (!module)
            throw std::runtime_error("symfind could not parse DLL: " + dll.string());
        const auto database = AnalysisDb::analyze(*module);
        ComparisonReport report{dll, pdb, oracle.identity, {}};
        for (const auto& named_rule : ntdll_symbol_rules)
        {
            auto rule = dsl::DslParser::parse(named_rule.script);
            if (!rule)
                throw std::runtime_error("Invalid built-in DSL rule for " + std::string(named_rule.symbol));
            const auto selected = match_rvas(dsl::DslMatcher::match(database, *rule));
            std::erase_if(rule->predicates, [](const auto& predicate)
                          { return predicate && predicate->kind == dsl::PredKind::Take; });
            const auto candidates = match_rvas(dsl::DslMatcher::match(database, *rule));
            report.symbols.push_back(compare_symbol(named_rule.symbol,
                                                    oracle.rvas.at(std::string(named_rule.symbol)), selected, candidates));
        }
        return report;
    }

    std::vector<std::pair<std::filesystem::path, std::filesystem::path>>
        find_corpus_pairs(const std::filesystem::path& directory)
    {
        if (!std::filesystem::is_directory(directory))
            throw std::runtime_error("Corpus directory is missing: " + directory.string());
        std::vector<std::pair<std::filesystem::path, std::filesystem::path>> pairs;
        for (const auto& entry : std::filesystem::recursive_directory_iterator(directory))
        {
            if (entry.is_regular_file() && _wcsicmp(entry.path().filename().c_str(), L"ntdll.dll") == 0)
            {
                auto pdb = entry.path().parent_path() / "ntdll.pdb";
                try
                {
                    pdb = entry.path().parent_path() / read_pe_identity(entry.path()).pdb_name;
                }
                catch (const std::runtime_error&)
                {
                    // Keep corrupt fixtures in the set. Validation will report
                    // the PE error for this DLL while continuing other pairs.
                }
                pairs.emplace_back(entry.path(), std::move(pdb));
            }
        }
        std::sort(pairs.begin(), pairs.end());
        if (pairs.empty())
            throw std::runtime_error("Configured corpus contains no ntdll.dll files");
        return pairs;
    }

    std::string describe(const SymbolComparison& comparison)
    {
        return comparison.symbol + ": " + std::string(status_name(comparison.status)) +
               ", PDB=" + format_rvas(comparison.pdb_rvas) +
               ", selected=" + format_rvas(comparison.selected_rvas) +
               ", candidates=" + format_rvas(comparison.candidate_rvas) +
               (comparison.ambiguous() ? " (ambiguous)" : "");
    }

    void write_csv_header(std::ostream& output)
    {
        output << "dll,pdb,pdb_identity,symbol,expected_rva,actual_rva,candidate_rvas,candidate_count,ambiguous,status,error\n";
    }

    void write_csv_report(std::ostream& output, const ComparisonReport& report)
    {
        for (const auto& symbol : report.symbols)
        {
            output << csv_cell(report.dll.string()) << ',' << csv_cell(report.pdb.string()) << ','
                   << csv_cell(report.identity.key()) << ',' << csv_cell(symbol.symbol) << ','
                   << csv_cell(format_rvas(symbol.pdb_rvas)) << ','
                   << csv_cell(format_rvas(symbol.selected_rvas)) << ','
                   << csv_cell(format_rvas(symbol.candidate_rvas)) << ','
                   << symbol.candidate_rvas.size() << ',' << (symbol.ambiguous() ? "true" : "false")
                   << ',' << status_name(symbol.status) << ",\n";
        }
    }

    void write_csv_error(std::ostream& output, const std::filesystem::path& dll,
                         const std::filesystem::path& pdb, std::string_view error)
    {
        for (const auto& rule : ntdll_symbol_rules)
        {
            output << csv_cell(dll.string()) << ',' << csv_cell(pdb.string()) << ",,"
                   << csv_cell(rule.symbol) << ",,,,0,false,validation-error," << csv_cell(error) << '\n';
        }
    }
} // namespace symfind::validation
