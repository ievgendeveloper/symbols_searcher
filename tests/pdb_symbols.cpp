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
        T ReadObject(nonstd::span<const uint8_t> sourceBytes, size_t objectOffset)
        {
            if (objectOffset > sourceBytes.size() || sizeof(T) > sourceBytes.size() - objectOffset)
            {
                throw std::runtime_error("Truncated PE metadata");
            }
            T parsedObject{};
            std::memcpy(&parsedObject, sourceBytes.data() + objectOffset, sizeof(T));
            return parsedObject;
        }

        std::vector<uint8_t> ReadFile(const std::filesystem::path& dllPath)
        {
            std::ifstream dllStream(dllPath, std::ios::binary | std::ios::ate);
            if (!dllStream)
            {
                throw std::runtime_error("Cannot open DLL: " + dllPath.string());
            }
            const auto fileSize = dllStream.tellg();
            if (fileSize <= 0)
            {
                throw std::runtime_error("Empty or unreadable DLL: " + dllPath.string());
            }
            std::vector<uint8_t> dllBytes(static_cast<size_t>(fileSize));
            dllStream.seekg(0);
            if (!dllStream.read(reinterpret_cast<char*>(dllBytes.data()), fileSize))
            {
                throw std::runtime_error("Cannot read DLL: " + dllPath.string());
            }
            return dllBytes;
        }

        std::string WinError(std::string_view operation)
        {
            return std::string(operation) + " failed (Win32 error " +
                   std::to_string(GetLastError()) + ")";
        }

        std::mutex dbghelpMutex;

        BOOL CALLBACK DebugSymbols(HANDLE, ULONG callbackAction, ULONG64 callbackData, ULONG64)
        {
            if (callbackAction == CBA_DEBUG_INFO)
            {
                std::fputs(reinterpret_cast<const char*>(callbackData), stderr);
            }
            return FALSE;
        }

        // DbgHelp locates a PDB by its RSDS basename. Stage the explicitly
        // selected file alone so arbitrary input names work without searching
        // neighboring DLLs, embedded build paths or symbol-server settings.
        class StagedPdb
        {
            public:
                StagedPdb(const std::filesystem::path& sourcePdbPath,
                          const std::string& rsdsPdbName)
                {
                    const std::filesystem::path pdbBasename = rsdsPdbName;
                    if (pdbBasename.filename() != pdbBasename ||
                        _wcsicmp(pdbBasename.extension().c_str(), L".pdb") != 0)
                    {
                        throw std::runtime_error("DLL RSDS contains an invalid PDB basename");
                    }
                    static std::atomic<unsigned> stagingSequence{0};
                    for (unsigned creationAttempt = 0; creationAttempt < 100; ++creationAttempt)
                    {
                        m_directory = std::filesystem::temp_directory_path() /
                                      ("symfind-pdb-" + std::to_string(GetCurrentProcessId()) +
                                       "-" + std::to_string(GetTickCount64()) + "-" +
                                       std::to_string(stagingSequence++));
                        if (std::filesystem::create_directory(m_directory))
                        {
                            break;
                        }
                        m_directory.clear();
                    }
                    if (m_directory.empty())
                    {
                        throw std::runtime_error("Could not create isolated PDB search directory");
                    }
                    path = m_directory / pdbBasename;
                    try
                    {
                        std::filesystem::copy_file(sourcePdbPath, path);
                    }
                    catch (...)
                    {
                        std::error_code cleanupError;
                        std::filesystem::remove_all(m_directory, cleanupError);
                        throw;
                    }
                }

                ~StagedPdb()
                {
                    std::error_code cleanupError;
                    std::filesystem::remove_all(m_directory, cleanupError);
                }

                StagedPdb(const StagedPdb&) = delete;
                StagedPdb& operator=(const StagedPdb&) = delete;
                std::filesystem::path path;

            private:
                std::filesystem::path m_directory;
        };

        // DbgHelp has process-global options and is not thread-safe. The lock
        // covers option changes, initialization, enumeration and cleanup.
        class SymbolSession
        {
            public:
                explicit SymbolSession(const std::filesystem::path& pdbPath)
                    : m_lock(dbghelpMutex), m_oldOptions(SymGetOptions())
                {
                    const auto debugLoggingEnabled =
                        GetEnvironmentVariableW(L"SYMFIND_PDB_DEBUG", nullptr, 0) != 0;
                    SymSetOptions(SYMOPT_EXACT_SYMBOLS | SYMOPT_IGNORE_NT_SYMPATH |
                                  SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_NO_PROMPTS |
                                  SYMOPT_NO_IMAGE_SEARCH | SYMOPT_IGNORE_CVREC |
                                  SYMOPT_IGNORE_IMAGEDIR | SYMOPT_DISABLE_SYMSRV_AUTODETECT |
                                  (debugLoggingEnabled ? SYMOPT_DEBUG : 0));
                    const auto symbolSearchPath = pdbPath.parent_path().wstring();
                    if (!SymInitializeW(Handle(), symbolSearchPath.c_str(), FALSE))
                    {
                        const auto initializationError = WinError("SymInitializeW");
                        SymSetOptions(m_oldOptions);
                        throw std::runtime_error(initializationError);
                    }
                    if (debugLoggingEnabled)
                    {
                        SymRegisterCallback64(Handle(), DebugSymbols, 0);
                    }
                }

                ~SymbolSession()
                {
                    SymCleanup(Handle());
                    SymSetOptions(m_oldOptions);
                }

                SymbolSession(const SymbolSession&) = delete;
                SymbolSession& operator=(const SymbolSession&) = delete;
                [[nodiscard]] HANDLE Handle()
                {
                    return reinterpret_cast<HANDLE>(this);
                }

            private:
                std::unique_lock<std::mutex> m_lock;
                DWORD m_oldOptions;
        };

        struct EnumerationContext
        {
                PdbSymbols& result;
                DWORD64 base;
                std::exception_ptr error;
        };

        BOOL CALLBACK CollectSymbol(PSYMBOL_INFO symbolInformation, ULONG, PVOID callbackContext)
        {
            auto& enumerationContext = *static_cast<EnumerationContext*>(callbackContext);
            try
            {
                const std::string symbolName(symbolInformation->Name, symbolInformation->NameLen);
                const auto symbolEntry = enumerationContext.result.rvas.find(symbolName);
                if (symbolEntry == enumerationContext.result.rvas.end())
                {
                    return TRUE;
                }
                if ((symbolInformation->Flags & SYMFLAG_EXPORT) != 0)
                {
                    throw std::runtime_error("Export fallback rejected for " + symbolName);
                }
                if (symbolInformation->ModBase != enumerationContext.base ||
                    symbolInformation->Address < enumerationContext.base ||
                    symbolInformation->Address - enumerationContext.base >=
                        enumerationContext.result.identity.imageSize)
                {
                    throw std::runtime_error("PDB symbol is outside the DLL image: " + symbolName);
                }
                symbolEntry->second.push_back(symbolInformation->Address - enumerationContext.base);
                return TRUE;
            }
            catch (...)
            {
                enumerationContext.error = std::current_exception();
                return FALSE;
            }
        }

        void Deduplicate(std::vector<uint64_t>& rvas)
        {
            std::sort(rvas.begin(), rvas.end());
            rvas.erase(std::unique(rvas.begin(), rvas.end()), rvas.end());
        }

        std::vector<uint64_t> MatchRvas(const std::vector<dsl::MatchResult>& matchedSymbols)
        {
            std::vector<uint64_t> matchedRvas;
            matchedRvas.reserve(matchedSymbols.size());
            for (const auto& matchedSymbol : matchedSymbols)
            {
                matchedRvas.push_back(matchedSymbol.rva);
            }
            return matchedRvas;
        }

        std::string FormatRvas(const std::vector<uint64_t>& rvas)
        {
            std::ostringstream formattedRvas;
            formattedRvas << std::hex << std::uppercase;
            for (size_t rvaIndex = 0; rvaIndex < rvas.size(); ++rvaIndex)
            {
                if (rvaIndex != 0)
                {
                    formattedRvas << ';';
                }
                formattedRvas << "0x" << rvas[rvaIndex];
            }
            return formattedRvas.str();
        }

        std::string CsvCell(std::string_view cellText)
        {
            std::string escapedCell = "\"";
            for (const char character : cellText)
            {
                if (character == '"')
                {
                    escapedCell += '"';
                }
                escapedCell += character;
            }
            return escapedCell + '"';
        }
    } // namespace

    std::string PdbIdentity::Key() const
    {
        // The symbol-server GUID spelling follows GUID fields, not memory byte order.
        GUID guidValue{};
        std::memcpy(&guidValue, guid.data(), sizeof(guidValue));
        std::ostringstream formattedIdentity;
        formattedIdentity << std::hex << std::uppercase << std::setfill('0') << std::setw(8)
                          << guidValue.Data1 << std::setw(4) << guidValue.Data2 << std::setw(4)
                          << guidValue.Data3;
        for (const auto guidByte : guidValue.Data4)
        {
            formattedIdentity << std::setw(2) << static_cast<unsigned>(guidByte);
        }
        formattedIdentity << age;
        return formattedIdentity.str();
    }

    PdbIdentity ReadPeIdentity(nonstd::span<const uint8_t> imageBytes)
    {
        const auto dosHeader = ReadObject<IMAGE_DOS_HEADER>(imageBytes, 0);
        if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE || dosHeader.e_lfanew < 0)
        {
            throw std::runtime_error("Invalid DOS header");
        }
        const auto ntHeadersOffset = static_cast<size_t>(dosHeader.e_lfanew);
        if (ReadObject<DWORD>(imageBytes, ntHeadersOffset) != IMAGE_NT_SIGNATURE)
        {
            throw std::runtime_error("Invalid PE signature");
        }
        const auto coffHeader =
            ReadObject<IMAGE_FILE_HEADER>(imageBytes, ntHeadersOffset + sizeof(DWORD));
        const auto optionalHeaderOffset =
            ntHeadersOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
        if (coffHeader.SizeOfOptionalHeader > imageBytes.size() ||
            optionalHeaderOffset > imageBytes.size() - coffHeader.SizeOfOptionalHeader)
        {
            throw std::runtime_error("Truncated optional header");
        }
        const auto optionalHeaderMagic = ReadObject<WORD>(imageBytes, optionalHeaderOffset);
        PdbIdentity pdbIdentity;
        pdbIdentity.machine = coffHeader.Machine;
        IMAGE_DATA_DIRECTORY debugDirectory{};
        uint32_t peHeadersSize = 0;
        if (optionalHeaderMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            if (coffHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64))
            {
                throw std::runtime_error("Truncated PE32+ optional header");
            }
            const auto optionalHeader =
                ReadObject<IMAGE_OPTIONAL_HEADER64>(imageBytes, optionalHeaderOffset);
            if (optionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_DEBUG)
            {
                throw std::runtime_error("DLL has no debug directory");
            }
            pdbIdentity.imageSize = optionalHeader.SizeOfImage;
            peHeadersSize = optionalHeader.SizeOfHeaders;
            debugDirectory = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        }
        else if (optionalHeaderMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            if (coffHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER32))
            {
                throw std::runtime_error("Truncated PE32 optional header");
            }
            const auto optionalHeader =
                ReadObject<IMAGE_OPTIONAL_HEADER32>(imageBytes, optionalHeaderOffset);
            if (optionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_DEBUG)
            {
                throw std::runtime_error("DLL has no debug directory");
            }
            pdbIdentity.imageSize = optionalHeader.SizeOfImage;
            peHeadersSize = optionalHeader.SizeOfHeaders;
            debugDirectory = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        }
        else
        {
            throw std::runtime_error("Unsupported PE optional header");
        }

        if (pdbIdentity.imageSize == 0 || debugDirectory.VirtualAddress == 0 ||
            debugDirectory.Size == 0 || debugDirectory.Size % sizeof(IMAGE_DEBUG_DIRECTORY) != 0)
        {
            throw std::runtime_error("DLL has no valid debug directory");
        }

        const auto sectionHeadersOffset = optionalHeaderOffset + coffHeader.SizeOfOptionalHeader;
        if (sectionHeadersOffset > imageBytes.size() ||
            coffHeader.NumberOfSections >
                (imageBytes.size() - sectionHeadersOffset) / sizeof(IMAGE_SECTION_HEADER))
        {
            throw std::runtime_error("Truncated section headers");
        }
        const auto rvaToFileOffset = [&](uint32_t requestedRva, uint32_t requestedSize) -> size_t
        {
            if (requestedRva < peHeadersSize && requestedSize <= peHeadersSize - requestedRva)
            {
                if (requestedRva > imageBytes.size() ||
                    requestedSize > imageBytes.size() - requestedRva)
                {
                    throw std::runtime_error("Debug directory is outside DLL file");
                }
                return requestedRva;
            }
            for (size_t sectionIndex = 0; sectionIndex < coffHeader.NumberOfSections;
                 ++sectionIndex)
            {
                const auto sectionHeader = ReadObject<IMAGE_SECTION_HEADER>(
                    imageBytes, sectionHeadersOffset + sectionIndex * sizeof(IMAGE_SECTION_HEADER));
                if (requestedRva >= sectionHeader.VirtualAddress)
                {
                    const uint64_t sectionRelativeOffset =
                        uint64_t{requestedRva} - sectionHeader.VirtualAddress;
                    if (sectionRelativeOffset < sectionHeader.SizeOfRawData &&
                        requestedSize <= sectionHeader.SizeOfRawData - sectionRelativeOffset)
                    {
                        const uint64_t fileOffset =
                            uint64_t{sectionHeader.PointerToRawData} + sectionRelativeOffset;
                        if (fileOffset > imageBytes.size() ||
                            requestedSize > imageBytes.size() - fileOffset)
                        {
                            throw std::runtime_error("Debug directory is outside DLL file");
                        }
                        return static_cast<size_t>(fileOffset);
                    }
                }
            }
            throw std::runtime_error("Debug directory RVA is not backed by file data");
        };

        const auto debugDirectoryOffset =
            rvaToFileOffset(debugDirectory.VirtualAddress, debugDirectory.Size);
        bool foundRsdsRecord = false;
        for (size_t debugEntryIndex = 0;
             debugEntryIndex < debugDirectory.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
             ++debugEntryIndex)
        {
            const auto debugEntry = ReadObject<IMAGE_DEBUG_DIRECTORY>(
                imageBytes, debugDirectoryOffset + debugEntryIndex * sizeof(IMAGE_DEBUG_DIRECTORY));
            if (debugEntry.Type != IMAGE_DEBUG_TYPE_CODEVIEW || debugEntry.SizeOfData < 25)
            {
                continue;
            }
            const size_t codeviewRecordOffset = debugEntry.PointerToRawData;
            if (codeviewRecordOffset > imageBytes.size() ||
                debugEntry.SizeOfData > imageBytes.size() - codeviewRecordOffset)
            {
                throw std::runtime_error("CodeView record is outside DLL file");
            }
            const auto codeviewRecord =
                imageBytes.subspan(codeviewRecordOffset, debugEntry.SizeOfData);
            if (std::memcmp(codeviewRecord.data(), "RSDS", 4) != 0)
            {
                continue;
            }
            if (foundRsdsRecord)
            {
                throw std::runtime_error("Multiple RSDS records are unsupported");
            }
            std::memcpy(pdbIdentity.guid.data(), codeviewRecord.data() + 4,
                        pdbIdentity.guid.size());
            pdbIdentity.age = ReadObject<uint32_t>(codeviewRecord, 20);
            const auto pdbNameTerminator =
                std::find(codeviewRecord.begin() + 24, codeviewRecord.end(), uint8_t{0});
            if (pdbNameTerminator == codeviewRecord.end() ||
                pdbNameTerminator == codeviewRecord.begin() + 24)
            {
                throw std::runtime_error("Missing PDB name in RSDS record");
            }
            const std::string embeddedPdbPath(codeviewRecord.begin() + 24, pdbNameTerminator);
            const auto pathSeparator = embeddedPdbPath.find_last_of("/\\");
            pdbIdentity.pdbName =
                embeddedPdbPath.substr(pathSeparator == std::string::npos ? 0 : pathSeparator + 1);
            foundRsdsRecord = true;
        }
        if (!foundRsdsRecord)
        {
            throw std::runtime_error("DLL has no RSDS PDB identity");
        }
        return pdbIdentity;
    }

    PdbIdentity ReadPeIdentity(const std::filesystem::path& dllPath)
    {
        return ReadPeIdentity(ReadFile(dllPath));
    }

    PdbSymbols ReadPdbSymbols(const std::filesystem::path& dllPath,
                              const std::filesystem::path& pdbPath,
                              nonstd::span<const std::string_view> symbolNames)
    {
        PdbSymbols pdbSymbols{ReadPeIdentity(dllPath), {}};
        if (pdbSymbols.identity.machine != IMAGE_FILE_MACHINE_AMD64)
        {
            throw std::runtime_error("PDB comparison currently supports AMD64 DLLs only");
        }
        if (!std::filesystem::is_regular_file(pdbPath))
        {
            throw std::runtime_error("Explicit PDB file is missing: " + pdbPath.string());
        }
        const auto canonicalPdbPath = std::filesystem::canonical(pdbPath);
        if (_wcsicmp(canonicalPdbPath.extension().c_str(), L".pdb") != 0)
        {
            throw std::runtime_error("Explicit symbol file must have a .pdb extension");
        }
        for (const auto symbolName : symbolNames)
        {
            pdbSymbols.rvas.emplace(std::string(symbolName), std::vector<uint64_t>{});
        }

        const StagedPdb stagedPdb(canonicalPdbPath, pdbSymbols.identity.pdbName);
        SymbolSession symbolSession(stagedPdb.path);
        constexpr DWORD64 moduleBaseAddress = 0x10000000;
        const auto canonicalDllPath = std::filesystem::canonical(dllPath);
        struct ImageHandle
        {
                HANDLE value;
                ~ImageHandle()
                {
                    if (value != INVALID_HANDLE_VALUE)
                    {
                        CloseHandle(value);
                    }
                }
        } dllFile{CreateFileW(canonicalDllPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)};
        if (dllFile.value == INVALID_HANDLE_VALUE)
        {
            throw std::runtime_error(WinError("CreateFileW(DLL)"));
        }
        const auto loadedModuleBase =
            SymLoadModuleExW(symbolSession.Handle(), dllFile.value, canonicalDllPath.c_str(),
                             nullptr, moduleBaseAddress, pdbSymbols.identity.imageSize, nullptr, 0);
        if (loadedModuleBase == 0)
        {
            throw std::runtime_error(WinError("SymLoadModuleExW"));
        }
        IMAGEHLP_MODULEW64 moduleInformation{};
        moduleInformation.SizeOfStruct = sizeof(moduleInformation);
        if (!SymGetModuleInfoW64(symbolSession.Handle(), loadedModuleBase, &moduleInformation))
        {
            throw std::runtime_error(WinError("SymGetModuleInfoW64"));
        }
        if (moduleInformation.SymType != SymPdb || moduleInformation.PdbUnmatched ||
            moduleInformation.DbgUnmatched)
        {
            throw std::runtime_error(
                "DbgHelp rejected explicit PDB for DLL RSDS GUID+age (export fallback rejected): "
                "SymType=" +
                std::to_string(moduleInformation.SymType) +
                ", PdbUnmatched=" + std::to_string(moduleInformation.PdbUnmatched) +
                ", DbgUnmatched=" + std::to_string(moduleInformation.DbgUnmatched) +
                ", PdbAge=" + std::to_string(moduleInformation.PdbAge));
        }
        if (std::memcmp(&moduleInformation.PdbSig70, pdbSymbols.identity.guid.data(), 16) != 0 ||
            moduleInformation.PdbAge != pdbSymbols.identity.age)
        {
            throw std::runtime_error("PDB GUID+age does not match DLL RSDS identity " +
                                     pdbSymbols.identity.Key());
        }
        if (moduleInformation.LoadedPdbName[0] == L'\0' ||
            !std::filesystem::equivalent(stagedPdb.path,
                                         std::filesystem::path(moduleInformation.LoadedPdbName)))
        {
            throw std::runtime_error("DbgHelp loaded a different PDB than the explicit input");
        }

        EnumerationContext enumerationContext{pdbSymbols, loadedModuleBase, {}};
        const auto enumerationSucceeded = SymEnumSymbols(symbolSession.Handle(), loadedModuleBase,
                                                         "*", CollectSymbol, &enumerationContext);
        if (enumerationContext.error)
        {
            std::rethrow_exception(enumerationContext.error);
        }
        if (!enumerationSucceeded)
        {
            throw std::runtime_error(WinError("SymEnumSymbols"));
        }
        for (auto& [symbolName, rvas] : pdbSymbols.rvas)
        {
            Deduplicate(rvas);
        }
        return pdbSymbols;
    }

    std::string_view StatusName(ComparisonStatus comparisonStatus)
    {
        switch (comparisonStatus)
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

    bool SymbolComparison::Ambiguous() const
    {
        return pdbRvas.size() > 1 || candidateRvas.size() > 1;
    }

    SymbolComparison CompareSymbol(std::string_view symbolName, std::vector<uint64_t> pdbRvas,
                                   std::vector<uint64_t> selectedRvas,
                                   std::vector<uint64_t> candidateRvas)
    {
        Deduplicate(pdbRvas);
        SymbolComparison comparison{std::string(symbolName), std::move(pdbRvas),
                                    std::move(selectedRvas), std::move(candidateRvas)};
        if (comparison.pdbRvas.empty())
        {
            comparison.status = ComparisonStatus::MissingPdbSymbol;
        }
        else if (comparison.selectedRvas.empty())
        {
            comparison.status = ComparisonStatus::NoMatch;
        }
        else if (comparison.pdbRvas.size() == 1 && comparison.selectedRvas.size() == 1 &&
                 comparison.pdbRvas.front() == comparison.selectedRvas.front())
        {
            comparison.status = ComparisonStatus::Match;
        }
        else
        {
            comparison.status = ComparisonStatus::Mismatch;
        }
        return comparison;
    }

    bool ComparisonReport::Successful() const
    {
        return !symbols.empty() &&
               std::all_of(symbols.begin(), symbols.end(),
                           [](const auto& symbolComparison)
                           {
                               return symbolComparison.status == ComparisonStatus::Match;
                           });
    }

    ComparisonReport CompareNtdllSymbols(const std::filesystem::path& dllPath,
                                         const std::filesystem::path& pdbPath)
    {
        std::array<std::string_view, ntdllSymbolRules.size()> symbolNames{};
        for (size_t symbolIndex = 0; symbolIndex < symbolNames.size(); ++symbolIndex)
        {
            symbolNames[symbolIndex] = ntdllSymbolRules[symbolIndex].symbol;
        }
        // The independent oracle is loaded first. It never adds names to AnalysisDb.
        const auto pdbSymbols = ReadPdbSymbols(dllPath, pdbPath, symbolNames);
        const auto peModule = PeModule::FromFile(dllPath.string());
        if (!peModule)
        {
            throw std::runtime_error("symfind could not parse DLL: " + dllPath.string());
        }
        const auto analysisDatabase = AnalysisDb::Analyze(*peModule);
        ComparisonReport comparisonReport{dllPath, pdbPath, pdbSymbols.identity, {}};
        for (const auto& symbolRule : ntdllSymbolRules)
        {
            auto parsedRule = dsl::DslParser::Parse(symbolRule.script);
            if (!parsedRule)
            {
                throw std::runtime_error("Invalid built-in DSL rule for " +
                                         std::string(symbolRule.symbol));
            }
            const auto selectedRvas =
                MatchRvas(dsl::DslMatcher::Match(analysisDatabase, *parsedRule));
            parsedRule->predicates.erase(
                std::remove_if(parsedRule->predicates.begin(), parsedRule->predicates.end(),
                               [](const auto& predicate)
                               {
                                   return predicate && predicate->kind == dsl::PredKind::Take;
                               }),
                parsedRule->predicates.end());
            const auto candidateRvas =
                MatchRvas(dsl::DslMatcher::Match(analysisDatabase, *parsedRule));
            comparisonReport.symbols.push_back(
                CompareSymbol(symbolRule.symbol, pdbSymbols.rvas.at(std::string(symbolRule.symbol)),
                              selectedRvas, candidateRvas));
        }
        return comparisonReport;
    }

    std::vector<std::pair<std::filesystem::path, std::filesystem::path>> FindCorpusPairs(
        const std::filesystem::path& corpusDirectory)
    {
        if (!std::filesystem::is_directory(corpusDirectory))
        {
            throw std::runtime_error("Corpus directory is missing: " + corpusDirectory.string());
        }
        std::vector<std::pair<std::filesystem::path, std::filesystem::path>> dllPdbPairs;
        for (const auto& corpusEntry :
             std::filesystem::recursive_directory_iterator(corpusDirectory))
        {
            if (corpusEntry.is_regular_file() &&
                _wcsicmp(corpusEntry.path().filename().c_str(), L"ntdll.dll") == 0)
            {
                auto pdbPath = corpusEntry.path().parent_path() / "ntdll.pdb";
                try
                {
                    pdbPath = corpusEntry.path().parent_path() /
                              ReadPeIdentity(corpusEntry.path()).pdbName;
                }
                catch (const std::runtime_error&)
                {
                    // Keep corrupt fixtures in the set. Validation will report
                    // the PE error for this DLL while continuing other pairs.
                }
                dllPdbPairs.emplace_back(corpusEntry.path(), std::move(pdbPath));
            }
        }
        std::sort(dllPdbPairs.begin(), dllPdbPairs.end());
        if (dllPdbPairs.empty())
        {
            throw std::runtime_error("Configured corpus contains no ntdll.dll files");
        }
        return dllPdbPairs;
    }

    std::string Describe(const SymbolComparison& symbolComparison)
    {
        return symbolComparison.symbol + ": " + std::string(StatusName(symbolComparison.status)) +
               ", PDB=" + FormatRvas(symbolComparison.pdbRvas) +
               ", selected=" + FormatRvas(symbolComparison.selectedRvas) +
               ", candidates=" + FormatRvas(symbolComparison.candidateRvas) +
               (symbolComparison.Ambiguous() ? " (ambiguous)" : "");
    }

    void WriteCsvHeader(std::ostream& csvOutput)
    {
        csvOutput << "dll,pdb,pdb_identity,symbol,expected_rva,actual_rva,candidate_rvas,candidate_"
                     "count,ambiguous,status,error\n";
    }

    void WriteCsvReport(std::ostream& csvOutput, const ComparisonReport& comparisonReport)
    {
        for (const auto& symbolComparison : comparisonReport.symbols)
        {
            csvOutput << CsvCell(comparisonReport.dll.string()) << ','
                      << CsvCell(comparisonReport.pdb.string()) << ','
                      << CsvCell(comparisonReport.identity.Key()) << ','
                      << CsvCell(symbolComparison.symbol) << ','
                      << CsvCell(FormatRvas(symbolComparison.pdbRvas)) << ','
                      << CsvCell(FormatRvas(symbolComparison.selectedRvas)) << ','
                      << CsvCell(FormatRvas(symbolComparison.candidateRvas)) << ','
                      << symbolComparison.candidateRvas.size() << ','
                      << (symbolComparison.Ambiguous() ? "true" : "false") << ','
                      << StatusName(symbolComparison.status) << ",\n";
        }
    }

    void WriteCsvError(std::ostream& csvOutput, const std::filesystem::path& dllPath,
                       const std::filesystem::path& pdbPath, std::string_view errorMessage)
    {
        for (const auto& symbolRule : ntdllSymbolRules)
        {
            csvOutput << CsvCell(dllPath.string()) << ',' << CsvCell(pdbPath.string()) << ",,"
                      << CsvCell(symbolRule.symbol) << ",,,,0,false,validation-error,"
                      << CsvCell(errorMessage) << '\n';
        }
    }
} // namespace symfind::validation
