#pragma once

#include "pdb_stuff/fixtures.h"

#include <nonstd/span.hpp>

#include <algorithm>
#include <array>
#include <cstdio>
#include <string_view>
#include <utility>

namespace symfind::testFixtures
{
    using pdbStuff::Bytes;
    using pdbStuff::Json;
    inline constexpr std::string_view dllMember = "Files/Windows/System32/ntdll.dll";
    inline constexpr std::string_view guid = "6192BFDB9F04442995FFCB0BE95172E1";
    inline constexpr std::array<uint8_t, 16> guidBytes{0xdb, 0xbf, 0x92, 0x61, 0x04, 0x9f,
                                                       0x29, 0x44, 0x95, 0xff, 0xcb, 0x0b,
                                                       0xe9, 0x51, 0x72, 0xe1};

    inline void Put(Bytes& fixtureBytes, size_t byteOffset, uint64_t integerValue, size_t byteCount)
    {
        if (byteOffset > fixtureBytes.size() || byteCount > fixtureBytes.size() - byteOffset)
        {
            throw std::runtime_error("Test byte fixture write is out of bounds");
        }
        for (size_t byteIndex = 0; byteIndex < byteCount; ++byteIndex)
        {
            fixtureBytes[byteOffset + byteIndex] =
                static_cast<uint8_t>(integerValue >> (byteIndex * 8));
        }
    }

    inline void PutString(Bytes& fixtureBytes, size_t byteOffset, std::string_view text)
    {
        if (byteOffset > fixtureBytes.size() || text.size() > fixtureBytes.size() - byteOffset)
        {
            throw std::runtime_error("Test string fixture write is out of bounds");
        }
        std::copy(text.begin(), text.end(), fixtureBytes.begin() + byteOffset);
    }

    inline Bytes MakePe()
    {
        Bytes peBytes(1024);
        PutString(peBytes, 0, "MZ");
        Put(peBytes, 0x3c, 0x80, 4);
        PutString(peBytes, 0x80, std::string_view("PE\0\0", 4));
        Put(peBytes, 0x84, 0x8664, 2);
        Put(peBytes, 0x86, 1, 2);
        Put(peBytes, 0x88, 0x4ce7c8f9, 4);
        Put(peBytes, 0x94, 240, 2);
        constexpr size_t optionalHeaderOffset = 0x98;
        Put(peBytes, optionalHeaderOffset, 0x20b, 2);
        Put(peBytes, optionalHeaderOffset + 56, 0x2000, 4);
        Put(peBytes, optionalHeaderOffset + 60, 0x200, 4);
        Put(peBytes, optionalHeaderOffset + 108, 16, 4);
        Put(peBytes, optionalHeaderOffset + 112 + 6 * 8, 0x1000, 4);
        Put(peBytes, optionalHeaderOffset + 116 + 6 * 8, 28, 4);
        const size_t sectionHeaderOffset = optionalHeaderOffset + 240;
        PutString(peBytes, sectionHeaderOffset, ".text");
        Put(peBytes, sectionHeaderOffset + 8, 512, 4);
        Put(peBytes, sectionHeaderOffset + 12, 0x1000, 4);
        Put(peBytes, sectionHeaderOffset + 16, 512, 4);
        Put(peBytes, sectionHeaderOffset + 20, 0x200, 4);
        Bytes codeviewRecord(24);
        PutString(codeviewRecord, 0, "RSDS");
        std::copy(guidBytes.begin(), guidBytes.end(), codeviewRecord.begin() + 4);
        Put(codeviewRecord, 20, 2, 4);
        const std::string_view embeddedPdbPath = "c:\\symbols\\ntdll.pdb";
        codeviewRecord.insert(codeviewRecord.end(), embeddedPdbPath.begin(), embeddedPdbPath.end());
        codeviewRecord.push_back(0);
        Put(peBytes, 0x200 + 12, 2, 4);
        Put(peBytes, 0x200 + 16, codeviewRecord.size(), 4);
        Put(peBytes, 0x200 + 20, 0x1040, 4);
        Put(peBytes, 0x200 + 24, 0x240, 4);
        std::copy(codeviewRecord.begin(), codeviewRecord.end(), peBytes.begin() + 0x240);
        return peBytes;
    }

    inline Bytes MakePdb(uint32_t pdbAge = 2, uint32_t dbiAge = 2,
                         const std::array<uint8_t, 16>& pdbGuidBytes = guidBytes)
    {
        constexpr size_t blockSize = 512;
        Bytes pdbBytes(blockSize * 8);
        PutString(pdbBytes, 0,
                  std::string_view("Microsoft C/C++ MSF 7.00\r\n\x1a"
                                   "DS\0\0\0",
                                   32));
        const std::array<uint32_t, 6> superblockFields{512, 1, 8, 32, 0, 3};
        for (size_t fieldIndex = 0; fieldIndex < superblockFields.size(); ++fieldIndex)
        {
            Put(pdbBytes, 32 + fieldIndex * 4, superblockFields[fieldIndex], 4);
        }
        Put(pdbBytes, blockSize * 3, 4, 4);
        // Stream 1 occupies blocks 5 and 7; stream 3 (DBI) occupies block 6.
        const std::array<uint32_t, 8> streamDirectoryFields{4, 0, 600, 0, 64, 5, 7, 6};
        for (size_t fieldIndex = 0; fieldIndex < streamDirectoryFields.size(); ++fieldIndex)
        {
            Put(pdbBytes, blockSize * 4 + fieldIndex * 4, streamDirectoryFields[fieldIndex], 4);
        }
        Put(pdbBytes, blockSize * 5, 20000404, 4);
        Put(pdbBytes, blockSize * 5 + 4, 123, 4);
        Put(pdbBytes, blockSize * 5 + 8, pdbAge, 4);
        std::copy(pdbGuidBytes.begin(), pdbGuidBytes.end(), pdbBytes.begin() + blockSize * 5 + 12);
        Put(pdbBytes, blockSize * 6, 0xffffffff, 4);
        Put(pdbBytes, blockSize * 6 + 4, 19990903, 4);
        Put(pdbBytes, blockSize * 6 + 8, dbiAge, 4);
        return pdbBytes;
    }

    inline uint32_t Crc32(nonstd::span<const uint8_t> bytes)
    {
        uint32_t checksum = 0xffffffff;
        for (const uint8_t byte : bytes)
        {
            checksum ^= byte;
            for (unsigned bitIndex = 0; bitIndex < 8; ++bitIndex)
            {
                checksum = (checksum >> 1) ^ ((checksum & 1) ? 0xedb88320 : 0);
            }
        }
        return ~checksum;
    }

    // Independent RFC 1952 gzip writer using stored DEFLATE blocks. The reader
    // under test cannot reuse this implementation to accidentally validate itself.
    inline Bytes GzipBytes(nonstd::span<const uint8_t> payload)
    {
        Bytes gzipData{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255};
        size_t payloadOffset = 0;
        do
        {
            const size_t blockByteCount = std::min<size_t>(65535, payload.size() - payloadOffset);
            gzipData.push_back(payloadOffset + blockByteCount == payload.size() ? 1 : 0);
            gzipData.push_back(static_cast<uint8_t>(blockByteCount));
            gzipData.push_back(static_cast<uint8_t>(blockByteCount >> 8));
            gzipData.push_back(static_cast<uint8_t>(~blockByteCount));
            gzipData.push_back(static_cast<uint8_t>(~blockByteCount >> 8));
            gzipData.insert(gzipData.end(), payload.begin() + payloadOffset,
                            payload.begin() + payloadOffset + blockByteCount);
            payloadOffset += blockByteCount;
        } while (payloadOffset < payload.size());
        const size_t footerOffset = gzipData.size();
        gzipData.resize(footerOffset + 8);
        Put(gzipData, footerOffset, Crc32(payload), 4);
        Put(gzipData, footerOffset + 4, payload.size(), 4);
        return gzipData;
    }

    inline Bytes GzipJson(const Json& jsonValue)
    {
        const std::string jsonText = jsonValue.dump();
        return GzipBytes(nonstd::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(jsonText.data()), jsonText.size()));
    }

    inline Bytes MakeTar(std::string_view memberName = dllMember, Bytes memberBytes = MakePe(),
                         char entryType = '0')
    {
        Bytes tarBytes(512);
        PutString(tarBytes, 0, memberName);
        PutString(tarBytes, 100, "0000644");
        PutString(tarBytes, 108, "0000000");
        PutString(tarBytes, 116, "0000000");
        std::array<char, 12> octalFileSize{};
        std::snprintf(octalFileSize.data(), octalFileSize.size(), "%011llo",
                      static_cast<unsigned long long>(entryType == '0' ? memberBytes.size() : 0));
        PutString(tarBytes, 124, std::string_view(octalFileSize.data(), 11));
        PutString(tarBytes, 136, "00000000000");
        PutString(tarBytes, 148, "        ");
        tarBytes[156] = static_cast<uint8_t>(entryType);
        if (entryType != '0')
        {
            PutString(tarBytes, 157, "another-file");
        }
        PutString(tarBytes, 257, "ustar");
        PutString(tarBytes, 263, "00");
        uint32_t headerChecksum = 0;
        for (const auto byte : tarBytes)
        {
            headerChecksum += byte;
        }
        std::array<char, 8> octalChecksum{};
        std::snprintf(octalChecksum.data(), octalChecksum.size(), "%06o", headerChecksum);
        PutString(tarBytes, 148, std::string_view(octalChecksum.data(), 7));
        tarBytes[155] = ' ';
        if (entryType == '0')
        {
            tarBytes.insert(tarBytes.end(), memberBytes.begin(), memberBytes.end());
            tarBytes.resize((tarBytes.size() + 511) / 512 * 512);
        }
        tarBytes.resize(tarBytes.size() + 1024);
        return tarBytes;
    }

    inline Bytes MakeArchive(std::string_view memberName = dllMember, Bytes memberBytes = MakePe(),
                             char entryType = '0')
    {
        return GzipBytes(MakeTar(memberName, std::move(memberBytes), entryType));
    }

    inline Json ArchiveConfig(const Bytes& archiveBytes)
    {
        const auto archiveSha256 = pdbStuff::Sha256(archiveBytes);
        return Json{{"url", "https://mcr.microsoft.com/v2/windows/nanoserver/blobs/sha256:" +
                                archiveSha256},
                    {"sha256", archiveSha256},
                    {"file_size", archiveBytes.size()},
                    {"member", dllMember},
                    {"format", "tar.gz"}};
    }

} // namespace symfind::testFixtures
