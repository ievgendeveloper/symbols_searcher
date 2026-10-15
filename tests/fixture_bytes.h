#pragma once

#include "pdb_stuff/fixtures.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <string_view>
#include <utility>

namespace symfind::test_fixtures
{
    using pdb_stuff::Bytes;
    using pdb_stuff::Json;
    inline constexpr std::string_view dll_member = "Files/Windows/System32/ntdll.dll";
    inline constexpr std::string_view guid = "6192BFDB9F04442995FFCB0BE95172E1";
    inline constexpr std::array<uint8_t, 16> guid_bytes{
        0xdb, 0xbf, 0x92, 0x61, 0x04, 0x9f, 0x29, 0x44,
        0x95, 0xff, 0xcb, 0x0b, 0xe9, 0x51, 0x72, 0xe1};

    inline void put(Bytes& data, size_t offset, uint64_t value, size_t count)
    {
        if (offset > data.size() || count > data.size() - offset)
        {
            throw std::runtime_error("Test byte fixture write is out of bounds");
        }
        for (size_t i = 0; i < count; ++i)
        {
            data[offset + i] = static_cast<uint8_t>(value >> (i * 8));
        }
    }

    inline void put_string(Bytes& data, size_t offset, std::string_view value)
    {
        if (offset > data.size() || value.size() > data.size() - offset)
        {
            throw std::runtime_error("Test string fixture write is out of bounds");
        }
        std::copy(value.begin(), value.end(), data.begin() + offset);
    }

    inline Bytes make_pe()
    {
        Bytes data(1024);
        put_string(data, 0, "MZ");
        put(data, 0x3c, 0x80, 4);
        put_string(data, 0x80, std::string_view("PE\0\0", 4));
        put(data, 0x84, 0x8664, 2);
        put(data, 0x86, 1, 2);
        put(data, 0x88, 0x4ce7c8f9, 4);
        put(data, 0x94, 240, 2);
        constexpr size_t optional = 0x98;
        put(data, optional, 0x20b, 2);
        put(data, optional + 56, 0x2000, 4);
        put(data, optional + 60, 0x200, 4);
        put(data, optional + 108, 16, 4);
        put(data, optional + 112 + 6 * 8, 0x1000, 4);
        put(data, optional + 116 + 6 * 8, 28, 4);
        const size_t section = optional + 240;
        put_string(data, section, ".text");
        put(data, section + 8, 512, 4);
        put(data, section + 12, 0x1000, 4);
        put(data, section + 16, 512, 4);
        put(data, section + 20, 0x200, 4);
        Bytes record(24);
        put_string(record, 0, "RSDS");
        std::copy(guid_bytes.begin(), guid_bytes.end(), record.begin() + 4);
        put(record, 20, 2, 4);
        const std::string_view name = "c:\\symbols\\ntdll.pdb";
        record.insert(record.end(), name.begin(), name.end());
        record.push_back(0);
        put(data, 0x200 + 12, 2, 4);
        put(data, 0x200 + 16, record.size(), 4);
        put(data, 0x200 + 20, 0x1040, 4);
        put(data, 0x200 + 24, 0x240, 4);
        std::copy(record.begin(), record.end(), data.begin() + 0x240);
        return data;
    }

    inline Bytes make_pdb(uint32_t age = 2, uint32_t dbi_age = 2,
                          const std::array<uint8_t, 16>& signature = guid_bytes)
    {
        constexpr size_t block = 512;
        Bytes data(block * 8);
        put_string(data, 0, std::string_view("Microsoft C/C++ MSF 7.00\r\n\x1a"
                                             "DS\0\0\0",
                                             32));
        const std::array<uint32_t, 6> superblock{512, 1, 8, 32, 0, 3};
        for (size_t i = 0; i < superblock.size(); ++i)
        {
            put(data, 32 + i * 4, superblock[i], 4);
        }
        put(data, block * 3, 4, 4);
        // Stream 1 occupies blocks 5 and 7; stream 3 (DBI) occupies block 6.
        const std::array<uint32_t, 8> directory{4, 0, 600, 0, 64, 5, 7, 6};
        for (size_t i = 0; i < directory.size(); ++i)
        {
            put(data, block * 4 + i * 4, directory[i], 4);
        }
        put(data, block * 5, 20000404, 4);
        put(data, block * 5 + 4, 123, 4);
        put(data, block * 5 + 8, age, 4);
        std::copy(signature.begin(), signature.end(), data.begin() + block * 5 + 12);
        put(data, block * 6, 0xffffffff, 4);
        put(data, block * 6 + 4, 19990903, 4);
        put(data, block * 6 + 8, dbi_age, 4);
        return data;
    }

    inline uint32_t crc32(std::span<const uint8_t> bytes)
    {
        uint32_t crc = 0xffffffff;
        for (const uint8_t byte : bytes)
        {
            crc ^= byte;
            for (unsigned bit = 0; bit < 8; ++bit)
            {
                crc = (crc >> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
            }
        }
        return ~crc;
    }

    // Independent RFC 1952 gzip writer using stored DEFLATE blocks. The reader
    // under test cannot reuse this implementation to accidentally validate itself.
    inline Bytes gzip_bytes(std::span<const uint8_t> payload)
    {
        Bytes result{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255};
        size_t offset = 0;
        do
        {
            const size_t count = std::min<size_t>(65535, payload.size() - offset);
            result.push_back(offset + count == payload.size() ? 1 : 0);
            result.push_back(static_cast<uint8_t>(count));
            result.push_back(static_cast<uint8_t>(count >> 8));
            result.push_back(static_cast<uint8_t>(~count));
            result.push_back(static_cast<uint8_t>(~count >> 8));
            result.insert(result.end(), payload.begin() + offset, payload.begin() + offset + count);
            offset += count;
        } while (offset < payload.size());
        const size_t footer = result.size();
        result.resize(footer + 8);
        put(result, footer, crc32(payload), 4);
        put(result, footer + 4, payload.size(), 4);
        return result;
    }

    inline Bytes gzip_json(const Json& value)
    {
        const std::string encoded = value.dump();
        return gzip_bytes(std::span(reinterpret_cast<const uint8_t*>(encoded.data()), encoded.size()));
    }

    inline Bytes make_tar(std::string_view name = dll_member, Bytes payload = make_pe(), char type = '0')
    {
        Bytes tar(512);
        put_string(tar, 0, name);
        put_string(tar, 100, "0000644");
        put_string(tar, 108, "0000000");
        put_string(tar, 116, "0000000");
        std::array<char, 12> size{};
        std::snprintf(size.data(), size.size(), "%011llo",
                      static_cast<unsigned long long>(type == '0' ? payload.size() : 0));
        put_string(tar, 124, std::string_view(size.data(), 11));
        put_string(tar, 136, "00000000000");
        put_string(tar, 148, "        ");
        tar[156] = static_cast<uint8_t>(type);
        if (type != '0')
            put_string(tar, 157, "another-file");
        put_string(tar, 257, "ustar");
        put_string(tar, 263, "00");
        uint32_t sum = 0;
        for (const auto byte : tar)
            sum += byte;
        std::array<char, 8> checksum{};
        std::snprintf(checksum.data(), checksum.size(), "%06o", sum);
        put_string(tar, 148, std::string_view(checksum.data(), 7));
        tar[155] = ' ';
        if (type == '0')
        {
            tar.insert(tar.end(), payload.begin(), payload.end());
            tar.resize((tar.size() + 511) / 512 * 512);
        }
        tar.resize(tar.size() + 1024);
        return tar;
    }

    inline Bytes make_archive(std::string_view name = dll_member, Bytes payload = make_pe(), char type = '0')
    {
        return gzip_bytes(make_tar(name, std::move(payload), type));
    }

    inline Json archive_config(const Bytes& data)
    {
        const auto digest = pdb_stuff::sha256(data);
        return Json{{"url", "https://mcr.microsoft.com/v2/windows/nanoserver/blobs/sha256:" + digest},
                    {"sha256", digest},
                    {"file_size", data.size()},
                    {"member", dll_member},
                    {"format", "tar.gz"}};
    }

} // namespace symfind::test_fixtures
