#include "pdb_stuff/io.h"

#include <cpr/cpr.h>
#include <zlib.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <exception>
#include <fstream>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>

namespace pdb_stuff
{
    namespace
    {
        constexpr std::size_t download_limit = 256 * 1024 * 1024;
        constexpr std::string_view symbol_prefix = "https://msdl.microsoft.com/download/symbols/";
        constexpr std::string_view winbindex = "https://winbindex.m417z.com/data/by_filename_compressed/ntdll.dll.json.gz";
        constexpr std::string_view mcr_prefix = "https://mcr.microsoft.com/v2/windows/nanoserver/blobs/sha256:";

        bool lower_hex_sha256(std::string_view text)
        {
            return text.size() == 64 && std::all_of(text.begin(), text.end(), [](char character)
                                                    { return (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f'); });
        }

        std::string_view host_of(std::string_view url)
        {
            if (!url.starts_with("https://"))
                return {};
            url.remove_prefix(8);
            return url.substr(0, url.find('/'));
        }

        bool symbol_blob_host(std::string_view host)
        {
            if (host == "symbolfiles.blob.core.windows.net")
                return true;
            // Microsoft's symbol server also redirects to sharded production
            // Azure accounts. Admit this account family only for a redirect
            // originating at the explicitly allowed Microsoft symbol server.
            constexpr std::string_view prefix = "vsblobprod";
            constexpr std::string_view suffix = ".blob.core.windows.net";
            if (!host.starts_with(prefix) || !host.ends_with(suffix) ||
                host.size() <= prefix.size() + suffix.size())
                return false;
            const auto shard = host.substr(prefix.size(), host.size() - prefix.size() - suffix.size());
            return std::all_of(shard.begin(), shard.end(), [](char character)
                               { return (character >= 'a' && character <= 'z') ||
                                        (character >= '0' && character <= '9'); });
        }

        bool allowed_redirect(std::string_view original, std::string_view redirected)
        {
            if (!redirected.starts_with("https://") ||
                redirected.find_first_of("\r\n\\") != std::string_view::npos ||
                std::any_of(redirected.begin(), redirected.end(), [](unsigned char value)
                            { return value <= 0x20; }))
                return false;
            if (is_supported_download_url(redirected))
                return true;
            const auto host = host_of(redirected);
            if (original.starts_with(symbol_prefix))
                return symbol_blob_host(host);
            if (original.starts_with(mcr_prefix))
                return host.ends_with(".data.mcr.microsoft.com") || host == "mcr.microsoft.com";
            return false;
        }

        bool safe_member(std::string_view path)
        {
            if (path.empty() || path.front() == '/' || path.back() == '/' ||
                path.find_first_of("\\:") != std::string_view::npos ||
                path.find('\0') != std::string_view::npos)
                return false;
            while (!path.empty())
            {
                const auto separator = path.find('/');
                const auto component = path.substr(0, separator);
                if (component.empty() || component == "." || component == "..")
                    return false;
                if (separator == std::string_view::npos)
                    break;
                path.remove_prefix(separator + 1);
            }
            return true;
        }

        // Incremental inflater for archives: a 150 MiB compressed layer can
        // expand to almost a GiB, so never materialize its complete tar stream.
        class GzipReader
        {
            public:
                explicit GzipReader(const std::filesystem::path& path, std::size_t limit)
                    : input_(path, std::ios::binary), limit_(limit)
                {
                    if (!input_)
                        throw FixtureError("cannot open tar.gz fixture archive");
                    if (inflateInit2(&stream_, MAX_WBITS + 16) != Z_OK)
                        throw FixtureError("could not initialize gzip reader");
                }
                ~GzipReader() { inflateEnd(&stream_); }
                GzipReader(const GzipReader&) = delete;
                GzipReader& operator=(const GzipReader&) = delete;

                std::size_t read(std::span<uint8_t> destination)
                {
                    std::size_t done = 0;
                    while (done < destination.size() && !finished_)
                    {
                        if (stream_.avail_in == 0)
                        {
                            input_.read(reinterpret_cast<char*>(compressed_.data()), compressed_.size());
                            const auto count = input_.gcount();
                            if (count <= 0)
                                throw FixtureError("invalid or truncated tar.gz fixture archive");
                            stream_.next_in = compressed_.data();
                            stream_.avail_in = static_cast<uInt>(count);
                        }
                        const auto size = static_cast<uInt>(std::min<std::size_t>(
                            destination.size() - done, std::numeric_limits<uInt>::max()));
                        stream_.next_out = destination.data() + done;
                        stream_.avail_out = size;
                        const auto before_input = stream_.avail_in;
                        const auto result = inflate(&stream_, Z_NO_FLUSH);
                        const std::size_t produced = size - stream_.avail_out;
                        if (produced > limit_ - scanned_)
                            throw FixtureError("archive exceeds the uncompressed scan limit");
                        scanned_ += produced;
                        done += produced;
                        if (result == Z_STREAM_END)
                            finished_ = true;
                        else if (result != Z_OK || (produced == 0 && before_input == stream_.avail_in))
                            throw FixtureError("invalid tar.gz fixture archive");
                    }
                    return done;
                }

                void exact(std::span<uint8_t> destination)
                {
                    if (read(destination) != destination.size())
                        throw FixtureError("archive member or header is truncated");
                }

                void skip(uint64_t size)
                {
                    if (size > limit_ - scanned_)
                        throw FixtureError("archive exceeds the uncompressed scan limit");
                    std::array<uint8_t, 64 * 1024> buffer{};
                    while (size != 0)
                    {
                        const auto chunk = static_cast<std::size_t>(std::min<uint64_t>(size, buffer.size()));
                        exact(std::span(buffer).first(chunk));
                        size -= chunk;
                    }
                }

                void finish()
                {
                    // The selected file can appear near the start of a layer. Read
                    // through the gzip footer so a truncated or corrupt remainder
                    // cannot be accepted simply because that file was intact.
                    std::array<uint8_t, 64 * 1024> buffer{};
                    while (read(buffer) != 0)
                    {
                    }
                    if (stream_.avail_in != 0 || input_.peek() != std::char_traits<char>::eof())
                        throw FixtureError("tar.gz fixture archive has unsupported trailing data");
                    if (input_.bad())
                        throw FixtureError("could not read tar.gz fixture archive");
                }

            private:
                std::ifstream input_;
                z_stream stream_{};
                std::array<uint8_t, 64 * 1024> compressed_{};
                std::size_t limit_;
                std::size_t scanned_ = 0;
                bool finished_ = false;
        };

        std::string tar_text(std::span<const uint8_t> field)
        {
            const auto end = std::find(field.begin(), field.end(), uint8_t{0});
            return std::string(field.begin(), end);
        }

        uint64_t tar_number(std::span<const uint8_t> field)
        {
            // GNU base-256 is used by large Windows container layer members.
            if (field.front() & 0x80)
            {
                if (field.front() & 0x40)
                    throw FixtureError("archive member has a negative size");
                uint64_t result = field.front() & 0x3f;
                for (const auto byte : field.subspan(1))
                {
                    if (result > (std::numeric_limits<uint64_t>::max() - byte) / 256)
                        throw FixtureError("archive numeric field exceeds supported range");
                    result = result * 256 + byte;
                }
                return result;
            }
            uint64_t result = 0;
            bool started = false;
            bool terminated = false;
            for (const auto character : field)
            {
                if (character == 0 || character == ' ')
                {
                    if (started || character == 0)
                        terminated = true;
                    continue;
                }
                if (terminated || character < '0' || character > '7')
                    throw FixtureError("invalid tar numeric field");
                if (result > (std::numeric_limits<uint64_t>::max() - (character - '0')) / 8)
                    throw FixtureError("archive numeric field exceeds supported range");
                started = true;
                result = result * 8 + character - '0';
            }
            return result;
        }

        std::pair<std::string, uint64_t> parse_tar_header(std::span<const uint8_t, 512> header)
        {
            const auto expected = tar_number(header.subspan(148, 8));
            uint64_t checksum = 0;
            for (std::size_t i = 0; i < header.size(); ++i)
                checksum += i >= 148 && i < 156 ? uint8_t{' '} : header[i];
            if (expected != checksum)
                throw FixtureError("invalid tar header checksum");
            auto name = tar_text(header.first(100));
            const auto magic = tar_text(header.subspan(257, 6));
            // Prefix belongs only to POSIX ustar, not GNU headers (whose
            // overlapping area stores other metadata).
            if (magic == "ustar")
            {
                const auto prefix = tar_text(header.subspan(345, 155));
                if (!prefix.empty())
                    name = prefix + '/' + name;
            }
            return {std::move(name), tar_number(header.subspan(124, 12))};
        }
    } // namespace

    bool is_supported_download_url(std::string_view url)
    {
        if (url.find_first_of("\r\n\\?#") != std::string_view::npos ||
            std::any_of(url.begin(), url.end(), [](unsigned char value)
                        { return value <= 0x20; }))
            return false;
        if (url == winbindex)
            return true;
        if (url.starts_with(mcr_prefix))
            return lower_hex_sha256(url.substr(mcr_prefix.size()));
        if (url.starts_with(symbol_prefix))
        {
            const auto path = url.substr(symbol_prefix.size());
            return !path.empty() && path.find("..") == std::string_view::npos &&
                   path.find('@') == std::string_view::npos;
        }
        return false;
    }

    Bytes download(std::string_view url, bool allow_network)
    {
        // Refuse before creating a CPR Session: offline tests perform no socket
        // initialization or proxy discovery at all.
        if (!allow_network)
            throw NetworkDisabled("network disabled; rerun with --allow-network to download missing files");
        if (!is_supported_download_url(url))
            throw FixtureError("unsupported download URL");
        const std::string original(url);
        std::string current = original;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
        for (unsigned redirect_count = 0; redirect_count <= 5; ++redirect_count)
        {
            cpr::Session session;
            session.SetUrl(cpr::Url{current});
            session.SetRedirect(cpr::Redirect{false});
            session.SetUserAgent(cpr::UserAgent{"symfind-fixtures/1.0"});
            session.SetVerifySsl(cpr::VerifySsl{true});
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                                       deadline - std::chrono::steady_clock::now())
                                       .count();
            if (remaining <= 0)
                throw std::runtime_error("fixture download timed out");
            session.SetTimeout(cpr::Timeout{static_cast<std::int32_t>(remaining)});
            session.SetConnectTimeout(cpr::ConnectTimeout{15000});
            Bytes result;
            bool exceeded = false;
            std::exception_ptr callback_error;
            auto response = session.Download(cpr::WriteCallback{[&](const auto& chunk, intptr_t)
                                                                {
                                                                    try
                                                                    {
                                                                        if (chunk.size() > download_limit - result.size())
                                                                        {
                                                                            exceeded = true;
                                                                            return false;
                                                                        }
                                                                        result.insert(result.end(), chunk.begin(), chunk.end());
                                                                        return true;
                                                                    }
                                                                    catch (...)
                                                                    {
                                                                        callback_error = std::current_exception();
                                                                        return false;
                                                                    }
                                                                }});
            if (callback_error)
                std::rethrow_exception(callback_error);
            if (exceeded)
                throw FixtureError("download exceeds the 256 MiB fixture limit");
            if (response.error.code != cpr::ErrorCode::OK)
                throw std::runtime_error("fixture HTTP request failed: " + response.error.message);
            if (response.status_code >= 200 && response.status_code < 300)
                return result;
            if (response.status_code == 301 || response.status_code == 302 || response.status_code == 303 ||
                response.status_code == 307 || response.status_code == 308)
            {
                const auto found = response.header.find("location");
                if (found == response.header.end() || found->second.empty() || redirect_count == 5)
                    throw FixtureError("fixture HTTP redirect is missing or exceeds the limit");
                std::string next = found->second;
                if (next.starts_with('/') && !next.starts_with("//"))
                    next = "https://" + std::string(host_of(current)) + next;
                if (!allowed_redirect(original, next))
                    throw FixtureError("unsupported fixture HTTP redirect");
                current = std::move(next);
                continue;
            }
            throw std::runtime_error("fixture HTTP status " + std::to_string(response.status_code));
        }
        throw FixtureError("fixture HTTP redirect limit exceeded");
    }

    Bytes gzip_decompress(const Bytes& data)
    {
        if (data.empty() || data.size() > download_limit)
            throw FixtureError("invalid or oversized gzip data");
        z_stream stream{};
        if (inflateInit2(&stream, MAX_WBITS + 16) != Z_OK)
            throw FixtureError("could not initialize gzip reader");
        struct Cleanup
        {
                z_stream& stream;
                ~Cleanup() { inflateEnd(&stream); }
        } cleanup{stream};
        stream.next_in = const_cast<uint8_t*>(data.data());
        stream.avail_in = static_cast<uInt>(data.size());
        Bytes result;
        std::array<uint8_t, 64 * 1024> buffer{};
        while (true)
        {
            stream.next_out = buffer.data();
            stream.avail_out = buffer.size();
            const auto code = inflate(&stream, Z_NO_FLUSH);
            const auto produced = buffer.size() - stream.avail_out;
            if (produced > download_limit - result.size())
                throw FixtureError("gzip expansion exceeds the 256 MiB limit");
            result.insert(result.end(), buffer.begin(), buffer.begin() + produced);
            if (code == Z_STREAM_END)
            {
                if (stream.avail_in != 0)
                    throw FixtureError("gzip data has unsupported trailing members");
                return result;
            }
            if (code != Z_OK || (produced == 0 && stream.avail_in == 0))
                throw FixtureError("invalid or truncated gzip data");
        }
    }

    Bytes read_archive_member(const std::filesystem::path& archive, std::string_view exact_member,
                              std::size_t max_payload, std::size_t max_scan)
    {
        if (!safe_member(exact_member))
            throw FixtureError("unsafe archive member path");
        GzipReader reader(archive, max_scan);
        std::array<uint8_t, 512> header{};
        std::string next_name;
        while (true)
        {
            const auto read = reader.read(header);
            if (read == 0)
                break;
            if (read != header.size())
                throw FixtureError("archive header is truncated");
            if (std::all_of(header.begin(), header.end(), [](uint8_t byte)
                            { return byte == 0; }))
                break;
            auto [name, size] = parse_tar_header(header);
            const auto type = header[156];
            const auto padding = (512 - size % 512) % 512;
            // GNU long-name and POSIX PAX headers are metadata, never selected
            // as executable-file payloads. Only their exact path is consumed.
            if (type == 'L' || type == 'x' || type == 'g')
            {
                if (size > 1024 * 1024)
                    throw FixtureError("archive extended header exceeds the size limit");
                Bytes metadata(static_cast<std::size_t>(size));
                reader.exact(metadata);
                reader.skip(padding);
                if (type == 'L')
                    next_name = tar_text(metadata);
                else
                {
                    std::size_t position = 0;
                    while (position < metadata.size())
                    {
                        const auto text = std::string_view(reinterpret_cast<const char*>(metadata.data() + position), metadata.size() - position);
                        const auto separator = text.find(' ');
                        if (separator == std::string_view::npos)
                            throw FixtureError("invalid PAX record");
                        uint64_t length = 0;
                        const auto parsed = std::from_chars(text.data(), text.data() + separator, length);
                        if (parsed.ec != std::errc{} || parsed.ptr != text.data() + separator ||
                            length <= separator + 1 || length > text.size() || text[length - 1] != '\n')
                            throw FixtureError("invalid PAX record length");
                        const auto value = text.substr(separator + 1, static_cast<std::size_t>(length) - separator - 2);
                        if (value.starts_with("path="))
                            next_name = value.substr(5);
                        else if (value.starts_with("size="))
                            throw FixtureError("PAX size overrides are unsupported");
                        else if (value.starts_with("GNU.sparse."))
                            throw FixtureError("sparse archive members are unsupported");
                        position += static_cast<std::size_t>(length);
                    }
                }
                continue;
            }
            if (!next_name.empty())
            {
                name = std::move(next_name);
                next_name.clear();
            }
            if (name == exact_member)
            {
                if ((type != 0 && type != '0') || size == 0 || size > max_payload)
                    throw FixtureError("archive DLL member must be a regular file within the payload limit");
                Bytes payload(static_cast<std::size_t>(size));
                reader.exact(payload);
                reader.finish();
                return payload;
            }
            if (size > std::numeric_limits<uint64_t>::max() - padding)
                throw FixtureError("archive member size overflows the supported range");
            reader.skip(size + padding);
        }
        throw FixtureError("archive has no exact DLL member " + std::string(exact_member));
    }
} // namespace pdb_stuff
