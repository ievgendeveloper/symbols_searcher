#include "symfind/compat.h"

#include <gtest/gtest.h>
#include <nonstd/span.hpp>
#include <tl/expected.hpp>

#include <array>
#include <string>
#include <string_view>

TEST(Cpp17Compatibility, PrefixAndSuffixKeepStringViewSemantics)
{
    using namespace std::string_view_literals;
    EXPECT_TRUE(symfind::StartsWith("", ""));
    EXPECT_TRUE(symfind::EndsWith("", ""));
    EXPECT_TRUE(symfind::StartsWith("https://example", "https://"));
    EXPECT_FALSE(symfind::StartsWith("https:", "https://"));
    EXPECT_TRUE(symfind::EndsWith("ntdll.dll", ".dll"));
    EXPECT_FALSE(symfind::EndsWith("dll", ".dll"));
    EXPECT_FALSE(symfind::StartsWith("NTDLL", "ntdll"));
    EXPECT_FALSE(symfind::EndsWith("NTDLL.DLL", ".dll"));
    EXPECT_TRUE(symfind::StartsWith("a\0b"sv, "a\0"sv));
    EXPECT_TRUE(symfind::EndsWith("a\0b"sv, "\0b"sv));
}

TEST(Cpp17Compatibility, SpanSubviewsShareStorageAndSupportConstConversion)
{
    std::array<unsigned char, 4> storageBytes{1, 2, 3, 4};
    nonstd::span<unsigned char> mutableByteView(storageBytes);
    auto middleByteView = mutableByteView.subspan(1, 2);
    middleByteView[0] = 9;
    const nonstd::span<const unsigned char> constantByteView = mutableByteView;
    EXPECT_EQ(storageBytes[1], 9);
    EXPECT_EQ(constantByteView.data(), storageBytes.data());
    EXPECT_EQ(constantByteView.first(2).back(), 9);
    EXPECT_EQ(constantByteView.last(1).front(), 4);
    EXPECT_TRUE(constantByteView.subspan(constantByteView.size()).empty());
    EXPECT_TRUE(nonstd::span<const unsigned char>{}.empty());
}

TEST(Cpp17Compatibility, ExpectedDependencyPropagatesThroughThePublicTarget)
{
    tl::expected<int, std::string> expectedSymbolValue = 42;
    ASSERT_TRUE(expectedSymbolValue.has_value());
    EXPECT_EQ(expectedSymbolValue.value(), 42);
    expectedSymbolValue = tl::make_unexpected(std::string("missing symbol"));
    ASSERT_FALSE(expectedSymbolValue.has_value());
    EXPECT_EQ(expectedSymbolValue.error(), "missing symbol");
    EXPECT_EQ(expectedSymbolValue.value_or(7), 7);
}
