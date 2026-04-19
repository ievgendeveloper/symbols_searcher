#include <gtest/gtest.h>

#include "symfind/analysis_db.h"

TEST(FunctionFinder, Search_functions_by_exceptions_parsing_in_ntdll)
{
    auto module = symfind::PeModule::from_file(R"(C:\Windows\System32\ntdll.dll)");
    ASSERT_TRUE(module.has_value());

    std::vector<symfind::Function> functions;
    symfind::FunctionFinder::from_exception_directory(*module, functions);

    EXPECT_GT(functions.size(), 10);
}