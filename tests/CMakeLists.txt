add_executable(symfind_tests
    test_dsl_lexer.cpp
    test_dsl_parser.cpp
    test_dsl_matcher.cpp
)

target_link_libraries(symfind_tests
    PRIVATE
        symfind
        GTest::gtest_main
        spdlog::spdlog_header_only
)

include(GoogleTest)
gtest_discover_tests(symfind_tests)
