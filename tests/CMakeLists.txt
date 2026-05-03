add_executable(symfind_tests
    test_dsl_lexer.cpp
    test_dsl_parser.cpp
    test_dsl_matcher.cpp
    test_function_finder.cpp
    test_disassembler.cpp
    test_pe_module.cpp
    test_globals.cpp
    test_stack_frame.cpp
    test_loop_checker.cpp
)

target_link_libraries(symfind_tests        
    PRIVATE
        spdlog::spdlog_header_only
        Zydis
        LIEF::LIEF            
        symfind
        GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(symfind_tests)
