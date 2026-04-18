add_library(symfind STATIC
    # PE module loading & analysis
    pe_module.cpp

    # Disassembly & function discovery
    disassembler.cpp
    function_finder.cpp

    # Analysis database — stores functions, xrefs, globals
    analysis_db.cpp

    # DSL parser & matcher
    dsl_lexer.cpp
    dsl_parser.cpp
    dsl_matcher.cpp
)

target_include_directories(symfind
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(symfind
    PUBLIC
        Zydis
        LIEF::LIEF
    PRIVATE
        spdlog::spdlog_header_only
)

target_compile_features(symfind PUBLIC cxx_std_20)

# Stricter warnings
if(MSVC)
    target_compile_options(symfind PRIVATE /W4)
else()
    target_compile_options(symfind PRIVATE -Wall -Wextra -Wpedantic)
endif()
