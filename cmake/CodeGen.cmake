# cmake/CodeGen.cmake
#
# Sets up code generation for the DSL:
#   1. Compiles `lemon` from tools/lemon/lemon.c (one-time)
#   2. Defines SymfindGenerateGrammar() — runs lemon on a .y file
#   3. Defines SymfindGenerateLexer()   — runs re2c on a .re file

# ─── Build the lemon executable ─────────────────────

set(lemonSourceDirectory "${CMAKE_SOURCE_DIR}/tools/lemon")
set(lemonSource "${lemonSourceDirectory}/lemon.c")
set(lemonParserTemplate "${lemonSourceDirectory}/lempar.c")

if(NOT EXISTS "${lemonSource}")
    message(FATAL_ERROR
        "Missing ${lemonSource}.\n"
        "Download it from https://github.com/sqlite/sqlite/blob/master/tool/lemon.c\n"
        "and place it in tools/lemon/")
endif()

if(NOT EXISTS "${lemonParserTemplate}")
    message(FATAL_ERROR
        "Missing ${lemonParserTemplate}.\n"
        "Download it from https://github.com/sqlite/sqlite/blob/master/tool/lempar.c\n"
        "and place it in tools/lemon/")
endif()

add_executable(lemon "${lemonSource}")
set_target_properties(lemon PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tools"
    C_STANDARD 99
)
if(MSVC)
    target_compile_definitions(lemon PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_options(lemon PRIVATE /W0)
else()
    target_compile_options(lemon PRIVATE -w)
endif()

# ─── Find re2c ──────────────────────────────────────

find_program(RE2C_EXECUTABLE re2c REQUIRED
    DOC "Path to the re2c lexer generator")

message(STATUS "Found re2c: ${RE2C_EXECUTABLE}")

# ─── Helper: generate a parser from a .y file ───────

function(SymfindGenerateGrammar)
    set(options "")
    set(oneValueArgs INPUT OUTPUT_DIR)
    set(multiValueArgs "")
    cmake_parse_arguments(ARG "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if(NOT ARG_INPUT OR NOT ARG_OUTPUT_DIR)
        message(FATAL_ERROR "SymfindGenerateGrammar: INPUT and OUTPUT_DIR required")
    endif()

    file(MAKE_DIRECTORY "${ARG_OUTPUT_DIR}")

    get_filename_component(grammarName "${ARG_INPUT}" NAME_WE)
    set(parserSource "${ARG_OUTPUT_DIR}/${grammarName}.c")
    set(parserHeader "${ARG_OUTPUT_DIR}/${grammarName}.h")
    set(stagedGrammar "${ARG_OUTPUT_DIR}/${grammarName}.y")

    add_custom_command(
        OUTPUT "${parserSource}" "${parserHeader}"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${ARG_INPUT}" "${stagedGrammar}"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${lemonParserTemplate}" "${ARG_OUTPUT_DIR}/lempar.c"
        COMMAND $<TARGET_FILE:lemon>
                -T${ARG_OUTPUT_DIR}/lempar.c
                "${stagedGrammar}"
        DEPENDS "${ARG_INPUT}" lemon "${lemonParserTemplate}"
        WORKING_DIRECTORY "${ARG_OUTPUT_DIR}"
        COMMENT "Generating parser from ${grammarName}.y"
        VERBATIM
    )

    set(parserSource "${parserSource}" PARENT_SCOPE)
    set(parserHeader "${parserHeader}" PARENT_SCOPE)
endfunction()

# ─── Helper: generate a lexer from a .re file ───────

function(SymfindGenerateLexer)
    set(options "")
    set(oneValueArgs INPUT OUTPUT)
    set(multiValueArgs "")
    cmake_parse_arguments(ARG "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if(NOT ARG_INPUT OR NOT ARG_OUTPUT)
        message(FATAL_ERROR "SymfindGenerateLexer: INPUT and OUTPUT required")
    endif()

    add_custom_command(
        OUTPUT "${ARG_OUTPUT}"
        COMMAND ${RE2C_EXECUTABLE}
                --no-debug-info
                -W
                -o "${ARG_OUTPUT}"
                "${ARG_INPUT}"
        DEPENDS "${ARG_INPUT}"
        COMMENT "Generating lexer from ${ARG_INPUT}"
        VERBATIM
    )
endfunction()
