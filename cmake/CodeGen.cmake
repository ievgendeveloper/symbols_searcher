# cmake/CodeGen.cmake
#
# Sets up code generation for the DSL:
#   1. Compiles `lemon` from tools/lemon/lemon.c (one-time)
#   2. Defines symfind_generate_grammar() — runs lemon on a .y file
#   3. Defines symfind_generate_lexer()   — runs re2c on a .re file

# ─── Build the lemon executable ─────────────────────

set(LEMON_SOURCE_DIR "${CMAKE_SOURCE_DIR}/tools/lemon")
set(LEMON_C          "${LEMON_SOURCE_DIR}/lemon.c")
set(LEMPAR_C         "${LEMON_SOURCE_DIR}/lempar.c")

if(NOT EXISTS "${LEMON_C}")
    message(FATAL_ERROR
        "Missing ${LEMON_C}.\n"
        "Download it from https://github.com/sqlite/sqlite/blob/master/tool/lemon.c\n"
        "and place it in tools/lemon/")
endif()

if(NOT EXISTS "${LEMPAR_C}")
    message(FATAL_ERROR
        "Missing ${LEMPAR_C}.\n"
        "Download it from https://github.com/sqlite/sqlite/blob/master/tool/lempar.c\n"
        "and place it in tools/lemon/")
endif()

add_executable(lemon "${LEMON_C}")
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

function(symfind_generate_grammar)
    set(options "")
    set(oneValueArgs INPUT OUTPUT_DIR)
    set(multiValueArgs "")
    cmake_parse_arguments(ARG "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if(NOT ARG_INPUT OR NOT ARG_OUTPUT_DIR)
        message(FATAL_ERROR "symfind_generate_grammar: INPUT and OUTPUT_DIR required")
    endif()

    file(MAKE_DIRECTORY "${ARG_OUTPUT_DIR}")

    get_filename_component(input_name "${ARG_INPUT}" NAME_WE)
    set(out_c    "${ARG_OUTPUT_DIR}/${input_name}.c")
    set(out_h    "${ARG_OUTPUT_DIR}/${input_name}.h")
    set(staged_y "${ARG_OUTPUT_DIR}/${input_name}.y")

    add_custom_command(
        OUTPUT "${out_c}" "${out_h}"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${ARG_INPUT}" "${staged_y}"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${LEMPAR_C}" "${ARG_OUTPUT_DIR}/lempar.c"
        COMMAND $<TARGET_FILE:lemon>
                -T${ARG_OUTPUT_DIR}/lempar.c
                "${staged_y}"
        DEPENDS "${ARG_INPUT}" lemon "${LEMPAR_C}"
        WORKING_DIRECTORY "${ARG_OUTPUT_DIR}"
        COMMENT "Generating parser from ${input_name}.y"
        VERBATIM
    )

    set(SYMFIND_GRAMMAR_C "${out_c}" PARENT_SCOPE)
    set(SYMFIND_GRAMMAR_H "${out_h}" PARENT_SCOPE)
endfunction()

# ─── Helper: generate a lexer from a .re file ───────

function(symfind_generate_lexer)
    set(options "")
    set(oneValueArgs INPUT OUTPUT)
    set(multiValueArgs "")
    cmake_parse_arguments(ARG "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if(NOT ARG_INPUT OR NOT ARG_OUTPUT)
        message(FATAL_ERROR "symfind_generate_lexer: INPUT and OUTPUT required")
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
