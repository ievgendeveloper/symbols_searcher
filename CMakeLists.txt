cmake_minimum_required(VERSION 3.25)

project(symfind
    VERSION 0.1.0
    DESCRIPTION "Symbol finder engine — locate unexported symbols via heuristic analysis"
    LANGUAGES CXX C
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

    # Use asynchronous exception handling instead of CMake's default /EHsc.
    string(REPLACE "/EHsc" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
    string(REPLACE "/EHs" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
    string(REPLACE "/EHsc" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
    string(REPLACE "/EHs" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
    add_compile_options("$<$<COMPILE_LANG_AND_ID:CXX,MSVC>:/EHa>")
    add_compile_options("$<$<COMPILE_LANG_AND_ID:C,MSVC>:/EHa>")
    add_compile_options("$<$<COMPILE_LANG_AND_ID:CXX,MSVC>:/GR->")
    add_compile_options(/utf-8)
    # Store only the PDB basename in the image's debug directory.
    add_link_options("$<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:/PDBALTPATH:%_PDB%>")
endif()

if(WIN32)
    add_compile_definitions(UNICODE _UNICODE)
endif()

# CMake module path
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

# ─── Options ───────────────────────────────────────────
option(SYMFIND_BUILD_TESTS    "Build unit tests"         ON)
option(SYMFIND_BUILD_EXAMPLES "Build example programs"   ON)
option(SYMFIND_BUILD_PDB_TOOLS "Build PDB comparison and fixture utilities" ON)
option(SYMFIND_AUTO_FETCH_NTDLL "Download missing pinned NTDLL test fixtures" ON)
option(SYMFIND_ENABLE_NETWORK_TESTS "Register fresh network corpus verification" OFF)
set(SYMFIND_NTDLL_CORPUS_DIR "${PROJECT_SOURCE_DIR}/pdb_stuff/corpus" CACHE PATH
    "Persistent pinned NTDLL test corpus")

# ─── Code generation (lemon + re2c) ───────────────────
include(CodeGen)

# ─── FetchContent ─────────────────────────────────────
include(FetchContent)

FetchContent_Declare(
    tl_expected
    GIT_REPOSITORY https://github.com/TartanLlama/expected.git
    GIT_TAG v1.3.1
)
set(EXPECTED_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(EXPECTED_BUILD_PACKAGE OFF CACHE BOOL "" FORCE)

# C++17 replacement for the contiguous byte views used by the public API.
FetchContent_Declare(
    span_lite
    GIT_REPOSITORY https://github.com/martinmoene/span-lite.git
    GIT_TAG v0.11.0
    GIT_SHALLOW TRUE
)
set(SPAN_LITE_OPT_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(SPAN_LITE_OPT_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(tl_expected span_lite)

add_library(symfind_compat INTERFACE)
target_compile_features(symfind_compat INTERFACE cxx_std_17)
target_link_libraries(symfind_compat INTERFACE tl::expected nonstd::span-lite)
# Keep the public span type stable even when a consumer enables a newer standard.
target_compile_definitions(symfind_compat INTERFACE span_CONFIG_SELECT_SPAN=1)
target_include_directories(symfind_compat INTERFACE "${PROJECT_SOURCE_DIR}/include")

# spdlog — logging
set(SPDLOG_USE_STD_FORMAT OFF CACHE BOOL "" FORCE)
set(symfindSpdlogVersion "1.17.0")
FetchContent_Declare(
    spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG        v${symfindSpdlogVersion}
    GIT_SHALLOW    TRUE
    OVERRIDE_FIND_PACKAGE
)

# Zydis — x86/x64 disassembler (brings Zycore as dependency)
FetchContent_Declare(
    zydis
    GIT_REPOSITORY https://github.com/zyantific/zydis.git
    GIT_TAG        v4.1.0
    GIT_SHALLOW    TRUE
)

# LIEF — PE/ELF/Mach-O parser
set(LIEF_COMPILE_DOC_EXAMPLES OFF CACHE BOOL "" FORCE)
set(LIEF_EXAMPLES  OFF CACHE BOOL "" FORCE)
set(LIEF_TESTS     OFF CACHE BOOL "" FORCE)
# LIEF is embedded; its standalone exports cannot export our FetchContent targets.
set(LIEF_INSTALL   OFF CACHE BOOL "" FORCE)
set(LIEF_PYTHON_API OFF CACHE BOOL "" FORCE)
set(LIEF_ELF       OFF CACHE BOOL "" FORCE)
set(LIEF_MACHO     OFF CACHE BOOL "" FORCE)
set(LIEF_OAT       OFF CACHE BOOL "" FORCE)
set(LIEF_DEX       OFF CACHE BOOL "" FORCE)
set(LIEF_VDEX      OFF CACHE BOOL "" FORCE)
set(LIEF_ART       OFF CACHE BOOL "" FORCE)
set(LIEF_EXTERNAL_SPDLOG ON CACHE BOOL "" FORCE)
set(LIEF_DISABLE_FROZEN ON CACHE BOOL "" FORCE)
set(LIEF_OPT_EXTERNAL_SPAN OFF CACHE BOOL "" FORCE)
set(LIEF_OPT_EXTERNAL_EXPECTED ON CACHE BOOL "" FORCE)
set(LIEF_OPT_UTFCPP_EXTERNAL OFF CACHE BOOL "" FORCE)
# PE requires the COFF backend; the new Runtime API is not used by symfind.
set(LIEF_PE        ON  CACHE BOOL "" FORCE)
set(LIEF_COFF      ON  CACHE BOOL "" FORCE)
set(LIEF_RUNTIME   OFF CACHE BOOL "" FORCE)
if(MSVC)
    # LIEF otherwise appends /EHsc-, overriding the project's /EHa.
    set(LIEF_DISABLE_EXCEPTIONS OFF CACHE BOOL "" FORCE)
endif()

set(symfindLiefVersion "1.0.0")
FetchContent_Declare(
    lief
    GIT_REPOSITORY https://github.com/lief-project/LIEF.git
    GIT_TAG        ${symfindLiefVersion}
    GIT_SHALLOW    TRUE
)

# Google Test
if(SYMFIND_BUILD_TESTS)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG        v1.15.2
        GIT_SHALLOW    TRUE
    )
    set(gtest_force_shared_crt OFF CACHE BOOL "" FORCE)
endif()

# Fetch everything
message(STATUS "Fetching dependencies (first build may take a while)...")
FetchContent_MakeAvailable(spdlog zydis)
get_directory_property(actualSpdlogVersion DIRECTORY "${spdlog_SOURCE_DIR}"
    DEFINITION spdlog_VERSION)
if(NOT "${actualSpdlogVersion}" VERSION_EQUAL "${symfindSpdlogVersion}")
    message(FATAL_ERROR
        "Expected spdlog ${symfindSpdlogVersion}, got ${actualSpdlogVersion}. "
        "Clear or update FETCHCONTENT_SOURCE_DIR_SPDLOG and the dependency cache.")
endif()
# LIEF's external logger uses the same version and compiled target as symfind.
set(SPDLOG_DIR "${spdlog_SOURCE_DIR}")
FetchContent_MakeAvailable(lief)

# A source override or disconnected cache must not silently retain an old LIEF.
get_directory_property(actualLiefVersion DIRECTORY "${lief_SOURCE_DIR}"
    DEFINITION LIEF_VERSION)
if(NOT "${actualLiefVersion}" VERSION_EQUAL "${symfindLiefVersion}")
    message(FATAL_ERROR
        "Expected LIEF ${symfindLiefVersion}, got ${actualLiefVersion}. "
        "Clear or update FETCHCONTENT_SOURCE_DIR_LIEF and the dependency cache.")
endif()

if(SYMFIND_BUILD_TESTS)
    FetchContent_MakeAvailable(googletest)
    if(MSVC)
        foreach(testTarget IN ITEMS gtest gtest_main gmock gmock_main)
            if(TARGET ${testTarget})
                get_target_property(compileFlags ${testTarget} COMPILE_FLAGS)
                if(compileFlags)
                    string(REPLACE "-EHsc" "" compileFlags "${compileFlags}")
                    string(REPLACE "/EHsc" "" compileFlags "${compileFlags}")
                    set_target_properties(${testTarget} PROPERTIES COMPILE_FLAGS "${compileFlags}")
                endif()
            endif()
        endforeach()
    endif()
    enable_testing()
endif()

# ─── Main library ─────────────────────────────────────
add_subdirectory(src)

# Persistent PDB data lives in pdb_stuff; only generated build files live in build.
if(WIN32 AND (SYMFIND_BUILD_PDB_TOOLS OR SYMFIND_BUILD_TESTS))
    add_subdirectory(pdb_stuff)
endif()

# ─── Tests ────────────────────────────────────────────
if(SYMFIND_BUILD_TESTS)
    add_subdirectory(tests)
endif()

# ─── Examples ─────────────────────────────────────────
if(SYMFIND_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()
