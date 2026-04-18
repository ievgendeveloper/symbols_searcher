cmake_minimum_required(VERSION 3.20)

project(symfind
    VERSION 0.1.0
    DESCRIPTION "Symbol finder engine — locate unexported symbols via heuristic analysis"
    LANGUAGES CXX C
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ─── Options ───────────────────────────────────────────
option(SYMFIND_BUILD_TESTS    "Build unit tests"         ON)
option(SYMFIND_BUILD_EXAMPLES "Build example programs"   ON)

# ─── FetchContent ─────────────────────────────────────
include(FetchContent)

# spdlog — logging
set(SPDLOG_HEADER_ONLY ON CACHE BOOL "" FORCE)
FetchContent_Declare(
    spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG        v1.15.0
    GIT_SHALLOW    TRUE
)

# Zydis — x86/x64 disassembler (brings Zycore as dependency)
FetchContent_Declare(
    zydis
    GIT_REPOSITORY https://github.com/zyantific/zydis.git
    GIT_TAG        v4.1.0
    GIT_SHALLOW    TRUE
)

# LIEF — PE/ELF/Mach-O parser
set(LIEF_DOC       OFF CACHE BOOL "" FORCE)
set(LIEF_EXAMPLES  OFF CACHE BOOL "" FORCE)
set(LIEF_TESTS     OFF CACHE BOOL "" FORCE)
set(LIEF_PYTHON_API OFF CACHE BOOL "" FORCE)
set(LIEF_ELF       OFF CACHE BOOL "" FORCE)
set(LIEF_MACHO     OFF CACHE BOOL "" FORCE)
set(LIEF_OAT       OFF CACHE BOOL "" FORCE)
set(LIEF_DEX       OFF CACHE BOOL "" FORCE)
set(LIEF_VDEX      OFF CACHE BOOL "" FORCE)
set(LIEF_ART       OFF CACHE BOOL "" FORCE)
set(LIEF_EXTERNAL_SPDLOG OFF CACHE BOOL "" FORCE)
set(LIEF_FROZEN_ENABLED OFF CACHE BOOL "" FORCE)
set(LIEF_EXTERNAL_SPAN OFF CACHE BOOL "" FORCE)
set(LIEF_EXTERNAL_EXPECTED OFF CACHE BOOL "" FORCE)
set(LIEF_OPT_UTFCPP_EXTERNAL OFF CACHE BOOL "" FORCE)
# Keep only PE support — we don't need the rest
set(LIEF_PE        ON  CACHE BOOL "" FORCE)

FetchContent_Declare(
    lief
    GIT_REPOSITORY https://github.com/lief-project/LIEF.git
    GIT_TAG        0.17.6
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
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
endif()

# Fetch everything
message(STATUS "Fetching dependencies (first build may take a while)...")
FetchContent_MakeAvailable(spdlog zydis lief)

if(SYMFIND_BUILD_TESTS)
    FetchContent_MakeAvailable(googletest)
    enable_testing()
endif()

# ─── Main library ─────────────────────────────────────
add_subdirectory(src)

# ─── Tests ────────────────────────────────────────────
if(SYMFIND_BUILD_TESTS)
    add_subdirectory(tests)
endif()

# ─── Examples ─────────────────────────────────────────
if(SYMFIND_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()
