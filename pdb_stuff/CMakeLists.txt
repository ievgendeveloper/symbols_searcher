# Tool dependencies are isolated from symfind's production library.
include(FetchContent)

function(symfind_fetch_pdb_dependencies)
    set(BUILD_SHARED_LIBS OFF)
    # zlib 1.3.1's upstream minimum predates CMake 4 compatibility defaults.
    set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
    set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
    set(JSON_Install OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(nlohmann_json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG v3.11.3
        GIT_SHALLOW TRUE)
    set(ZLIB_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(SKIP_INSTALL_ALL ON)
    FetchContent_Declare(zlib
        GIT_REPOSITORY https://github.com/madler/zlib.git
        GIT_TAG v1.3.1
        GIT_SHALLOW TRUE)

    set(CPR_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(CPR_BUILD_TESTS_SSL OFF CACHE BOOL "" FORCE)
    set(CPR_BUILD_TESTS_PROXY OFF CACHE BOOL "" FORCE)
    set(CPR_USE_SYSTEM_CURL OFF CACHE BOOL "" FORCE)
    set(CPR_ENABLE_SSL ON CACHE BOOL "" FORCE)
    set(CPR_FORCE_WINSSL_BACKEND ON CACHE BOOL "" FORCE)
    set(CPR_ENABLE_CURL_HTTP_ONLY ON CACHE BOOL "" FORCE)
    set(CURL_ZLIB OFF CACHE STRING "" FORCE)
    set(CURL_USE_LIBPSL OFF CACHE BOOL "" FORCE)
    set(CURL_BROTLI OFF CACHE STRING "" FORCE)
    set(CURL_ZSTD OFF CACHE STRING "" FORCE)
    set(BUILD_CURL_EXE OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(cpr
        GIT_REPOSITORY https://github.com/libcpr/cpr.git
        GIT_TAG 1.11.2
        GIT_SHALLOW TRUE)
    FetchContent_MakeAvailable(nlohmann_json zlib cpr)

    # CPR defaults static MSVC libraries to /MT; symfind and GoogleTest use /MD.
    foreach(dependency cpr libcurl libcurl_static CURL::libcurl)
        if(TARGET ${dependency})
            get_target_property(actual_target ${dependency} ALIASED_TARGET)
            if(NOT actual_target)
                set(actual_target ${dependency})
            endif()
            set_property(TARGET ${actual_target} PROPERTY MSVC_RUNTIME_LIBRARY
                "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
        endif()
    endforeach()
endfunction()
symfind_fetch_pdb_dependencies()

add_library(symfind_pdb_fixtures STATIC
    src/corpus.cpp
    src/fixtures.cpp
    src/io.cpp
    src/diagnostics.cpp)
target_include_directories(symfind_pdb_fixtures PUBLIC include)
target_link_libraries(symfind_pdb_fixtures
    PUBLIC nlohmann_json::nlohmann_json
    PRIVATE cpr::cpr zlibstatic bcrypt)
target_compile_definitions(symfind_pdb_fixtures PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)

add_library(symfind_pdb_validation STATIC ../tests/pdb_symbols.cpp)
target_include_directories(symfind_pdb_validation PUBLIC ${PROJECT_SOURCE_DIR}/tests)
target_link_libraries(symfind_pdb_validation PUBLIC symfind dbghelp)

add_executable(symfind_corpus_manager src/corpus_main.cpp)
target_link_libraries(symfind_corpus_manager PRIVATE symfind_pdb_fixtures)
target_compile_definitions(symfind_corpus_manager PRIVATE
    SYMFIND_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
set_target_properties(symfind_corpus_manager PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/$<CONFIG>")

if(SYMFIND_BUILD_PDB_TOOLS)
    add_executable(symfind_fetch_ntdll src/fetch_main.cpp)
    target_link_libraries(symfind_fetch_ntdll PRIVATE symfind_pdb_fixtures)
    target_compile_definitions(symfind_fetch_ntdll PRIVATE
        SYMFIND_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
    add_executable(symfind_pdb_util src/util_main.cpp)
    target_link_libraries(symfind_pdb_util PRIVATE symfind_pdb_fixtures)
    add_executable(symfind_compare_symbols ../tools/compare_symbols.cpp)
    target_link_libraries(symfind_compare_symbols
        PRIVATE symfind_pdb_validation spdlog::spdlog_header_only)
    foreach(tool symfind_fetch_ntdll symfind_pdb_util symfind_compare_symbols)
        set_target_properties(${tool} PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/$<CONFIG>")
    endforeach()
endif()
