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
    test_chained_unwind.cpp
    test_cpp17_compat.cpp
)

target_link_libraries(symfind_tests        
    PRIVATE
        spdlog::spdlog
        Zydis
        LIEF::LIEF            
        symfind
        GTest::gtest_main
)

if(WIN32)
    # PDBs are an independent test oracle; the production library remains PDB-free.
    target_sources(symfind_tests PRIVATE test_pdb_comparison.cpp)
    target_link_libraries(symfind_tests PRIVATE symfind_pdb_validation)
    target_sources(symfind_tests PRIVATE test_fetch_ntdll.cpp test_delta_diagnostics.cpp test_corpus_lifecycle.cpp)
    target_link_libraries(symfind_tests PRIVATE symfind_pdb_fixtures)
    add_dependencies(symfind_tests symfind_corpus_manager)
endif()

include(GoogleTest)
gtest_discover_tests(symfind_tests TEST_LIST symfindTests)

if(WIN32)
    set(corpusManifest "${PROJECT_SOURCE_DIR}/pdb_stuff/ntdll_fixtures.json")
    set(corpusNetworkArgument)
    if(SYMFIND_AUTO_FETCH_NTDLL)
        set(corpusNetworkArgument --allow-network)
    endif()
    add_test(NAME NtdllCorpus.Prepare COMMAND symfind_corpus_manager --prepare-tests
        --manifest "${corpusManifest}" --corpus "${SYMFIND_NTDLL_CORPUS_DIR}"
        ${corpusNetworkArgument})
    set_tests_properties(NtdllCorpus.Prepare PROPERTIES
        FIXTURES_SETUP ntdll_corpus LABELS corpus TIMEOUT 1800)

    # This include follows GoogleTest discovery and only marks the integration
    # test as requiring the corpus; selecting a unit test stays offline.
    configure_file("${PROJECT_SOURCE_DIR}/cmake/CorpusTests.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/CorpusTests.cmake" @ONLY)
    set_property(DIRECTORY APPEND PROPERTY TEST_INCLUDE_FILES
        "${CMAKE_CURRENT_BINARY_DIR}/CorpusTests.cmake")

    if(SYMFIND_ENABLE_NETWORK_TESTS)
        add_test(NAME NtdllCorpus.NetworkReproducibility COMMAND symfind_corpus_manager
            --verify-network --manifest "${corpusManifest}"
            --corpus "${SYMFIND_NTDLL_CORPUS_DIR}"
            --checks "${PROJECT_SOURCE_DIR}/pdb_stuff/reproducibility-check" --allow-network)
        set_tests_properties(NtdllCorpus.NetworkReproducibility PROPERTIES
            LABELS network TIMEOUT 1800)
    endif()
endif()
