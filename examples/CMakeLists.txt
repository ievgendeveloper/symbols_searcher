add_executable(symfind_example
    main.cpp
)

target_link_libraries(symfind_example
    PRIVATE
        symfind
        spdlog::spdlog
)
