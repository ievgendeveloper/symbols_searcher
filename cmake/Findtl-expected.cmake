# LIEF calls find_package(tl-expected); reuse the pinned FetchContent target.
if(NOT TARGET tl::expected)
    message(FATAL_ERROR "tl_expected must be made available before configuring LIEF")
endif()
set(tl-expected_FOUND TRUE)
