cmake_minimum_required(VERSION 3.20)
project(ReleaseGuardExample VERSION 0.2.0 LANGUAGES CXX)

# Single-configuration generators otherwise default to an unoptimized build.
if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

include("${CMAKE_CURRENT_LIST_DIR}/../cmake/ReleaseGuard.cmake")

add_executable(releaseguard-example main.cpp)
target_compile_features(releaseguard-example PRIVATE cxx_std_17)
target_compile_definitions(releaseguard-example PRIVATE RELEASEGUARD_EXAMPLE_PROTECTED=1)
releaseguard_protect(releaseguard-example POLICY "${CMAKE_CURRENT_LIST_DIR}/policy.json")

# Same observable program, built without protect or the literal wrapper.
add_executable(releaseguard-example-plain main.cpp)
target_compile_features(releaseguard-example-plain PRIVATE cxx_std_17)

enable_testing()
add_test(NAME releaseguard-example-smoke COMMAND releaseguard-example)
set_tests_properties(releaseguard-example-smoke PROPERTIES
    PASS_REGULAR_EXPRESSION "ReleaseGuard example: build mitigations enabled\\."
)
add_test(NAME releaseguard-example-plain-smoke COMMAND releaseguard-example-plain)
set_tests_properties(releaseguard-example-plain-smoke PROPERTIES
    PASS_REGULAR_EXPRESSION "ReleaseGuard example: build mitigations enabled\\."
)
