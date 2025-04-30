cmake_minimum_required(VERSION 3.15)
project(
  fstrace
  LANGUAGES C CXX
)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_DEBUG_POSTFIX -debug)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
  message(STATUS "Building in debug mode")
  set(CMAKE_BUILD_TYPE Debug)
  add_compile_options(-Og)
else()
  message(STATUS "Building in release mode")
  set(CMAKE_BUILD_TYPE Release)
  add_compile_options(-Ofast)
endif()

add_compile_options(-Wall -Wextra -Wpedantic -Wimplicit-fallthrough)

include(FetchContent)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY "https://github.com/google/googletest"
  GIT_TAG "v1.16.0"
)
FetchContent_MakeAvailable(googletest)

add_executable(fstrace src/fstrace.cc)

set(DEBUG_FD 4)
target_compile_definitions(fstrace PRIVATE DEBUGFD=${DEBUG_FD})

set_target_properties(fstrace PROPERTIES DEBUG_POSTFIX ${CMAKE_DEBUG_POSTFIX})
target_include_directories(fstrace PUBLIC "${PROJECT_BINARY_DIR}")
target_compile_features(fstrace PUBLIC cxx_std_20)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  target_compile_definitions(fstrace PRIVATE DEBUG)
  message(STATUS "Setting DEBUG flag. DEBUG_FD (${DEBUG_FD}) will have debug log. and FD3 will have comments with syscall info.")
endif()

add_custom_command(
    TARGET fstrace POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:fstrace>
        ${PROJECT_SOURCE_DIR}/node/fstrace/$<TARGET_FILE_NAME:fstrace>
)

enable_testing()

include(CTest)

add_test(NAME exit-code-passthrough COMMAND ${PROJECT_SOURCE_DIR}/tests/exit-code-passthrough.sh)
add_test(NAME signal-passthrough COMMAND ${PROJECT_SOURCE_DIR}/tests/signal-passthrough.sh)


add_executable(
  syscall-tests
  tests/syscalls.cc
)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  target_compile_definitions(syscall-tests PRIVATE DEBUG)
  message(STATUS "Setting DEBUG flag. DEBUG_FD (${DEBUG_FD}) will have debug log. and FD3 will have comments with syscall info.")
  target_compile_definitions(syscall-tests PRIVATE DEBUGFD=${DEBUG_FD})
endif()
target_link_libraries(syscall-tests GTest::gtest_main)

include(GoogleTest)

target_include_directories(syscall-tests PUBLIC "${PROJECT_SOURCE_DIR}")
target_compile_options(syscall-tests PRIVATE --coverage)
target_link_options(syscall-tests PRIVATE --coverage)

gtest_discover_tests(syscall-tests)
