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

add_compile_options(-Wall -Wextra -Wpedantic)

# Build fstrace
add_executable(fstrace src/fstrace.cc)
set_target_properties(fstrace PROPERTIES DEBUG_POSTFIX ${CMAKE_DEBUG_POSTFIX})
target_include_directories(fstrace PUBLIC "${PROJECT_BINARY_DIR}")
target_compile_features(fstrace PUBLIC cxx_std_20)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  message(STATUS "Setting DEBUG flag. FD4 will have debug log. and FD3 will have comments with syscall info.")
  target_compile_definitions(fstrace PRIVATE DEBUG)
endif()

set_target_properties(fstrace PROPERTIES
    ADDITIONAL_CLEAN_FILES "${PROJECT_SOURCE_DIR}/node/fstrace/${PROJECT_NAME}"
)
set_target_properties(fstrace PROPERTIES
    ADDITIONAL_CLEAN_FILES "${PROJECT_SOURCE_DIR}/node/fstrace/${PROJECT_NAME}${CMAKE_DEBUG_POSTFIX}"
)
add_custom_command(
    TARGET fstrace POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:fstrace>
        ${PROJECT_SOURCE_DIR}/node/fstrace/$<TARGET_FILE_NAME:fstrace>
)

include(CTest)
add_test(NAME exit-code-passthrough COMMAND ${PROJECT_SOURCE_DIR}/tests/exit-code-passthrough.sh)
add_test(NAME signal-passthrough COMMAND ${PROJECT_SOURCE_DIR}/tests/signal-passthrough.sh)
