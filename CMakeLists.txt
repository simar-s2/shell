cmake_minimum_required(VERSION 3.14)

project(
  BasicShell
  VERSION 1.0
  DESCRIPTION "This is my Basic Shell implementation for Assignment 8."
  LANGUAGES C CXX)

set(SANITIZE_FLAGS "-fsanitize=address")

add_executable(shell src/main.c)
target_compile_options(shell PRIVATE ${SANITIZE_FLAGS})
target_link_libraries(shell PRIVATE ${SANITIZE_FLAGS})

# GoogleTest requires at least C++14
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(
  googletest
  DOWNLOAD_EXTRACT_TIMESTAMP false
  URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip)
FetchContent_MakeAvailable(googletest)

enable_testing()

add_executable(shell_test gtest/shell_test.cpp)
target_link_libraries(shell_test GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(shell_test)
