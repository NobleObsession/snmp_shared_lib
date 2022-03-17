cmake_minimum_required(VERSION 3.5)

project(snmp_shared_lib LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/609281088cfefc76f9d0ce82e1ff6c30cc3591e5.zip
)
FetchContent_MakeAvailable(googletest)


add_executable(snmp_shared_lib main.cpp mib_handler.cc default_store.cc
    )

enable_testing()

add_executable(
  my_test
  my_test.cc packet_parser.cc trap_handler.cc mib_handler.cc default_store.cc

)
target_link_libraries(
  my_test
  gtest_main
)

include(GoogleTest)
gtest_discover_tests(my_test)

