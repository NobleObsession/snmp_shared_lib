cmake_minimum_required(VERSION 3.5)

project(snmp_shared_lib LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

cmake_policy(SET CMP0068 NEW)

################## Conan bootstrap ###############
# see https://blog.conan.io/2018/06/11/Transparent-CMake-Integration.html
# auto-run conan https://github.com/conan-io/cmake-conan
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake-modules)
list(APPEND CMAKE_MODULE_PATH ${CMAKE_BINARY_DIR})#
list(APPEND CMAKE_PREFIX_PATH ${CMAKE_BINARY_DIR})

if (NOT EXISTS "${CMAKE_BINARY_DIR}/conan.cmake")
    message(STATUS "Downloading conan.cmake from https://github.com/conan-io/cmake-conan")
    file(DOWNLOAD "https://raw.githubusercontent.com/conan-io/cmake-conan/v0.16.1/conan.cmake"
            "${CMAKE_BINARY_DIR}/conan.cmake"
            TLS_VERIFY ON)
endif ()


include(${CMAKE_BINARY_DIR}/conan.cmake)
conan_check(VERSION 1.40.0 REQUIRED)
conan_cmake_autodetect(settings)
list(APPEND settings cppstd=20)

#conan_add_remote(NAME bincrafters INDEX 1
#        URL https://bincrafters.jfrog.io/artifactory/api/conan/public-conan)
#message(STATUS ${settings})

set(CONAN_REBUILD missing)
if (
(${CMAKE_BUILD_TYPE} STREQUAL "Release" AND NOT EXISTS "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libtbb.so")
        OR (NOT ${CMAKE_BUILD_TYPE} STREQUAL "Release" AND NOT EXISTS "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libtbb_debug.so")
)

#    list(PREPEND CONAN_REBUILD bzip2)
#    MESSAGE(WARNING "================ Rebuilding  ${CMAKE_BUILD_TYPE} conan libs ${CONAN_REBUILD}  ===================")
else ()
    MESSAGE(STATUS "============= Found builded TBB libraries ${CMAKE_BUILD_TYPE} in  ${CMAKE_LIBRARY_OUTPUT_DIRECTORY} ==================")
endif ()
conan_cmake_run(CONANFILE conanfile.txt
        BUILD_TYPE ${CMAKE_BUILD_TYPE}
        BASIC_SETUP
        BUILD missing ${CONAN_REBUILD}
        SETTINGS ${settings}
        )

#add_custom_command(OUTPUT ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libtbb.so
#        COMMAND "${CONAN_CMD}" ${CONAN_SOURCE_ARGS}"
#        WORKING_DIRECTORY "${CMAKE_BINARY_DIR}")
#boost moduar requires this:
#include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
#conan_basic_setup()
#
##############################  END COANAN bottstrap

set(Boost_USE_STATIC_LIBS ON)
find_package(Boost)


    set (SHARED_LIB_NAME TrapDataProvider)
    add_library(${SHARED_LIB_NAME} SHARED
            mib_handler.cc packet_parser.cc
            packet_handler.cc TrapDataProvider.cc
            )
    add_executable(snmp_shared_lib main.cpp)
SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH FALSE)
set_target_properties(snmp_shared_lib PROPERTIES LINK_FLAGS "-Wl,-rpath,${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")

target_link_libraries(snmp_shared_lib ${CONAN_LIBS}
        ${SHARED_LIB_NAME})


