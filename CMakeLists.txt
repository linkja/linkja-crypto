# CMakeLists.txt : Top-level CMake project file, do global configuration
# and include sub-projects here.
#
cmake_minimum_required (VERSION 3.8)
find_package(Java REQUIRED)
find_package(JNI REQUIRED)

project ("liblinkjacrypto")

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU" OR
    "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    set(warnings "-Wall -Wextra -Werror")
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    set(warnings "/W4 /WX /EHsc")
endif()
if (NOT CONFIGURED_ONCE)
    set(CMAKE_CXX_FLAGS "${warnings}"
        CACHE STRING "Flags used by the compiler during all build types." FORCE)
    set(CMAKE_C_FLAGS   "${warnings}"
        CACHE STRING "Flags used by the compiler during all build types." FORCE)
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${JNI_INCLUDE_DIRS})

# try to extract the version from the VERSION file
FILE(READ ${CMAKE_CURRENT_SOURCE_DIR}/VERSION VERSION)
SET(LC_VERSION ${VERSION})
# Make sure to strip trailing newline
string(REGEX REPLACE "\n$" "" LC_VERSION "${LC_VERSION}")
if(LC_VERSION STREQUAL "") # lookup failed
	set(LC_VERSION "unknown")
endif()
message(STATUS "Detected version: ${LC_VERSION}")
unset(VERSION)

# Include sub-projects.
add_subdirectory ("src")