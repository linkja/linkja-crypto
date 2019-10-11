# CMakeLists.txt : Top-level CMake project file, do global configuration
# and include sub-projects here.
#
cmake_minimum_required (VERSION 3.8)

find_package(Java REQUIRED)
set(JAVA_AWT_LIBRARY NotNeeded)
set(JAVA_JVM_LIBRARY NotNeeded)
find_package(JNI REQUIRED)
include(UseJava)
message(STATUS "Using Java ${Java_VERSION_STRING}")
message(STATUS "  - Java compiler ${Java_JAVAC_EXECUTABLE}")
SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/build/modules")
find_package(CMOCKA REQUIRED)

project ("liblinkjacrypto")

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${JNI_INCLUDE_DIRS})
include_directories("${CMAKE_SOURCE_DIR}/lib/openssl/include")

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

# Include our actual source.
add_subdirectory ("src")

# Include our C unit tests
enable_testing()
add_subdirectory(src/test/c)
