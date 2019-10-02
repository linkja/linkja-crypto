# CMakeList.txt : CMake project for the main src/ directory of linkja-crypto
#
cmake_minimum_required (VERSION 3.8)

add_library(openssl STATIC IMPORTED) # or STATIC instead of SHARED
set_target_properties(openssl PROPERTIES
  IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/lib/openssl/macos/libcrypto.a"
  INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/lib/openssl/include"
)

# Specify the .c file that creates our shared library
add_library (linkjacrypto SHARED "linkja-crypto.c")

# Add the dependency to link to the openssl library
target_link_libraries(linkjacrypto openssl)

# Specify the directory where we want our final library written
set_target_properties(linkjacrypto
    PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/out"
)
