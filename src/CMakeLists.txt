# CMakeList.txt : CMake project for the main src/ directory of linkja-crypto
#
cmake_minimum_required (VERSION 3.8)

# Helper function to generate a random byte and format it for inclusion
# in our byte array.
function(append_random_value suffix)
  execute_process(COMMAND openssl rand -hex 1 OUTPUT_VARIABLE RANDOM_VALUE)
  string(REGEX REPLACE "\n$" "" RANDOM_VALUE "${RANDOM_VALUE}")
  file(APPEND include/linkja_secret.h "0x${RANDOM_VALUE}${suffix}")
endfunction(append_random_value)

# Generate our secret value within a header file.
file(WRITE include/linkja_secret.h "#ifndef LINKJA_SECRET_H\n#define LINKJA_SECRET_H\n")
file(APPEND include/linkja_secret.h "const char LINKJA_SECRET[] = {")
foreach(gen_loop RANGE 1 15)
  append_random_value(",")
endforeach(gen_loop)
append_random_value("")
file(APPEND include/linkja_secret.h "};\n#endif")

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
