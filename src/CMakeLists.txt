# CMakeList.txt : CMake project for the main src/ directory of linkja-crypto
#
cmake_minimum_required (VERSION 3.8)

# Define how many bytes should be in the secret value
SET(SECRET_LEN 16)

# Start writing out the header file that will contain our secret value.
file(WRITE include/linkja_secret.h "#ifndef LINKJA_SECRET_H\n#define LINKJA_SECRET_H\n")
file(APPEND include/linkja_secret.h "const char LINKJA_SECRET[] = {")

# Use openssl to generate random hex digits and use those to populate the secret
# value in the header file
execute_process(COMMAND openssl rand -hex ${SECRET_LEN} OUTPUT_VARIABLE RANDOM_VALUE)
string(REGEX REPLACE "\n$" "" RANDOM_VALUE "${RANDOM_VALUE}")
foreach(gen_loop RANGE 1 ${SECRET_LEN})
  MATH(EXPR str_start "(${gen_loop}*2)-2")
  string(SUBSTRING "${RANDOM_VALUE}" ${str_start} 2 VALUE)
  file(APPEND include/linkja_secret.h "0x${VALUE}")
  IF(NOT gen_loop EQUAL ${SECRET_LEN})
    file(APPEND include/linkja_secret.h ", ")
  ENDIF(NOT gen_loop EQUAL ${SECRET_LEN})
endforeach(gen_loop)
file(APPEND include/linkja_secret.h "};\n#endif")

# Link in openssl
add_library(openssl STATIC IMPORTED) # or STATIC instead of SHARED
set_target_properties(openssl PROPERTIES
  IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/lib/openssl/macos/libcrypto.a"
  INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/lib/openssl/include"
)

# Specify the .c file that creates our shared library
add_library(linkjacrypto SHARED "linkja-crypto.c")

# Add the dependency to link to the openssl library
target_link_libraries(linkjacrypto openssl)

# Specify the directory where we want our final library written
set_target_properties(linkjacrypto
    PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/out"
)
