# CMakeList.txt : CMake project for the main src/ directory of linkja-crypto
#
cmake_minimum_required (VERSION 3.8)

# Define how many bytes should be in the secret value
SET(SECRET_LEN 32)
# Define how many characters of the secret value's hash we should display.
# By showing less than the whole string, we are minimizing information disclosure.
SET(SECRET_HASH_LEN 32)

if(EXISTS "src/include/linkja_secret.h")
  message(WARNING "*** The secret header file (src/include/linkja_secret) already exists ***\nIf you need a new secret generated, please delete the header first.")
else()
  message(STATUS "Generating the secret header file (src/include/linkja_secret).")

  # Start writing out the header file that will contain our secret value.
  file(WRITE include/linkja_secret.h "// This is an automatically generated file\n\n#ifndef LINKJA_SECRET_H\n#define LINKJA_SECRET_H\n\n")
  file(APPEND include/linkja_secret.h "#define LINKJA_SECRET_LEN ${SECRET_LEN}\n#define LINKJA_SECRET {")

  # Use openssl to generate random hex digits and use those to populate the secret
  # value in the header file
  execute_process(COMMAND openssl rand -hex ${SECRET_LEN} OUTPUT_VARIABLE RANDOM_VALUE)
  file(WRITE ../tmp/openssl.tmp "${RANDOM_VALUE}")
  # Note that the process executes in the context of the top-level directory, so we
  # access the file under tmp/ instead of ../tmp/
  execute_process(COMMAND openssl dgst -sha256 tmp/openssl.tmp OUTPUT_VARIABLE RANDOM_VALUE_HASH)
  string(REGEX REPLACE "SHA256.*= " "" RANDOM_VALUE_HASH "${RANDOM_VALUE_HASH}")
  string(REGEX REPLACE "\n$" "" RANDOM_VALUE_HASH "${RANDOM_VALUE_HASH}")
  file(REMOVE ../tmp/openssl.tmp)
  foreach(gen_loop RANGE 1 ${SECRET_LEN})
    MATH(EXPR str_start "(${gen_loop}*2)-2")
    string(SUBSTRING "${RANDOM_VALUE}" ${str_start} 2 VALUE)
    file(APPEND include/linkja_secret.h "0x${VALUE}")
    IF(NOT gen_loop EQUAL ${SECRET_LEN})
      file(APPEND include/linkja_secret.h ", ")
    ENDIF(NOT gen_loop EQUAL ${SECRET_LEN})
  endforeach(gen_loop)

  string(SUBSTRING "${RANDOM_VALUE_HASH}" 0 ${SECRET_HASH_LEN} RANDOM_VALUE_HASH)
  file(APPEND include/linkja_secret.h "}\n#define LINKJA_SECRET_HASH \"${RANDOM_VALUE_HASH}\" \n\n#endif\n")
endif()


# Link in openssl
add_library(openssl STATIC IMPORTED) # or STATIC instead of SHARED
set_target_properties(openssl PROPERTIES
  IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/lib/openssl/macos/libcrypto.a"
  INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/lib/openssl/include"
)

# Specify the .c file that creates our shared library
add_library(linkjacrypto SHARED "linkja-crypto.c")

# Add some additional compiler options for strict warning checks.
target_compile_options(linkjacrypto PRIVATE -Wall -Wextra -Wpedantic -Werror)

# Add the dependency to link to the openssl library
target_link_libraries(linkjacrypto openssl)

# Specify the directory where we want our final library written
set_target_properties(linkjacrypto
    PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/target"
)
