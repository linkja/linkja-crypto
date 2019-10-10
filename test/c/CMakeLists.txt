# Derived from https://github.com/lperkov/cmocka-hello/blob/master/tests/CMakeLists.txt

cmake_minimum_required (VERSION 3.8)

FILE(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/out)

SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/../build/modules")
SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/out)

SET(SOURCES
	../../src/linkja-crypto.c
	test-linkja-crypto-hash.c
)

ADD_EXECUTABLE(test-linkja-crypto-hash ${SOURCES})

FIND_PACKAGE(CMOCKA REQUIRED)
INCLUDE_DIRECTORIES(${LIBCMOCKA_INCLUDE_DIR})
TARGET_LINK_LIBRARIES(test-linkja-crypto-hash ${LIBCMOCKA_LIBRARIES})

# Install and register our test programs
INSTALL(TARGETS test-linkja-crypto-hash RUNTIME DESTINATION out)
add_test(test-linkja-crypto-hash ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-linkja-crypto-hash)


# Link in openssl
add_library(openssl STATIC IMPORTED) # or STATIC instead of SHARED
set_target_properties(openssl PROPERTIES
  IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/lib/openssl/macos/libcrypto.a"
  INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/lib/openssl/include"
)

# Add the dependency to link to the openssl library
target_link_libraries(test-linkja-crypto-hash openssl)
