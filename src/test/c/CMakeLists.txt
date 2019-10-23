# Derived from https://github.com/lperkov/cmocka-hello/blob/master/tests/CMakeLists.txt

cmake_minimum_required (VERSION 3.8)

FILE(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/out)

SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/../build/modules")
SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/out)

SET(SOURCES
	../../linkja-crypto.c
	test-linkja-crypto-hash.c
)
ADD_EXECUTABLE(test-linkja-crypto-hash ${SOURCES})
SET(SOURCES
	../../linkja-crypto.c
	test-linkja-crypto-token.c
)
ADD_EXECUTABLE(test-linkja-crypto-token ${SOURCES})
SET(SOURCES
	../../linkja-crypto.c
	test-linkja-crypto-hash-supplemental-data.c
)
ADD_EXECUTABLE(test-linkja-crypto-hash-supplemental-data ${SOURCES})

FIND_PACKAGE(CMOCKA REQUIRED)
INCLUDE_DIRECTORIES(${LIBCMOCKA_INCLUDE_DIR})
TARGET_LINK_LIBRARIES(test-linkja-crypto-hash ${LIBCMOCKA_LIBRARIES})
TARGET_LINK_LIBRARIES(test-linkja-crypto-token ${LIBCMOCKA_LIBRARIES})
TARGET_LINK_LIBRARIES(test-linkja-crypto-hash-supplemental-data ${LIBCMOCKA_LIBRARIES})

# Install and register our test programs
INSTALL(TARGETS test-linkja-crypto-hash RUNTIME DESTINATION out)
add_test(test-linkja-crypto-hash ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-linkja-crypto-hash)
INSTALL(TARGETS test-linkja-crypto-token RUNTIME DESTINATION out)
add_test(test-linkja-crypto-token ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-linkja-crypto-token)
INSTALL(TARGETS test-linkja-crypto-hash-supplemental-data RUNTIME DESTINATION out)
add_test(test-linkja-crypto-hash-supplemental-data ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-linkja-crypto-hash-supplemental-data)


# Link in openssl
add_library(openssl STATIC IMPORTED) # or STATIC instead of SHARED
set_target_properties(openssl PROPERTIES
  IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/lib/openssl/macos/libcrypto.a"
  INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/lib/openssl/include"
)

# Add the dependency to link to the openssl library
target_link_libraries(test-linkja-crypto-hash openssl)
target_link_libraries(test-linkja-crypto-token openssl)
target_link_libraries(test-linkja-crypto-hash-supplemental-data openssl)
