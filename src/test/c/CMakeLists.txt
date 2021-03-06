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

if(INCLUDE_SECRETS)
SET(SOURCES
	../../linkja-crypto.c
	test-linkja-crypto-hash-input-data.c
)
ADD_EXECUTABLE(test-linkja-crypto-hash-input-data ${SOURCES})
endif()

SET(SOURCES
	../../linkja-crypto.c
	test-linkja-crypto-hash-supplemental-data.c
)
ADD_EXECUTABLE(test-linkja-crypto-hash-supplemental-data ${SOURCES})
SET(SOURCES
	../../linkja-crypto.c
	test-linkja-crypto-conversions.c
)
ADD_EXECUTABLE(test-linkja-crypto-conversions ${SOURCES})
SET(SOURCES
	../../linkja-crypto.c
	test-linkja-crypto-aes.c
)
ADD_EXECUTABLE(test-linkja-crypto-aes ${SOURCES})
SET(SOURCES
	../../linkja-crypto.c
	test-linkja-crypto-rsa.c
)
ADD_EXECUTABLE(test-linkja-crypto-rsa ${SOURCES})

FIND_PACKAGE(CMOCKA REQUIRED)
INCLUDE_DIRECTORIES(${LIBCMOCKA_INCLUDE_DIR})
TARGET_LINK_LIBRARIES(test-linkja-crypto-hash ${LIBCMOCKA_LIBRARIES})
TARGET_LINK_LIBRARIES(test-linkja-crypto-token ${LIBCMOCKA_LIBRARIES})
if(INCLUDE_SECRETS)
TARGET_LINK_LIBRARIES(test-linkja-crypto-hash-input-data ${LIBCMOCKA_LIBRARIES})
endif()
TARGET_LINK_LIBRARIES(test-linkja-crypto-hash-supplemental-data ${LIBCMOCKA_LIBRARIES})
TARGET_LINK_LIBRARIES(test-linkja-crypto-conversions ${LIBCMOCKA_LIBRARIES})
TARGET_LINK_LIBRARIES(test-linkja-crypto-aes ${LIBCMOCKA_LIBRARIES})
TARGET_LINK_LIBRARIES(test-linkja-crypto-rsa ${LIBCMOCKA_LIBRARIES})

# Install and register our test programs
INSTALL(TARGETS test-linkja-crypto-hash RUNTIME DESTINATION out)
add_test(test-linkja-crypto-hash ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-linkja-crypto-hash)
INSTALL(TARGETS test-linkja-crypto-token RUNTIME DESTINATION out)
add_test(test-linkja-crypto-token ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-linkja-crypto-token)
if(INCLUDE_SECRETS)
INSTALL(TARGETS test-linkja-crypto-hash-input-data RUNTIME DESTINATION out)
add_test(test-linkja-crypto-hash-input-data ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-linkja-crypto-hash-input-data)
endif()
INSTALL(TARGETS test-linkja-crypto-hash-supplemental-data RUNTIME DESTINATION out)
add_test(test-linkja-crypto-hash-supplemental-data ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-linkja-crypto-hash-supplemental-data)
INSTALL(TARGETS test-linkja-crypto-conversions RUNTIME DESTINATION out)
add_test(test-linkja-crypto-conversions ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-linkja-crypto-conversions)
INSTALL(TARGETS test-linkja-crypto-aes RUNTIME DESTINATION out)
add_test(test-linkja-crypto-aes ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-linkja-crypto-aes)
INSTALL(TARGETS test-linkja-crypto-rsa RUNTIME DESTINATION out)
add_test(test-linkja-crypto-rsa ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test-linkja-crypto-rsa)


# Link in openssl
add_library(openssl STATIC IMPORTED) # or STATIC instead of SHARED
set_target_properties(openssl PROPERTIES
  IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/lib/openssl/macos/libcrypto.a"
  INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/lib/openssl/include"
)

# Add the dependency to link to the openssl library
target_link_libraries(test-linkja-crypto-hash openssl)
target_link_libraries(test-linkja-crypto-token openssl)
if(INCLUDE_SECRETS)
target_link_libraries(test-linkja-crypto-hash-input-data openssl)
endif()
target_link_libraries(test-linkja-crypto-hash-supplemental-data openssl)
target_link_libraries(test-linkja-crypto-conversions openssl)
target_link_libraries(test-linkja-crypto-aes openssl)
target_link_libraries(test-linkja-crypto-rsa openssl)
