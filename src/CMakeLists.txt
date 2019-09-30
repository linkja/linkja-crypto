# CMakeList.txt : CMake project for the main src/ directory of linkja-crypto
#
cmake_minimum_required (VERSION 3.8)

add_subdirectory ("openssl")

# Specify the .c file that creates our shared library
add_library (liblinkjacrypto SHARED "linkja-crypto.c")

target_link_libraries(liblinkjacrypto bio bn buffer engine asn1 rsa)
