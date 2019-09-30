# CMakeList.txt : CMake project for the openssl code used by linkja-crypto
#
cmake_minimum_required (VERSION 3.8)

add_subdirectory ("bn")
add_subdirectory ("bio")
add_subdirectory ("buffer")
add_subdirectory ("engine")
add_subdirectory ("asn1")
add_subdirectory ("rsa")
