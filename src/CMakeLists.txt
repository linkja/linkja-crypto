# CMakeList.txt : CMake project for CMakeProject1, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

# Specify the .c file that creates our shared library
add_library (liblinkjacrypto SHARED "linkja-crypto.c")

# TODO: Add tests and install targets if needed.
