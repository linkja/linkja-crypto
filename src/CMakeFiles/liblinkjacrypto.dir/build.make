# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.15

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/Cellar/cmake/3.15.3/bin/cmake

# The command to remove a file.
RM = /usr/local/Cellar/cmake/3.15.3/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/lvr491/Development/linkja/linkja-crypto

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/lvr491/Development/linkja/linkja-crypto

# Include any dependencies generated for this target.
include src/CMakeFiles/liblinkjacrypto.dir/depend.make

# Include the progress variables for this target.
include src/CMakeFiles/liblinkjacrypto.dir/progress.make

# Include the compile flags for this target's objects.
include src/CMakeFiles/liblinkjacrypto.dir/flags.make

src/CMakeFiles/liblinkjacrypto.dir/linkja-crypto.c.o: src/CMakeFiles/liblinkjacrypto.dir/flags.make
src/CMakeFiles/liblinkjacrypto.dir/linkja-crypto.c.o: src/linkja-crypto.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/lvr491/Development/linkja/linkja-crypto/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object src/CMakeFiles/liblinkjacrypto.dir/linkja-crypto.c.o"
	cd /Users/lvr491/Development/linkja/linkja-crypto/src && /Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/liblinkjacrypto.dir/linkja-crypto.c.o   -c /Users/lvr491/Development/linkja/linkja-crypto/src/linkja-crypto.c

src/CMakeFiles/liblinkjacrypto.dir/linkja-crypto.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/liblinkjacrypto.dir/linkja-crypto.c.i"
	cd /Users/lvr491/Development/linkja/linkja-crypto/src && /Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/lvr491/Development/linkja/linkja-crypto/src/linkja-crypto.c > CMakeFiles/liblinkjacrypto.dir/linkja-crypto.c.i

src/CMakeFiles/liblinkjacrypto.dir/linkja-crypto.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/liblinkjacrypto.dir/linkja-crypto.c.s"
	cd /Users/lvr491/Development/linkja/linkja-crypto/src && /Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/lvr491/Development/linkja/linkja-crypto/src/linkja-crypto.c -o CMakeFiles/liblinkjacrypto.dir/linkja-crypto.c.s

# Object files for target liblinkjacrypto
liblinkjacrypto_OBJECTS = \
"CMakeFiles/liblinkjacrypto.dir/linkja-crypto.c.o"

# External object files for target liblinkjacrypto
liblinkjacrypto_EXTERNAL_OBJECTS =

src/libliblinkjacrypto.dylib: src/CMakeFiles/liblinkjacrypto.dir/linkja-crypto.c.o
src/libliblinkjacrypto.dylib: src/CMakeFiles/liblinkjacrypto.dir/build.make
src/libliblinkjacrypto.dylib: src/CMakeFiles/liblinkjacrypto.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/lvr491/Development/linkja/linkja-crypto/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C shared library libliblinkjacrypto.dylib"
	cd /Users/lvr491/Development/linkja/linkja-crypto/src && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/liblinkjacrypto.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
src/CMakeFiles/liblinkjacrypto.dir/build: src/libliblinkjacrypto.dylib

.PHONY : src/CMakeFiles/liblinkjacrypto.dir/build

src/CMakeFiles/liblinkjacrypto.dir/clean:
	cd /Users/lvr491/Development/linkja/linkja-crypto/src && $(CMAKE_COMMAND) -P CMakeFiles/liblinkjacrypto.dir/cmake_clean.cmake
.PHONY : src/CMakeFiles/liblinkjacrypto.dir/clean

src/CMakeFiles/liblinkjacrypto.dir/depend:
	cd /Users/lvr491/Development/linkja/linkja-crypto && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/lvr491/Development/linkja/linkja-crypto /Users/lvr491/Development/linkja/linkja-crypto/src /Users/lvr491/Development/linkja/linkja-crypto /Users/lvr491/Development/linkja/linkja-crypto/src /Users/lvr491/Development/linkja/linkja-crypto/src/CMakeFiles/liblinkjacrypto.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : src/CMakeFiles/liblinkjacrypto.dir/depend
