#!/bin/bash
set -e

export JAVA_HOME=$(/usr/libexec/java_home)

# Clean up all previous output
rm -r out/

# Create the JNI header file
$JAVA_HOME/bin/javac -h ./src/include ./src/java/Library.java

# Ensure cmake targets are updated
cmake .

make clean
make
