#!/bin/bash
set -e

export JAVA_HOME=$(/usr/libexec/java_home)

# Clean up all previous output
rm -rf out/

# Create the JNI header file
$JAVA_HOME/bin/javac -h ./src/include ./src/main/java/Library.java

# Ensure cmake targets are updated
cmake . -DCMAKE_BUILD_TYPE=Release

make clean
make

mvn clean package
