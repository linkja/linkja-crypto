#!/bin/bash
set -e

# Run the C unit tests
ctest -V

# Run the simple Java integration test
export JAVA_HOME=$(/usr/libexec/java_home)

# Compile our simple test program
$JAVA_HOME/bin/javac -cp ./out/linkja-crypto.jar ./test/java/Test.java

# Run the test program, ensuring that we specify where our Java library exists,
# as well as the path where the dylib exists (both in ./out)
$JAVA_HOME/bin/java -cp ./out/linkja-crypto.jar:./test/java -Djava.library.path=./out Test
