#!/bin/bash
set -e

export JAVA_HOME=$(/usr/libexec/java_home)

# Compile our simple test program
$JAVA_HOME/bin/javac -cp ./out/Library.jar ./test/Test.java

# Run the test program, ensuring that we specify where our Java library exists
# (Library.jar), as well as the path where the dylib texts (./out)
$JAVA_HOME/bin/java -cp ./out/Library.jar:./test -Djava.library.path=./out Test
