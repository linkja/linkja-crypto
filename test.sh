#!/bin/bash
set -e

# Because maven and cmake can run at different times and clobber the target
# directory, we need to make an explicit check that the dylib exists.  If not,
# we will build it quick
if [[ "$OSTYPE" == "darwin"* ]]; then
  if [ ! -f "./target/liblinkjacrypto.dylib" ]; then
    make clean
    make
  fi
fi

# Run the C unit tests
ctest -V

# Run the simple Java integration test
export JAVA_HOME=$(/usr/libexec/java_home)

# Compile our simple test program
$JAVA_HOME/bin/javac -cp ./target/linkja-crypto-0.2.0.jar ./src/test/java/Test.java

# Run the test program, ensuring that we specify where our Java library exists,
# as well as the path where the dylib exists (both in ./out)
$JAVA_HOME/bin/java -cp ./target/linkja-crypto-0.2.0.jar:./src/test/java -Djava.library.path=./target Test
