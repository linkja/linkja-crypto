export JAVA_HOME=$(/usr/libexec/java_home)

# Clean up all previous output
rm -r out/

# Create the JNI header file
javac -h ./src/include ./src/java/Library.java

# Compile our actual code
mkdir -p out
gcc -c -fPIC -I${JAVA_HOME}/include -I${JAVA_HOME}/include/darwin -I./lib/openssl/include ./src/linkja-crypto.c -o ./out/linkja-crypto.o

# Create our bridge library, and link in openssl
gcc -dynamiclib ./out/linkja-crypto.o -L ./lib/openssl/macos -lcrypto -lc -o ./out/liblinkjacrypto.dylib

# Compile our JAR
mkdir -p out/java
javac -d out/java src/java/Library.java
cd out/java
jar -cvf ../Library.jar *
cd ../..
