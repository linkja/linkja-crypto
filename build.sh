export JAVA_HOME=$(/usr/libexec/java_home)

# Clean up all previous output
rm -r out/

# Create the JNI header file
javac -h ./src/include ./src/java/Library.java

# Compile our actual code
mkdir -p out
gcc -c -fPIC -I${JAVA_HOME}/include -I${JAVA_HOME}/include/darwin ./src/linkja-crypto.c -o ./out/linkja-crypto.o

# Create our bridge library
gcc -dynamiclib -o ./out/liblinkjacrypto.dylib ./out/linkja-crypto.o -lc

# Compile our JAR
mkdir -p out/java
javac -d out/java src/java/Library.java
cd out/java
jar -cvf ../Library.jar *
cd ../..
