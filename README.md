# linkja-crypto
C library to handle cryptographic functions.  Because this is intended to be used by the
linkja programs (which are written in Java), this includes the Java Native Interface (JNI)
headers with the C code.

**WORK IN PROGRESS** - This is under active development

## Compiling
From the root directory, run the build script:

```
./build.sh
```

The build process performs several steps, managed in part by [CMake](https://cmake.org):
1. Generate the JNI header file for our library.
  `$JAVA_HOME/bin/javac -h ./src/include ./src/java/Library.java`
2. Generate the project secret, which is used to add more entropy to our encryption routines.  This is done via [???].

## Testing
To ensure everything is set up correctly, you can compile and run a simple
test program using the testing script:

```
./test.sh
```
