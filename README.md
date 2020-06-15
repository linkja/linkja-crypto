# linkja-crypto
C library to handle cryptographic functions.  Because this is intended to be used by the
linkja programs (which are written in Java), this includes the Java Native Interface (JNI)
headers with the C code.



## Dependencies

Setup and building of the linkja-crypto library requires the following:

1. [CMake](https://cmake.org) (3.8 or higher)
2. Java (1.8 or higher; [OpenJDK](https://openjdk.java.net/) is allowed)
    1. Requires the JDK to be installed
    2. Will use javac and java binaries
    3. Requires Java Native Interface (JNI), which comes with most JDKs
3. [OpenSSL](https://www.openssl.org/) - the openssl binary needs to be in your path for the build scripts to work.  You can test this by executing "openssl version" at the command line.
4. C compiler and make system
    1. For macOS, gcc and make can be used.
    2. For Windows, Visual Studio 2019 Community edition can be used.
5. [cmocka](https://cmocka.org/) for unit tests
    1. For macOS, `brew install cmocka`
    2. For Windows, [download the latest source code](https://cmocka.org/files/1.1/)
        1. Extract the .tar.xz to a folder
        2. You can use Visual Studio to open the folder and build via CMakeList

## Building

There are multiple components that go into building the linkja-crypto library.  For macOS, these are wrapped up into the `build.sh` script (available from the root directory).

1. Create the JNI header file
  >`$JAVA_HOME/bin/javac -h ./src/include ./src/java/Library.java`

2. Ensure cmake targets are built and/or updated
  > `cmake .`

3. Build the library
  ```
  make clean
  make
  ```

## Testing
To ensure everything is set up correctly, you can compile and run a simple test program using the testing script:

```
./test.sh
```
