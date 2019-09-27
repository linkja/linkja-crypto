./build.sh

# Compile our simple test program
javac -cp ./out/Library.jar ./test/Test.java

# Run the test program, ensuring that we specify where our Java library exists
# (Library.jar), as well as the path where the dylib texts (./out)
java -cp ./out/Library.jar:./test -Djava.library.path=./out Test
