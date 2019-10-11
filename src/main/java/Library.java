package org.linkja.crypto;

public class Library {
    static {
      System.loadLibrary("linkjacrypto");
    }

    // Generate a string representing the hex characters of a hash from the
    // input string.
    public static native String hash(String input);

    // Generate a random token of the specified length.  The resulting String
    // will be the hex characters representing the random token (meaning it will
    // be 2x the size of length).
    public static native String generateToken(int length);

    // Return a hash representing this particular build of the library.
    public static native String getLibrarySignature();


}
