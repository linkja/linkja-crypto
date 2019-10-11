package org.linkja.crypto;

public class Library {
    static {
      System.loadLibrary("linkjacrypto");
    }

    public static native String hash(String input);

    // Return a hash representing this particular build of the library.
    public static native String getLibrarySignature();
}
