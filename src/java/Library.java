package org.linkja.crypto;

public class Library {
    static {
      System.loadLibrary("linkjacrypto");
    }

    // Return a hash representing this particular build of the library.
    public static native String getLibrarySignature();
}
