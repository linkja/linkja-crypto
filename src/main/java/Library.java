package org.linkja.crypto;

public class Library {
    static {
      System.loadLibrary("linkjacrypto");
    }

    // Generate a string representing the hex characters of a hash from the
    // input string.
    public static native String hash(String input);

    // Generate a string representing the hex characters of a hash given the
    // input string, and further mixed with the row ID and an ID for the
    // token we are creating.
    public static native String createSecureHash(String input, String rowId, String tokenId);

    // Generate a string representing the hex characters of the true hash of a
    // token, given the linkja secure hash (with additional entropy), the row ID
    // and an ID for the token we want.
    public static native String revertSecureHash(String input, String rowId, String tokenId);

    // Generate a random token of the specified length.  The resulting String
    // will be the hex characters representing the random token (meaning it will
    // be 2x the size of length).
    public static native String generateToken(int length);

    // Generate a random key of the specified length.  The resulting byte array
    // will be the random token data.
    public static native byte[] generateKey(int length);

    // Return a hash representing this particular build of the library.
    public static native String getLibrarySignature();

}
