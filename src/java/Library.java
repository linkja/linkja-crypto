package linkja.crypto;

public class Library {
    static {
      System.loadLibrary("linkjacrypto");
    }

    // Declare a native method test() that receives no arguments and returns void
    public static native void test();
}
