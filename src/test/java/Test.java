import org.linkja.crypto.Library;

public class Test {
  // A very basic tester for linkja-crypto integration tests
  public static void main(String[] args) {
    Library library = new Library();
    System.out.printf("Library signature: %s\r\n", library.getLibrarySignature());

    // HASH
    String input = "linkja";
    String hash = library.hash(input);
    if (hash.equals("d9a759a5b2b67c17ac8dcaf239b97fae8535c297b6775ba0e2e338f5879982b4950825387ecfb4c56b11bd23109dcf599fb43f0ba4de47bde820752095220fdb")) {
      System.out.println("OK - hash");
    }
    else {
      System.out.printf("**ERROR : unexpected results from hash: %s\r\n", hash);
    }

    // CREATESECUREHASH
    final String TEST_TOKEN_STRING = "8ba490e699fc3d12db277445def2cae8ecd3f23c04c3344b63781bf9e5804f22";
    final String ROW_ID = "1001";
    final String TOKEN_ID = "testToken1";
    String secureHash = library.createSecureHash(TEST_TOKEN_STRING, ROW_ID, TOKEN_ID);
    // The secure hash is considered valid if it is not a null or empty string
    if (secureHash == null || secureHash.equals("")) {
      System.out.println("**ERROR : createSecureHash returned empty string");
    }
    else {
      System.out.println("OK - createSecureHash");
    }

    // REVERTSECUREHASH
    String originalHash = library.revertSecureHash(secureHash, ROW_ID, TOKEN_ID);
    if (originalHash.equals(library.hash(TEST_TOKEN_STRING))) {
      System.out.println("OK - revertSecureHash");
    }
    else {
      System.out.printf("**ERROR : Hash did not revert properly.  Received %s\r\n", originalHash);
    }
  }
}
