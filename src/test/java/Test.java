import org.linkja.crypto.Library;
import org.linkja.crypto.AesResult;
import java.util.Arrays;

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

    // GENERATETOKEN
    final int TOKEN_LEN = 32;
    String token1 = library.generateToken(TOKEN_LEN);
    String token2 = library.generateToken(TOKEN_LEN);
    if (token1 == null || token1.length() != TOKEN_LEN*2) { // Remember 2 chars for 1 byte in response
      System.out.printf("**ERROR : generateToken did not return a %d character string for the first %d byte value\r\n", (TOKEN_LEN*2), TOKEN_LEN);
    }
    else if (token2 == null || token2.length() != TOKEN_LEN*2) { // Remember 2 chars for 1 byte in response
      System.out.printf("**ERROR : generateToken did not return a %d character string for the second %d byte value\r\n", (TOKEN_LEN*2), TOKEN_LEN);
    }
    else if (token1.equals(token2)) {
      System.out.println("**ERROR : generateToken returned the same key twice");
    }
    else {
      System.out.println("OK - generateToken");
    }

    // GENERATEKEY
    final int KEY_LEN = 64;
    byte[] key1 = library.generateKey(KEY_LEN);
    byte[] key2 = library.generateKey(KEY_LEN);
    if (key1 == null || key1.length != KEY_LEN) {
      System.out.printf("**ERROR : generateKey did not return a %d byte value for the first key\r\n", KEY_LEN);
    }
    else if (key2 == null || key2.length != KEY_LEN) {
      System.out.printf("**ERROR : generateKey did not return a %d byte value for the second key\r\n", KEY_LEN);
    }
    else if (Arrays.equals(key1, key2)) {
      System.out.println("**ERROR : generateKey returned the same key twice");
    }
    else {
      System.out.println("OK - generateKey");
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

    // AESENCRYPT
    String toEncrypt = "Q/P1p5MxhzSD2AmyFLiufXvEICN49gAxM2dAGVzK//c=,JJxoVizrAxGs1kRyGoMGGvvw1C+e9xKJTI2rwj8Dmxw=,0iBtATEM/0RDCNYRfb8YFNmsEd8cQKcR5txG2bj8YMU=,XGCnzvIQBtQTrWW1Svs1IArkFBPfv/g4ulXgzb6uuP0=,j6wgTfEuUx6whub452yYu2c93PNC8Ms92c49H3vMWQk=";
    String aad = "Project12345";
    byte[] key = library.generateKey(32);
    byte[] iv = library.generateIV(12);
    AesResult encryptResult = library.aesEncrypt(toEncrypt.getBytes(), aad.getBytes(), key, iv);
    if (encryptResult == null || encryptResult.data == null || encryptResult.tag == null) {
        System.out.println("**ERROR : aesEncrypt did not return a result");
    }
    else {
        System.out.println("OK - aesEncrypt");
    }

    // AESDECRYPT
    AesResult decryptResult = library.aesDecrypt(encryptResult.data, aad.getBytes(), key, iv, encryptResult.tag);
    if (decryptResult == null) {
        System.out.println("**ERROR : aesDecrypt did not return a result");
    }
    else if (!Arrays.equals(toEncrypt.getBytes(), decryptResult.data)) {
        System.out.println("**ERROR : aesDecrypt returned an invalid result");
    }
    else {
        System.out.println("OK - aesDecrypt");
    }
  }
}
