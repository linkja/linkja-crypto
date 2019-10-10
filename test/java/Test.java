import org.linkja.crypto.Library;

public class Test {
  // A very basic tester to call our test function call for linkja-crypto
  public static void main(String[] args) {
    Library library = new Library();
    System.out.printf("Library signature: %s\r\n", library.getLibrarySignature());
  }
}
