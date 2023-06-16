import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;

public class Utils {

  private static final int HEX_RADIX = 16;

  public static String parseBigIntToHexString(BigInteger b) {
    byte[] byteArray = b.toByteArray();
    return parseByteArrayToHexString(byteArray);
  }

  public static byte[] parseHexStringToByteArray(String hexString) {
    int length = hexString.length() / 2;
    byte[] byteArray = new byte[length];
    for (int i = 0, j = 0; i < hexString.length(); i += 2, j++) {
      String hexByte = hexString.substring(i, i + 2);
      byteArray[j] = (byte) Integer.parseInt(hexByte, HEX_RADIX);
    }
    return byteArray;
  }

  public static String parseByteArrayToHexString(byte[] byteArray) {
    int capacity = byteArray.length * 2;
    StringBuilder sb = new StringBuilder(capacity);
    for (byte b : byteArray) {
      int V = b & 0xff;
      if (V < Constants.SECRET_LENGTH) {
        sb.append('0');
      }
      sb.append(Integer.toHexString(V));
    }
    return sb.toString().toUpperCase();
  }

  public static String reverseString(String string) {
    return new StringBuilder(string).reverse().toString();
  }

  public static String createSecret(BigInteger input, int secretLength) throws Exception {
    MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
    messageDigest.update(input.toByteArray());
    byte[] inputHashedBytes = messageDigest.digest();
    byte[] secret = Arrays.copyOfRange(inputHashedBytes, 0, secretLength);
    return parseByteArrayToHexString(secret);
  }

}
