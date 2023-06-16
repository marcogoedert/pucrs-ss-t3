import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AES {
  public static String cipher(String password, String textToCipher) throws Exception {
    SecretKeySpec skeySpec = new SecretKeySpec(Utils.parseHexStringToByteArray(password), "AES");
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    byte[] iv = new byte[Constants.SECRET_LENGTH];
    new SecureRandom().nextBytes(iv);
    IvParameterSpec ivp = new IvParameterSpec(iv);
    cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivp);
    byte[] encrypted = cipher.doFinal(textToCipher.getBytes());
    return Utils.parseByteArrayToHexString(iv) + Utils.parseByteArrayToHexString(encrypted);
  }

  static String decipher(String password, String cipheredMessage) throws Exception {
    SecretKeySpec skeySpec = new SecretKeySpec(Utils.parseHexStringToByteArray(password), "AES");
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    byte[] string = Utils.parseHexStringToByteArray(cipheredMessage);
    IvParameterSpec ivp = new IvParameterSpec(Arrays.copyOfRange(string, 0, Constants.SECRET_LENGTH));
    cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivp);
    byte[] deciphered = cipher.doFinal(Arrays.copyOfRange(string, Constants.SECRET_LENGTH, string.length));
    return new String(deciphered, StandardCharsets.UTF_8);
  }
}
