package isp.secrecy;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
// STUDENT: ORI GONEN
/**
 * Implement a brute force key search (exhaustive key search) if you know that the
 * message is:
 * "I would like to keep this text confidential Bob. Kind regards, Alice."
 * <p>
 * Assume the message was encrypted with "DES/ECB/PKCS5Padding".
 * Also assume that the key was poorly chosen. In particular, as an attacker,
 * you are certain that all bytes in the key, with the exception of th last three bytes,
 * have been set to 0.
 * <p>
 * The length of DES key is 8 bytes.
 * <p>
 * To manually specify a key, use the class {@link javax.crypto.spec.SecretKeySpec})
 */
public class A4ExhaustiveSearch {
    public static void main(String[] args) throws Exception {
        final String message = "I would like to keep this text confidential Bob. Kind regards, Alice.";
        System.out.println("[MESSAGE] " + message);
        final byte[] pt = message.getBytes();

        // Just for an example, I'll set i=6, j=66, k=100
        int i=6,j=66,k=100;
        byte[] bytesForKey = new byte[] {(byte)0, (byte)0, (byte)0, (byte)0, (byte)0, (byte)i, (byte)j, (byte)k};
        SecretKeySpec key = new SecretKeySpec(bytesForKey, "DES");
        Cipher encrypt = Cipher.getInstance("DES/ECB/PKCS5Padding");
        encrypt.init(Cipher.ENCRYPT_MODE, key);
        final byte[] ct = encrypt.doFinal(pt);

        // Now we'll run the function and see if we get the correct i,j,k
        final byte[] res = bruteForceKey(ct, message);

        System.out.println("[Real key]\t" + Arrays.toString(bytesForKey));
        System.out.println("[Found key]\t" + Arrays.toString(res));
        // indeed, we got the same result! :)

    }

    public static byte[] bruteForceKey(byte[] ct, String message) throws Exception {
        final byte[] pt = message.getBytes();

        for (int i = 0; i<=256; i++) {
            for (int j = 0; j<=256; j++) {
                for (int k = 0; k<=256; k++) {
                    // note that in DES a 0 byte cannot happen because the 7th bit is the odd parity, so
                    // there will be 00000001 and not 00000000
                    byte[] bytesForKey = new byte[] {(byte)0, (byte)0, (byte)0, (byte)0, (byte)0, (byte)i, (byte)j, (byte)k};
                    SecretKeySpec key = new SecretKeySpec(bytesForKey, "DES");

                    Cipher encrypt = Cipher.getInstance("DES/ECB/PKCS5Padding");
                    encrypt.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] testCipherText = encrypt.doFinal(pt);
                    if (Arrays.equals(ct, testCipherText)) {
                        return bytesForKey;
                    }
                }
            }
        }
        //No key has been found
        return null;
    }
}
