package isp.kolokvij;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.SecureRandom;

//https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html

public class Secrecy {
    public static void main(String[] args) throws Exception {

        final Key rc4Key = KeyGenerator.getInstance("RC4").generateKey();
        final Key aesKey = KeyGenerator.getInstance("AES").generateKey();
        final Key chaCha20Key = KeyGenerator.getInstance("ChaCha20").generateKey();

        SecureRandom random = SecureRandom.getInstanceStrong();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String message = "Hi Bob, this is Alice.";
                final byte[] pt = message.getBytes(StandardCharsets.UTF_8);

                //RC4
                final Cipher rc4 = Cipher.getInstance("RC4");
                rc4.init(Cipher.ENCRYPT_MODE, rc4Key);
                final byte[] ct1 = rc4.doFinal(pt);
                send("bob", ct1);

                //AES in CBC mode
                final Cipher aesCbc = Cipher.getInstance("AES/CBC/PKCS5Padding");
                final byte[] iv2 = new byte[16];
                random.nextBytes(iv2);
                aesCbc.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv2));
                final byte[] ct2 = aesCbc.doFinal(pt);
                send("bob", ct2);
                send("bob", iv2);

                //AES in CTR mode
                final Cipher aesCtr = Cipher.getInstance("AES/CTR/NoPadding");
                final byte[] iv3 = new byte[16];
                random.nextBytes(iv3);
                aesCtr.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv3));
                final byte[] ct3 = aesCtr.doFinal(pt);
                send("bob", ct3);
                send("bob", iv3);

                //ChaCha20
                final Cipher chacha20 = Cipher.getInstance("ChaCha20");
                final byte[] iv4 = new byte[12];
                random.nextBytes(iv4);
                chacha20.init(Cipher.ENCRYPT_MODE, chaCha20Key, new ChaCha20ParameterSpec(iv4, 0));
                final byte[] ct4 = chacha20.doFinal(pt);
                send("bob", ct4);
                send("bob", iv4);
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                //RC4
                final Cipher rc4 = Cipher.getInstance("RC4");
                final byte[] ct1 = receive("alice");
                rc4.init(Cipher.DECRYPT_MODE, rc4Key);
                final byte[] pt1 = rc4.doFinal(ct1);
                print(new String(pt1));

                //AES in CBC mode
                final Cipher aesCbc = Cipher.getInstance("AES/CBC/PKCS5Padding");
                final byte[] ct2 = receive("alice");
                final byte[] iv2 = receive("alice");
                aesCbc.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv2));
                final byte[] pt2 = aesCbc.doFinal(ct2);
                print(new String(pt2));

                //AES in CTR mode
                final Cipher aesCtr = Cipher.getInstance("AES/CTR/NoPadding");
                final byte[] ct3 = receive("alice");
                final byte[] iv3 = receive("alice");
                aesCtr.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv3));
                final byte[] pt3 = aesCtr.doFinal(ct3);
                print(new String(pt3));

                //ChaCha20
                final Cipher chacha20 = Cipher.getInstance("ChaCha20");
                final byte[] ct4 = receive("alice");
                final byte[] iv4 = receive("alice");
                chacha20.init(Cipher.DECRYPT_MODE, chaCha20Key, new ChaCha20ParameterSpec(iv4, 0));
                final byte[] pt4 = chacha20.doFinal(ct4);
                print(new String(pt4));
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
