package isp.kolokvij;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class AePke {
    public static void main(String[] args) throws Exception {

        final SecretKey aesKey = KeyGenerator.getInstance("AES").generateKey();

        final SecretKey chaCha20Key = KeyGenerator.getInstance("ChaCha20").generateKey();

        final KeyPair aliceKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        final KeyPair bobKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String message = "Hi Bob, this is Alice.";
                final byte[] pt = message.getBytes(StandardCharsets.UTF_8);

                //AES in GCM mode
                final Cipher aesGCM = Cipher.getInstance("AES/GCM/NoPadding");
                aesGCM.init(Cipher.ENCRYPT_MODE, aesKey);
                final byte[] iv1 = aesGCM.getIV();
                final byte[] ct1 = aesGCM.doFinal(pt);
                send("bob", ct1);
                send("bob", iv1);

                //RSA
                final Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
                rsa.init(Cipher.ENCRYPT_MODE, bobKP.getPublic());
                final byte[] ct2 = rsa.doFinal(pt);
                send("bob", ct2);

                //ChaCha20
                final Cipher chacha20 = Cipher.getInstance("ChaCha20-Poly1305");
                chacha20.init(Cipher.ENCRYPT_MODE, chaCha20Key);
                final byte[] iv3 = chacha20.getIV();
                final byte[] ct3 = chacha20.doFinal(pt);
                send("bob", ct3);
                send("bob", iv3);
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {

                //AES in GCM mode
                final Cipher aesGCM = Cipher.getInstance("AES/GCM/NoPadding");
                final byte[] ct1 = receive("alice");
                final byte[] iv1 = receive("alice");
                aesGCM.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, iv1));
                final byte[] pt1 = aesGCM.doFinal(ct1);
                print(new String(pt1));

                //RSA
                final Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
                final byte[] ct2 = receive("alice");
                rsa.init(Cipher.DECRYPT_MODE, bobKP.getPrivate());
                final byte[] pt2 = rsa.doFinal(ct2);
                print(new String(pt2));

                //ChaCha20
                final Cipher chacha20 = Cipher.getInstance("ChaCha20-Poly1305");
                final byte[] ct3 = receive("alice");
                final byte[] iv3 = receive("alice");
                chacha20.init(Cipher.DECRYPT_MODE, chaCha20Key, new IvParameterSpec(iv3));
                final byte[] pt3 = chacha20.doFinal(ct3);
                print(new String(pt3));
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
