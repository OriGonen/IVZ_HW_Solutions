package isp.kolokvij;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Integrity {
    public static byte[] hash(byte[] msg) throws NoSuchAlgorithmException {
        final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
        return digestAlgorithm.digest(msg);
    }



    public static void main(String[] args) throws Exception {

        final Key hmacKey = KeyGenerator.getInstance("HmacSHA256").generateKey();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String message = "Hi Bob, this is Alice.";
                final byte[] pt = message.getBytes(StandardCharsets.UTF_8);

                //HASH
                byte[] hash = hash(pt);
                send("bob", hash);

                //HMAC
                final Mac hmac = Mac.getInstance("HmacSHA256");
                hmac.init(hmacKey);
                final byte[] tag = hmac.doFinal(pt);
                send("bob", pt);
                send("bob", tag);
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                final String message = "Hi Bob, this is Alice.";
                final byte[] pt = message.getBytes(StandardCharsets.UTF_8);

                //HASH
                final byte[] hash1 = receive("alice");
                final byte[] hash2 = hash(pt);

                if (MessageDigest.isEqual(hash1, hash2)) {
                    print(new String(pt));
                } else {
                    print("INVALID");
                }

                //HMAC
                final Mac hmac = Mac.getInstance("HmacSHA256");
                hmac.init(hmacKey);
                final byte[] pt1 = receive("alice");
                final byte[] tag1 = receive("alice");
                final byte[] tag2 = hmac.doFinal(pt);

                if (MessageDigest.isEqual(tag1, tag2)) {
                    print(new String(pt1));
                } else {
                    print("INVALID");
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
