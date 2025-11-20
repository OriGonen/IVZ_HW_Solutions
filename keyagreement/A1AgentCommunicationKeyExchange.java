package isp.keyagreement;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
// NAME: Ori Gonen
/*
 * Implement a key exchange between Alice and Bob using public-key encryption.
 * Once the shared secret is established, send an encrypted message from Alice to Bob using
 * AES in GCM.
 */
public class A1AgentCommunicationKeyExchange {
    public static void main(String[] args) {
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final KeyPair aliceKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();
                final Cipher rsa = Cipher.getInstance("RSA");
                rsa.init(Cipher.DECRYPT_MODE, aliceKP.getPrivate());

                // send pk to bob
                send("bob", aliceKP.getPublic().getEncoded());
                print("sent PK: " + hex(aliceKP.getPublic().getEncoded()));

                // receive the encrypted session key from bob and decrypt it using the secret key
                final byte[] enc_session_key = receive("bob");
                final byte[] session_key = rsa.doFinal(enc_session_key);

                final SecretKeySpec aesKey = new SecretKeySpec(session_key, "AES");

                // encrypt in AES-GCM
                final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                aes.init(Cipher.ENCRYPT_MODE, aesKey);

                // encrypt a message using AER GCM
                final byte[] ct = aes.doFinal("Hey Bob!".getBytes(StandardCharsets.UTF_8));
                final byte[] iv = aes.getIV();

                send("bob", iv);
                send("bob", ct);
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                // get PK from alice
                final byte[] alicePK_bytes = receive("alice");
                final KeyFactory kf = KeyFactory.getInstance("RSA");
                final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(alicePK_bytes);
                final PublicKey alicePK = kf.generatePublic(keySpec);


                final Cipher rsa = Cipher.getInstance("RSA");
                rsa.init(Cipher.ENCRYPT_MODE, alicePK);

                final Key session_key = KeyGenerator.getInstance("AES").generateKey();
                final byte[] enc_session_key = rsa.doFinal(session_key.getEncoded());

                // send encrypted session key
                send("alice", enc_session_key);


                final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                final byte[] iv = receive("alice");
                final byte[] ct = receive("alice");
                aes.init(Cipher.DECRYPT_MODE, session_key, new GCMParameterSpec(128, iv));
                final byte[] pt = aes.doFinal(ct);

                print("I got: %s", new String(pt, StandardCharsets.UTF_8));
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}