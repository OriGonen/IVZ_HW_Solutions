package isp.keyagreement;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;

//import everything
//import java.security.*;


public class example_solution {

    public static String hex(byte[] bytes) {
        final char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {


        final Environment env = new Environment();

        // alice has only access to pk
        final KeyPair serverRSA = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        // shared password
        final String pwd = "qwertyuiop";

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                // 1.
                // generate alice keypair
                final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                kpg.initialize(256);
                final KeyPair keyPair = kpg.generateKeyPair();
                // send A to server
                send("server", keyPair.getPublic().getEncoded());

                // 2. get server PK and generate secret
                final byte[] serverPublicBytes = receive("server");

                final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(serverPublicBytes);
                final ECPublicKey serverPK = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(keySpec);

                final KeyAgreement dh = KeyAgreement.getInstance("ECDH");
                dh.init(keyPair.getPrivate());
                dh.doPhase(serverPK, true);
                final byte[] sharedSecret = dh.generateSecret();
                print("Shared secret: \t%s", hex(sharedSecret));

                // hash it and get aesKey
                MessageDigest sha = MessageDigest.getInstance("SHA-256");
                byte[] hashed_secret = sha.digest(sharedSecret);
                final SecretKeySpec aesKey = new SecretKeySpec(hashed_secret, 0, 16, "AES");

                // receive signature
                final byte[] signature = receive("server");
                //verify
                final Signature verifier = Signature.getInstance("SHA256withRSA");
                verifier.initVerify(serverRSA.getPublic());

                byte[] a = keyPair.getPublic().getEncoded(), b = serverPublicBytes;
//                alicePK.getEncoded() = alicePublicBytes
                byte[] c = new byte[a.length + b.length];
                System.arraycopy(a, 0, c, 0, a.length);
                System.arraycopy(b, 0, c, a.length, b.length);

                verifier.update(c);

                print("\t\t" + Agent.hex(c));

                if (verifier.verify(signature)) {
                    print("Signature verified.");
                }
                else {
                    print("Signature not verified. ABORTING");
                    int error_maker = 1 / 0;
                }

                // decrypt
                final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                final byte[] iv = receive("server");
                final byte[] c_chall = receive("server");
                aes.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));
                final byte[] chall = aes.doFinal(c_chall);

                byte[] pwd_bytes = pwd.getBytes(StandardCharsets.UTF_8);
                byte[] pwd_chall = new byte[pwd_bytes.length+chall.length];
                System.arraycopy(pwd_bytes, 0, pwd_chall, 0, pwd_bytes.length);
                System.arraycopy(chall, 0, pwd_chall, pwd_bytes.length, chall.length);

                byte[] resp = sha.digest(pwd_chall);
                aes.init(Cipher.ENCRYPT_MODE, aesKey);
                final byte[] c_resp = aes.doFinal(resp);
                final byte[] iv_send = aes.getIV();

                send("server", iv_send);
                send("server", c_resp);
                print("\t\t"+Agent.hex(iv_send));



            }
        });

        env.add(new Agent("server") {
            @Override
            public void task() throws Exception {
                // 1. receive A from alice
                final byte[] alicePublicBytes = receive("alice");

                final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(alicePublicBytes);
                final ECPublicKey alicePK = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(keySpec);

                // 2. create server key pair
                final ECParameterSpec dhParamSpec = alicePK.getParams();
                final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                kpg.initialize(dhParamSpec);
                final KeyPair keyPair = kpg.generateKeyPair();
                send("alice", keyPair.getPublic().getEncoded());

                // shared secret
                final KeyAgreement dh = KeyAgreement.getInstance("ECDH");
                dh.init(keyPair.getPrivate());
                dh.doPhase(alicePK, true);
                final byte[] sharedSecret = dh.generateSecret();
                print("Shared secret: \t\t%s", hex(sharedSecret));

                // hash it
                MessageDigest sha = MessageDigest.getInstance("SHA-256");
                byte[] hashed_secret = sha.digest(sharedSecret);
                final SecretKeySpec aesKey = new SecretKeySpec(hashed_secret, 0, 16, "AES");

                // concatenate
//                maybe also  hex(a.getBytes()) + hex(b.getBytes()) works
                byte[] b = keyPair.getPublic().getEncoded(), a = alicePK.getEncoded();
//                alicePK.getEncoded() = alicePublicBytes
                byte[] c = new byte[a.length + b.length];
                System.arraycopy(a, 0, c, 0, a.length);
                System.arraycopy(b, 0, c, a.length, b.length);


                // now sign
                final Signature signer = Signature.getInstance("SHA256withRSA");
                signer.initSign(serverRSA.getPrivate());
                signer.update(c);
                final byte[] signature = signer.sign();
                // and send the signature
                send("alice", signature);
                print("\t\t" + Agent.hex(c));

                // password-based challenge
                SecureRandom rnd = new SecureRandom();
                byte[] chall = new byte[32];
                rnd.nextBytes(chall);

                final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                aes.init(Cipher.ENCRYPT_MODE, aesKey);
                final byte[] c_chall = aes.doFinal(chall);
                final byte[] iv = aes.getIV();

                send("alice", iv);
                send("alice", c_chall);

                // 4
                final byte[] iv_resp = receive("alice");
                final byte[] c_resp = receive("alice");

                aes.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, iv_resp));
                final byte[] received_resp = aes.doFinal(c_resp);

                // now compute it ourselves to compare
                byte[] pwd_bytes = pwd.getBytes(StandardCharsets.UTF_8);
                byte[] pwd_chall = new byte[pwd_bytes.length+chall.length];
                System.arraycopy(pwd_bytes, 0, pwd_chall, 0, pwd_bytes.length);
                System.arraycopy(chall, 0, pwd_chall, pwd_bytes.length, chall.length);

                byte[] computed_resp = sha.digest(pwd_chall);

                // compare
                if (MessageDigest.isEqual(received_resp, computed_resp)) {
                    print("Authenticated! We can now communicate ...");
                }
                else {
                    print("Not Authenticated. ABORTING");
                    return;
                }


                return;

            }
        });

        env.connect("alice", "server");
        env.start();
    }
}
