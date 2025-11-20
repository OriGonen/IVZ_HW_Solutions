package isp;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;

// NAME: Ori Gonen
/**
 * TASK:
 * We want to send a large chunk of data from Alice to Bob while maintaining its integrity and considering
 * the limitations of communication channels -- we have three such channels:
 * - Alice to Bob: an insecure channel, but has high bandwidth and can thus transfer large files
 * - Alice to Public Space: a secure channel, but has low bandwidth and can only transfer small amounts of data
 * - Bob to Public Space: a secure channel, but has low bandwidth and can only transfer small amounts of data
 * <p>
 * The plan is to make use of the public-space technique:
 * - Alice creates the data and computes its digest
 * - Alice sends the data to Bob, and sends the encrypted digest to Public Space
 * - Channel between Alice and Public space is secured with ChaCha20-Poly1305 (Alice and Public space share
 * a ChaCha20 key)
 * - Public space forwards the digest to Bob
 * - The channel between Public Space and Bob is secured but with AES in GCM mode (Bob and Public space share
 * an AES key)
 * - Bob receives the data from Alice and the digest from Public space
 * - Bob computes the digest over the received data and compares it to the received digest
 * <p>
 * Further instructions are given below.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A2AgentCommunicationPublicSpace {
    public static void main(String[] args) throws Exception {
        final Environment env = new Environment();

        // Create a ChaCha20 key that is used by Alice and the public-space
        final SecretKey alice_key = KeyGenerator.getInstance("ChaCha20").generateKey();
        // Create an AES key that is used by Bob and the public-space
        final SecretKey bob_key = KeyGenerator.getInstance("AES").generateKey();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                // a payload of 200 MB
                final byte[] data = new byte[200 * 1024 * 1024];
                new SecureRandom().nextBytes(data);

                // Alice sends the data directly to Bob
                send("bob", data);

                // The channel between Alice and Bob is not secured
                // Alice then computes the digest of the data and sends the digest to public-space
                final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
                final byte[] digest = digestAlgorithm.digest(data);
                // The channel between Alice and the public-space is secured with ChaCha20-Poly1305
                // Use the key that you have created above.
                final Cipher alice = Cipher.getInstance("ChaCha20-Poly1305");
                alice.init(Cipher.ENCRYPT_MODE, alice_key);
                final byte[] ct = alice.doFinal(digest);
                final byte[] iv = alice.getIV();
                send("public-space", iv);
                send("public-space", ct);
            }
        });

        env.add(new Agent("public-space") {
            @Override
            public void task() throws Exception {
                // Receive the encrypted digest from Alice and decrypt ChaCha20 and
                // the key that you share with Alice
                final Cipher from_alice = Cipher.getInstance("ChaCha20-Poly1305");
                final byte[] iv_alice = receive("alice");
                final byte[] ct_alice = receive("alice");
                final IvParameterSpec specs = new IvParameterSpec(iv_alice);
                from_alice.init(Cipher.DECRYPT_MODE, alice_key, specs);
                final byte[] digest = from_alice.doFinal(ct_alice);


                // Encrypt the digest with AES-GCM and the key that you share with Bob and
                // send the encrypted digest to Bob
                final Cipher to_bob = Cipher.getInstance("AES/GCM/NoPadding");
                to_bob.init(Cipher.ENCRYPT_MODE, bob_key);
                final byte[] iv_bob = to_bob.getIV();
                final byte[] ct_bob = to_bob.doFinal(digest);
                send("bob",  iv_bob);
                send("bob",  ct_bob);

            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                // Receive the data from Alice and compute the digest over it using SHA-256
                final byte[] data = receive("alice");
                final MessageDigest digestAlgorithm = MessageDigest.getInstance("SHA-256");
                final byte[] computed_digest = digestAlgorithm.digest(data);

                // Receive the encrypted digest from the public-space, decrypt it using AES-GCM
                // and the key that Bob shares with the public-space
                final byte[] iv = receive("public-space");
                final byte[] ct = receive("public-space");
                final Cipher bob = Cipher.getInstance("AES/GCM/NoPadding");
                final GCMParameterSpec specs = new GCMParameterSpec(128, iv);
                bob.init(Cipher.DECRYPT_MODE, bob_key, specs);
                final byte[] received_digest = bob.doFinal(ct);


                // Compare the computed digest and the received digest and print the string
                // "data valid" if the verification succeeds, otherwise print "data invalid"
                System.out.println("Computed digest: " + Agent.hex(computed_digest));
                System.out.println("Received digest: " + Agent.hex(received_digest));

                final boolean flag = MessageDigest.isEqual(computed_digest, received_digest);

                if (flag) {
                    System.out.println("data valid");
                }
                else {
                    System.out.println("data invalid");
                }


            }
        });

        env.connect("alice", "bob");
        env.connect("alice", "public-space");
        env.connect("public-space", "bob");
        env.start();
    }
}
