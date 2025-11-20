package isp.secrecy;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.security.SecureRandom;
// STUDENT: ORI GONEN
/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key in advance, secure the channel using
 * ChaCha20 stream cipher. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A3ChaCha20 {
    public static void main(String[] args) throws Exception {
        // STEP 1: Alice and Bob beforehand agree upon a cipher algorithm and a shared secret key
        // This key may be accessed as a global variable by both agents
        final Key key = KeyGenerator.getInstance("ChaCha20").generateKey();

        // STEP 2: Setup communication
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {

                int num_rounds = 10;

                for (int i=0;i<num_rounds;i++) {
                    // *************
                    // send to bob:
                    // *************
                    final String message = "I love you Bob. Kisses, Alice. " + i; // added i to make each msg slightly different
                    final Cipher encrypt = Cipher.getInstance("ChaCha20");

                    // send the nonce
                    final byte[] nonce_A = new byte[12];
                    SecureRandom.getInstanceStrong().nextBytes(nonce_A);
                    send("bob", nonce_A);


                    encrypt.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(nonce_A, 0));
                    final byte[] pt = message.getBytes();
                    System.out.println("ALICE:\tI sent PT: \t" + Agent.hex(pt));
                    final byte[] cipherText = encrypt.doFinal(pt);

                    // this is what an attacker would see
                    System.out.println("ALICE:\tI sent CT: \t" + Agent.hex(cipherText));

                    // send msg
                    send("bob", cipherText);

                    // ******************
                    // end of send to bob
                    // ******************

                    // ****************
                    // receive from bob
                    // ****************
                    // receive Bob's nonce
                    final byte[] nonce_B = receive("bob");

                    // receive Bob's ciphertext
                    final byte[] cipherText_B = receive("bob");

                    final Cipher decrypt = Cipher.getInstance("ChaCha20");
                    decrypt.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(nonce_B, 0));
                    final byte[] dt = decrypt.doFinal(cipherText_B);
                    System.out.println("ALICE:\tI got PT: \t" + Agent.hex(dt));

                    // ***********************
                    // end of receive from bob
                    // ***********************

                }


            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {

                int num_rounds = 10;

                for (int i=0;i<num_rounds;i++) {
                    // ******************
                    // receive from alice
                    // ******************

                    // receive Alice's nonce
                    final byte[] nonce_A = receive("alice");

                    // receive Alice's ciphertext
                    final byte[] cipherText_A = receive("alice");

                    final Cipher decrypt = Cipher.getInstance("ChaCha20");
                    decrypt.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(nonce_A, 0));
                    final byte[] dt = decrypt.doFinal(cipherText_A);
                    System.out.println("BOB:\tI got PT: \t" + Agent.hex(dt));

                    // *************************
                    // end of receive from alice
                    // *************************

                    // *************
                    // send to alice
                    // *************
                    final String message = "Goodnight Alice. Love, Bob " + i; // added i to make each msg slightly different
                    final Cipher encrypt = Cipher.getInstance("ChaCha20");


                    // send the nonce
                    final byte[] nonce_B = new byte[12];
                    SecureRandom.getInstanceStrong().nextBytes(nonce_B);
                    send("alice", nonce_B);


                    encrypt.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(nonce_B, 0));

                    final byte[] pt = message.getBytes();
                    System.out.println("BOB:\tI sent PT: \t" + Agent.hex(pt));
                    final byte[] cipherText_B = encrypt.doFinal(pt);

                    // this is what an attacker would see
                    System.out.println("BOB:\tI sent CT: \t" + Agent.hex(cipherText_B));

                    // send msg
                    send("alice", cipherText_B);

                    // ********************
                    // end of send to alice
                    // ********************

                }

            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
