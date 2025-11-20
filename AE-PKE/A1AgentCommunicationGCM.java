package isp;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
// NAME: Ori Gonen
/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key, secure the channel using a
 * AES in GCM. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A1AgentCommunicationGCM {
    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob share a secret session key that will be
         * used for AES in GCM.
         */
        final Key key = KeyGenerator.getInstance("AES").generateKey();

        final Environment env = new Environment();

        final int num_rounds = 10;

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {

                for (int i=0;i<num_rounds;i++) {
                    // send to bob
                    final String text = "I hope you get this message intact and in secret. Kisses, Alice." + i;
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);

                    System.out.printf("MSG: %s%n", text);
                    System.out.printf("PT:  %s%n", Agent.hex(pt));

                    final Cipher alice = Cipher.getInstance("AES/GCM/NoPadding");
                    alice.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] ct = alice.doFinal(pt);
                    System.out.printf("CT:  %s%n", Agent.hex(ct));

                    final byte[] iv = alice.getIV();
                    System.out.printf("IV:  %s%n", Agent.hex(iv));


                    send("bob", iv);
                    send("bob", ct);


                    // received from bob
                    final byte[] iv_received = receive("bob");
                    final byte[] ct_received = receive("bob");
                    final GCMParameterSpec specs = new GCMParameterSpec(128, iv_received);
                    alice.init(Cipher.DECRYPT_MODE, key, specs);
                    final byte[] pt_received = alice.doFinal(ct_received);

                    System.out.printf("Got MSG: %s%n", new String(pt_received, StandardCharsets.UTF_8));
                }


            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {

                for (int i=0;i<num_rounds;i++) {
                    // receive from alice
                    final byte[] iv_received = receive("alice");
                    final byte[] ct_received = receive("alice");
                    final GCMParameterSpec specs = new GCMParameterSpec(128, iv_received);
                    final Cipher bob = Cipher.getInstance("AES/GCM/NoPadding");
                    bob.init(Cipher.DECRYPT_MODE, key, specs);
                    final byte[] pt_received = bob.doFinal(ct_received);

                    System.out.printf("Bob: Got MSG: %s%n", new String(pt_received, StandardCharsets.UTF_8));

                    // send to alice
                    final String text = "Hey Alice. Cheers, Bob."+i;
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);
                    System.out.printf("MSG: %s%n", text);
                    System.out.printf("PT:  %s%n", Agent.hex(pt));


                    bob.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] ct = bob.doFinal(pt);
                    System.out.printf("CT:  %s%n", Agent.hex(ct));

                    final byte[] iv = bob.getIV();
                    System.out.printf("IV:  %s%n", Agent.hex(iv));

                    send("alice", iv);
                    send("alice", ct);
                }

            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
