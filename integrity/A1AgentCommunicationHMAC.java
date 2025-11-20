package isp.integrity;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.util.Arrays;
// name: Ori Gonen
/**
 * TASK:
 * Assuming Alice and Bob know a shared secret key, provide integrity to the channel
 * using HMAC implemted with SHA256. Then exchange ten messages between Alice and Bob.
 * <p>
 * https://docs.oracle.com/en/java/javase/11/docs/api/java.base/javax/crypto/Cipher.html
 */
public class A1AgentCommunicationHMAC {
    public static void main(String[] args) throws Exception {
        /*
         * Alice and Bob share a secret session key that will be
         * used for hash based message authentication code.
         */
        final Key key = KeyGenerator.getInstance("HmacSHA256").generateKey();

        final Environment env = new Environment();

        final int num_rounds = 10;

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {

                final Mac alice = Mac.getInstance("HmacSHA256");
                alice.init(key);

                for (int i=0;i<num_rounds;i++) {

                    // send
                    final String text = "I hope you get this message intact. Kisses, Alice. " + i;
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);
                    send("bob", pt);
                    final byte[] tag = alice.doFinal(text.getBytes(StandardCharsets.UTF_8));
                    send("bob", tag);
                    // end send

                    // receive
                    final byte[] msg = receive("bob");
                    final byte[] received_tag = receive("bob");
                    final byte[] computed_tag = alice.doFinal(msg);

                    System.out.println("ALICE: received msg " + Agent.hex(msg));
                    System.out.println("ALICE: received tag " + Agent.hex(received_tag));
                    System.out.println("ALICE: computed tag " + Agent.hex(computed_tag));

                    // compare tags
                    if (!MessageDigest.isEqual(received_tag, computed_tag)) {
                        // this shouldn't happen
                        System.out.println("Bob's tag is NOT valid");
                    }
                    else {
                        System.out.println("Bob's tag is valid!");
                    }
                    // end receive
                }



            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {

                final Mac bob = Mac.getInstance("HmacSHA256");
                bob.init(key);

                for (int i=0;i<num_rounds;i++) {

                    // receive
                    final byte[] msg = receive("alice");
                    final byte[] received_tag = receive("alice");
                    final byte[] computed_tag = bob.doFinal(msg);

                    System.out.println("BOB: received msg " + Agent.hex(msg));
                    System.out.println("BOB: received tag " + Agent.hex(received_tag));
                    System.out.println("BOB: computed tag " + Agent.hex(computed_tag));

                    // compare tags
                    if (!MessageDigest.isEqual(received_tag, computed_tag)) {
                        // this shouldn't happen
                        System.out.println("Alice's tag is NOT valid");
                    }
                    else {
                        System.out.println("Alice's tag is valid!");
                    }

                    // end receive

                    // send
                    final String text = "Hey Alice. Best regards, Bob. " + i;
                    final byte[] pt = text.getBytes(StandardCharsets.UTF_8);
                    send("alice", pt);
                    final byte[] tag = bob.doFinal(text.getBytes(StandardCharsets.UTF_8));
                    send("alice", tag);
                    // end send
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
