package isp;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;


// NAME: Ori Gonen
public class A3AgentCommunicationRSA {
    public static void main(String[] args) throws Exception {

        // note: since only alice sends to bob (and bob doesn't send anything back),
        // there's no reason to generate a key pair for alice
        final KeyPair aliceKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        final KeyPair bobKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                /*
                - Create an RSA cipher and encrypt a message using Bob's PK;
                - Send the CT to Bob;
                - Reference the keys by using global variables aliceKP and bobKP.
                 */
                final String message = "Hey Bob. Love, Alice";
                final byte[] pt = message.getBytes(StandardCharsets.UTF_8);
                System.out.println("Message: " + message);
                System.out.println("PT: " + Agent.hex(pt));
                final Cipher rsa = Cipher.getInstance("RSA");
                rsa.init(Cipher.ENCRYPT_MODE, bobKP.getPublic());
                final byte[] ct = rsa.doFinal(pt);
                send("bob", ct);
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                /*
                - Take the incoming message from the queue;
                - Create an RSA cipher and decrypt incoming CT using Bob's SK;
                - Print the message;
                - Reference the keys by using global variables aliceKP and bobKP.
                 */
                final byte[] ct = receive("alice");

                final Cipher rsa = Cipher.getInstance("RSA");
                rsa.init(Cipher.DECRYPT_MODE, bobKP.getPrivate());

                final byte[] pt = rsa.doFinal(ct);

                final String message = new String(pt, StandardCharsets.UTF_8);
                System.out.println("Received PT: " + Agent.hex(pt));
                System.out.println("Received Message: " + message);
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
