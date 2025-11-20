package isp.signatures;

import fri.isp.Agent;
import fri.isp.Environment;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

// NAME: Ori Gonen
/*
 * Assuming Alice and Bob know each other's public key, provide integrity and non-repudiation
 * to exchanged messages with ECDSA. Then exchange ten signed messages between Alice and Bob.
 */
public class A2AgentCommunicationSignature {
    public static void main(String[] args) throws Exception {
        final Environment env = new Environment();

        final int num_rounds = 10;

        // Create key pairs, I create them here and reference them directly in the code of each agent
        // Of course, only Alice will reference aliceKP.getPrivate() and only Bob will reference bobKP.getPrivate()
        final KeyPair aliceKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        final KeyPair bobKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();


        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                // create a message, sign it,
                // and send the message, signature pair to bob
                // receive the message signature pair, verify the signature
                // repeat 10 times
                for  (int i = 0; i < num_rounds; i++) {

                    // send
                    final String msg = "Hello Bob! This is Alice sending you the message. " +i;
                    final Signature signer = Signature.getInstance("RSASSA-PSS");
                    signer.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
                    signer.initSign(aliceKP.getPrivate());
                    signer.update(msg.getBytes(StandardCharsets.UTF_8));
                    final byte[] signature = signer.sign();
                    // send message and signature
                    send("bob", msg.getBytes(StandardCharsets.UTF_8));
                    send("bob", signature);
                    print("Sending " + msg + " with signature " + Agent.hex(signature));

                    // receive
                    final byte[] pt = receive("bob");
                    final String msg_received = new String(pt, StandardCharsets.UTF_8);
                    final byte[] signature_received = receive("bob");

                    final Signature verifier = Signature.getInstance("RSASSA-PSS");
                    verifier.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
                    verifier.initVerify(bobKP.getPublic());
                    verifier.update(msg_received.getBytes(StandardCharsets.UTF_8));

                    if (verifier.verify(signature_received))
                        print("Valid signature.");
                    else
                        print("Invalid signature.");

                }
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {

                for (int i = 0; i<num_rounds;i++)
                {

                    // receive
                    final byte[] pt = receive("alice");
                    final String msg_received = new String(pt, StandardCharsets.UTF_8);
                    final byte[] signature_received = receive("alice");

                    final Signature verifier = Signature.getInstance("RSASSA-PSS");
                    verifier.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
                    verifier.initVerify(aliceKP.getPublic());
                    verifier.update(msg_received.getBytes(StandardCharsets.UTF_8));

                    if (verifier.verify(signature_received))
                        print("Valid signature.");
                    else
                        print("Invalid signature.");

                    // send
                    final String msg = "Hello Alice! This is Bob sending you the message. " + i;
                    final Signature signer = Signature.getInstance("RSASSA-PSS");
                    signer.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
                    signer.initSign(bobKP.getPrivate());
                    signer.update(msg.getBytes(StandardCharsets.UTF_8));
                    final byte[] signature = signer.sign();
                    // send message and signature
                    send("alice", msg.getBytes(StandardCharsets.UTF_8));
                    send("alice", signature);
                    print("Sending " + msg + " with signature " + Agent.hex(signature));
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}