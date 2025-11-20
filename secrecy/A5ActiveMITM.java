package isp.secrecy;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import fri.isp.Agent;
import fri.isp.Environment;
// STUDENT: ORI GONEN
/**
 * The goal of this assignment is to demonstrate that ciphertexts are vulnerable to modifications
 * and that in many cases these modifications have (painfully) predictable effect on the plaintext.
 * 
 * The setting. Teaching assistant David wants to send a highly confidential email to professor
 * Denis, most likely containing questions for the upcoming exam. Needless to say, you are very
 * interested in seeing the contents of that email. Luckily, a few things go your way.
 * 
 * First, David has no Internet connectivity, but your mobile phone does. So you kindly offer to
 * set-up a mobile hot-spot through which David will be able to connect to a FMTP server. (You get
 * to play the role of the man-in-the-middle!)
 * 
 * FMTP is a new kind of a mail protocol; it stands for Funny Mail Transfer Protocol, and it is a
 * simple text-based protocol. The first line denotes the email of the recipient, the second line
 * the email of the sender, the third line the subject of the email, then we have an empty line and
 * finally we have the email contents.
 * 
 * All that David’s mail client has to do to send an email, is to deliver a string like the
 * following to the FMTP server.
 * 
 * ```txt
 * recipient@somedomain.com
 * sender@anotherdomain.com
 * Subject line
 * 
 * <Email body>
 * ```
 * 
 * Any preceding or trailing spaces on any line are removed before processing. For instance, we
 * could have written the email above as follows and it would have made no difference.
 * 
 * ```txt
 *              recipient@somedomain.com            
 *         sender@anotherdomain.com            
 *          Subject line
 * 
 * <Email body>
 * ```
 * 
 * Third, David is naive enough to tell you that he’s sending the email to professor Denis.
 * So you know the contents of the first line of the plaintext.
 * 
 * Fourth, David is using AES in CTR mode. No integrity checks are in place.
 * 
 * The task. As the man-in-the-middle (MITM), modify the messages so that the FMTP server will not send the
 * email to professor Denis, but instead will forward the email to the address that you control. In
 * this exercise the address is `isp@gmail.com`.
 * 
 */
public class A5ActiveMITM {
    public static void main(String[] args) throws Exception {
        // David and FMTP server both know the same shared secret key
        final Key key = KeyGenerator.getInstance("AES").generateKey();

        final Environment env = new Environment();

        env.add(new Agent("david") {
            @Override
            public void task() throws Exception {
                final String message = "prf.denis@fri.si\n" +
                        "david@fri.si\n" +
                        "Some ideas for the exam\n\n" +
                        "Hi! Find attached <some secret stuff>!";

                final Cipher aes = Cipher.getInstance("AES/CTR/NoPadding");
                aes.init(Cipher.ENCRYPT_MODE, key);
                final byte[] ct = aes.doFinal(message.getBytes(StandardCharsets.UTF_8));
                final byte[] iv = aes.getIV();
                print("sending: '%s' (%s)", message, hex(ct));
                send("server", ct);
                send("server", iv);
            }
        });

        env.add(new Agent("student") {
            @Override
            public void task() throws Exception {
                final byte[] bytes = receive("david");
                final byte[] iv = receive("david");
                print(" IN: %s", hex(bytes));

                // As the person-in-the-middle, modify the ciphertext
                // so that the FMTP server will send the email to you
                // (Needless to say, you are not allowed to use the key
                // that is being used by david and server.)

                /**
                Solution:

                we notice that the encryption for the first line is of the form:
                 c = (prf.denis@fri.si) xor (AES(nonce))

                 and thus we modify it to be:
                 c_modified = c xor (   isp@gmail.com) xor (prf.denis@fri.si) =
                    = (prf.denis@fri.si) xor (AES(nonce)) xor (   isp@gmail.com) xor (prf.denis@fri.si) =
                    = (   isp@gmail.com) xor (AES(nonce))

                 what we did, is canceled professor Denis' address, and replaced it with my own!
                 now, c_modified will be decrypted to '   isp@gmail.com', and since the server is removing the
                 trailing spaces, it will recognize this as the address 'isp@gmail.com', which I have access to

                 note: we added 3 spaces (' ') to match the length of my mail with the prof.'s mail


                 indeed, when running the program, we see the server gets '   isp@gmail.com' in the first line!
                 **/
                final byte[] my_mail_with_spaces = "   isp@gmail.com".getBytes(StandardCharsets.UTF_8);
                final byte[] prf_mail = "prf.denis@fri.si".getBytes(StandardCharsets.UTF_8);

                // modify the received bytes (only the first 16)
                for (int i = 0; i < my_mail_with_spaces.length; i++) {
                    bytes[i] = (byte) (bytes[i] ^ my_mail_with_spaces[i] ^ prf_mail[i]);
                }


                print("OUT: %s", hex(bytes));
                send("server", bytes);
                send("server", iv);
            }
        });

        env.add(new Agent("server") {
            @Override
            public void task() throws Exception {
                final byte[] ct = receive("david");
                final byte[] iv = receive("david");
                final Cipher aes = Cipher.getInstance("AES/CTR/NoPadding");
                aes.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
                final byte[] pt = aes.doFinal(ct);
                final String message = new String(pt, StandardCharsets.UTF_8);

                print("got: '%s' (%s)", message, hex(ct));
            }
        });

        env.mitm("david", "server", "student");
        env.start();
    }
}
