package isp.kolokvij;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;

public class Keyagreement {
    public static void main(String[] args) throws NoSuchAlgorithmException {

        final String signingAlgorithm = "SHA256withRSA"; //"SHA256withDSA" "SHA256withECDSA"
        final String keyAlgorithm = "RSA"; //"DSA" "EC"
        final KeyPair keyRSA = KeyPairGenerator.getInstance(keyAlgorithm).generateKeyPair();

        final KeyPair keyRSAPSS = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                final String document = "We would like to sign this.";

                //DH ("PK": A = g^a, "SK": a)
                final KeyPairGenerator kpgDH = KeyPairGenerator.getInstance("DH");
                kpgDH.initialize(2048);
                final KeyPair keyPairDH = kpgDH.generateKeyPair();
                send("bob", keyPairDH.getPublic().getEncoded());

                final X509EncodedKeySpec keySpecDH = new X509EncodedKeySpec(receive("bob"));
                final DHPublicKey bobPKDH = (DHPublicKey) KeyFactory.getInstance("DH").generatePublic(keySpecDH);
                final KeyAgreement dh = KeyAgreement.getInstance("DH");
                dh.init(keyPairDH.getPrivate());
                dh.doPhase(bobPKDH, true);
                final byte[] sharedSecret1 = dh.generateSecret();

                final SecretKeySpec aesKey1 = new SecretKeySpec(sharedSecret1, 0, 16, "AES");
                print(hex(aesKey1.getEncoded()));

                //ECDH
                final KeyPairGenerator kpgEC = KeyPairGenerator.getInstance("EC");
                kpgEC.initialize(256);
                final KeyPair keyPairEC = kpgEC.generateKeyPair();
                send("bob", keyPairEC.getPublic().getEncoded());

                final X509EncodedKeySpec keySpecEC = new X509EncodedKeySpec(receive("bob"));
                final ECPublicKey bobPKEC = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(keySpecEC);
                final KeyAgreement ec = KeyAgreement.getInstance("ECDH");
                ec.init(keyPairEC.getPrivate());
                ec.doPhase(bobPKEC, true);
                final byte[] sharedSecret2 = ec.generateSecret();

                final SecretKeySpec aesKey2 = new SecretKeySpec(sharedSecret2, 0, 16, "AES");
                print(hex(aesKey2.getEncoded()));

                //Signature RSA
                final Signature signerRSA = Signature.getInstance(signingAlgorithm);
                signerRSA.initSign(keyRSA.getPrivate());
                signerRSA.update(document.getBytes(StandardCharsets.UTF_8));
                final byte[] signatureRSA = signerRSA.sign();
                send("bob", document.getBytes(StandardCharsets.UTF_8));
                send("bob", signatureRSA);

                //Signature RSAPSS
                final Signature signerRSAPSS = Signature.getInstance("RSASSA-PSS");
                signerRSAPSS.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
                signerRSAPSS.initSign(keyRSAPSS.getPrivate());
                signerRSAPSS.update(document.getBytes(StandardCharsets.UTF_8));
                final byte[] signatureRSAPSS = signerRSAPSS.sign();
                send("bob", document.getBytes(StandardCharsets.UTF_8));
                send("bob", signatureRSAPSS);
            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {

                //DH
                final X509EncodedKeySpec keySpecDH = new X509EncodedKeySpec(receive("alice"));
                final DHPublicKey alicePKDH = (DHPublicKey) KeyFactory.getInstance("DH").generatePublic(keySpecDH);
                final DHParameterSpec dhParamSpec = alicePKDH.getParams();
                final KeyPairGenerator kpgDH = KeyPairGenerator.getInstance("DH");
                kpgDH.initialize(dhParamSpec);
                final KeyPair keyPairDH = kpgDH.generateKeyPair();
                send("alice", keyPairDH.getPublic().getEncoded());

                final KeyAgreement dh = KeyAgreement.getInstance("DH");
                dh.init(keyPairDH.getPrivate());
                dh.doPhase(alicePKDH, true);
                final byte[] sharedSecret1 = dh.generateSecret();

                final SecretKeySpec aesKey1 = new SecretKeySpec(sharedSecret1, 0, 16, "AES");
                print(hex(aesKey1.getEncoded()));

                //ECDH
                final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(receive("alice"));
                final ECPublicKey alicePKEC = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(keySpec);
                final ECParameterSpec ecParamSpec = alicePKEC.getParams();
                final KeyPairGenerator kpgEC = KeyPairGenerator.getInstance("EC");
                kpgEC.initialize(ecParamSpec);
                final KeyPair keyPairEC = kpgEC.generateKeyPair();
                send("alice", keyPairEC.getPublic().getEncoded());

                final KeyAgreement ec = KeyAgreement.getInstance("ECDH");
                ec.init(keyPairEC.getPrivate());
                ec.doPhase(alicePKEC, true);
                final byte[] sharedSecret2 = ec.generateSecret();

                final SecretKeySpec aesKey2 = new SecretKeySpec(sharedSecret2, 0, 16, "AES");
                print(hex(aesKey2.getEncoded()));

                //Signature RSA
                final byte[] document1 = receive("alice");
                final byte[] signatureRSA = receive("alice");
                final Signature verifierRSA = Signature.getInstance(signingAlgorithm);
                verifierRSA.initVerify(keyRSA.getPublic());
                verifierRSA.update(document1);

                if (verifierRSA.verify(signatureRSA)) {
                    print(new String(document1));
                } else {
                    print("INVALID");
                }

                //Signature RSAPSS
                final byte[] document2 = receive("alice");
                final byte[] signatureRSAPSS = receive("alice");
                final Signature verifierRSAPSS = Signature.getInstance("RSASSA-PSS");
                verifierRSAPSS.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
                verifierRSAPSS.initVerify(keyRSAPSS.getPublic());
                verifierRSAPSS.update(document2);

                if (verifierRSAPSS.verify(signatureRSAPSS)) {
                    print(new String(document2));
                } else {
                    print("INVALID");
                }
            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
