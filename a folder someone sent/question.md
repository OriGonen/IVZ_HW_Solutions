# Detailed Description

The protocol contains the following steps. At the end, you’ll find a diagram that provides an overview.

1. **Alice begins by initiating the Diffie–Hellman key exchange protocol.**
   Use the Elliptic Curve variant as in the labs; a good starting point for the assignment is the `isp-keyagreement` project.

   Alice creates her secret value a and computes her public value:
   A = g^a mod p
   (While the notation might suggest the DH protocol is using arithmetic modulo prime numbers, use the Elliptic Curve variant.)

   She then sends the public value A to the server.

2. **Similarly, the server picks its own secret value b** and computes its public value:
   B = g^b mod p
   It then receives Alice’s public value A, and combines it with its own secret value to obtain the Diffie–Hellman shared secret.

   This value is immediately hashed with SHA-256, and from the result an AES symmetric key is derived:
   k = H(A^b mod p)
   Since the hash will have 32 bytes and the key only requires 16 bytes, the first 16 bytes are used as the key.

   Next, the server concatenates Alice’s public value A and its own public value B, and signs the result using RSA with SHA-256 and its secret key:
   σ = S(sk, A || B)

   While the pair (B, σ) should be sufficient to prove to Alice that the server is genuine, the server cannot be sure that Alice is really Alice — it could be someone impersonating her.

   So the server issues a password-based challenge to Alice: it picks a random 256-bit (32-byte) value chall, symmetrically encrypts it with the derived symmetric key k using AES-GCM, and sends its encrypted value:
   c_chall ← E(k, chall)
   to Alice, along with the DH public value B and the signature σ.

3. **Alice receives the messages and immediately verifies the signature σ.**
   If the signature fails to verify, the protocol is aborted.

   If the signature verifies, she computes the key k like the server:
   k = H(B^a mod p)

   She then uses AES-GCM to decrypt the challenge:
   chall ← D(k, c_chall)

   Next, she creates the response by appending the challenge chall to the password pwd and hashing the result with SHA-256:
   resp = H(pwd || chall)

   Finally, she encrypts the response:
   c_resp ← E(k, resp)
   and sends c_resp to the server. She is now done.

4. **The server receives the ciphertext c_resp** and decrypts it:
   resp ← D(k, c_resp)

   Finally, the server verifies the response: it hashes the concatenation of Alice’s password and the challenge value:
   H(pwd || chall)
   and compares the result with the decrypted response. If they match, Alice is authenticated. If not, the protocol is aborted.

If the protocol terminates successfully, both Alice and the server are authenticated, and they share a secret key k which can be used to symmetrically encrypt and authenticate data.
