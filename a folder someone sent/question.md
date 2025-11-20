The protocol contains the following steps. At the end, you’ll find a diagram that provides an overview.

Alice begins by initiating the Diffie–Hellman key exchange protocol.
Use the Elliptic Curve variant as in the labs; a good starting point for the assignment is the isp-keyagreement project.

Alice creates her secret value 
𝑎
a and computes her public value

𝐴
=
𝑔
𝑎
 
m
o
d
 
𝑝
.
A=g
a
modp.

(While the notation might suggest the DH protocol is using arithmetic modulo prime numbers, use the Elliptic Curve variant.)

She then sends the public value 
𝐴
A to the server.

Similarly, the server picks its own secret value 
𝑏
b and computes its public value

𝐵
=
𝑔
𝑏
 
m
o
d
 
𝑝
.
B=g
b
modp.

It then receives Alice’s public value 
𝐴
A, and combines it with its own secret value to obtain the Diffie–Hellman shared secret.

This value is immediately hashed with SHA-256, and from the result an AES symmetric key is derived:

𝑘
=
𝐻
(
𝐴
𝑏
 
m
o
d
 
𝑝
)
.
k=H(A
b
modp).

Since the hash will have 32 bytes and the key only requires 16 bytes, the first 16 bytes are used as the key.

Next, the server concatenates Alice’s public value 
𝐴
A and its own public value 
𝐵
B, and signs the result using RSA with SHA-256 and its secret key:

𝜎
=
𝑆
(
sk
,
𝐴
∥
𝐵
)
.
σ=S(sk,A∥B).

While the pair 
(
𝐵
,
𝜎
)
(B,σ) should be sufficient to prove to Alice that the server is genuine, the server cannot be sure that Alice is really Alice — it could be someone impersonating her.

So the server issues a password-based challenge to Alice: it picks a random 256-bit (32-byte) value 
chall
chall, symmetrically encrypts it with the derived symmetric key 
𝑘
k using AES-GCM, and sends its encrypted value

𝑐
chall
←
𝐸
(
𝑘
,
chall
)
c
chall
	​

←E(k,chall)

to Alice, along with the DH public value 
𝐵
B and the signature 
𝜎
σ.

Alice receives the messages and immediately verifies the signature 
𝜎
σ.
If the signature fails to verify, the protocol is aborted.

If the signature verifies, she computes the key 
𝑘
k like the server:

𝑘
=
𝐻
(
𝐵
𝑎
 
m
o
d
 
𝑝
)
.
k=H(B
a
modp).

She then uses AES-GCM to decrypt the challenge:

chall
←
𝐷
(
𝑘
,
𝑐
chall
)
.
chall←D(k,c
chall
	​

).

Next, she creates the response by appending the challenge 
chall
chall to the password 
pwd
pwd and hashing the result with SHA-256:

resp
=
𝐻
(
pwd
∥
chall
)
.
resp=H(pwd∥chall).

Finally, she encrypts the response

𝑐
resp
←
𝐸
(
𝑘
,
resp
)
c
resp
	​

←E(k,resp)

and sends 
𝑐
resp
c
resp
	​

 to the server. She is now done.

The server receives the ciphertext 
𝑐
resp
c
resp
	​

 and decrypts it:

resp
←
𝐷
(
𝑘
,
𝑐
resp
)
.
resp←D(k,c
resp
	​

).

Finally, the server verifies the response: it hashes the concatenation of Alice’s password and the challenge value 
𝐻
(
pwd
∥
chall
)
H(pwd∥chall), and compares the result with the decrypted response.
If they match, Alice is authenticated. If not, the protocol is aborted.

If the protocol terminates successfully, both Alice and the server are authenticated, and they share a secret key 
𝑘
k which can be used to symmetrically encrypt and authenticate data.
