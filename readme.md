# Diffie-Hellman Key Exchange Using C25519

*Diffie-Hellman* (DH) function using the elliptic curve C25519. DH is a method of securely exchanging private key information over a public channel. X25519 refers to the key exchange scheme using curve 25519 while ed25519 refers to the signature scheme. 

*Forward secrecy* - compromise of long-term keys does not allow decryption of past communication using those keys. Ie, if a man-in-the-middle saved all the previous key exchange comms and then in some future time, one of the long-term keys were to be disclosed, the past comms that were saved could not be compromised using this now disclosed secret. 
Using ephemeral session keys help alleviate this to some degree. 

*Initialization Vector* - random and unique binary sequence for block cipher modes. IV ensures that distinct ciphertexts are produced even when the same plaintext is encrypted multiple times independently using the same key material. Essentially, a nonce with a new name for this context. All modes require IV to be unique but not all require it to be random. In CBC mode, IV must be random. It also  doesn't need to be a secret itself. 

## Generating Keys 

Using OpenSSL
- Generate private key: `openssl genpkey -algorithm x25519 > testserver.key.pem`
- Get public key: `openssl pkey -in testserver.key.pem -pubout -out testserver.pubkey.pem`
    
    
## Running the Program

`x25519TestApp.exe`  
`x25519TestApp.exe -h` for help  
`x25519TestApp.exe [url]`

## Limitations
No effort was made to secure the keys in memory.

## References
1. https://en.wikipedia.org/wiki/Curve25519
2. https://www.cryptopp.com/wiki/X25519
3. https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange
4. https://blog.pinterjann.is/ed25519-certificates.html
5. http://openssl.6102.n7.nabble.com/X25519-how-to-generate-public-key-td70090.html
6. https://github.com/tabrath/libsodium-core/tree/master/src/Sodium.Core
7. https://github.com/ektrah/nsec/tree/master/src/Cryptography
8. https://cr.yp.to/ecdh.html
9. [Parse curve25519 keys generated using openssl in Go - Stack Overflow](https://stackoverflow.com/questions/58191402/parse-curve25519-keys-generated-using-openssl-in-go)
10. https://bitbeans.gitbooks.io/libsodium-net/content/advanced/scalar_multiplication.html
