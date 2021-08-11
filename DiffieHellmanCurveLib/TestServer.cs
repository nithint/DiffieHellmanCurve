using Sodium;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace DiffieHellmanCurveLib
{
    /// <summary>
    /// Exposes a single method where you can retrieve an encrypted secret message, given a client x25519 public key.
    /// </summary>
    /// <remarks>
    /// TODO: Server private key is loaded directly into memory and is not secure. 
    /// </remarks>
    public class TestServer
    {
        const string MESSAGE = "this is a test link to https://www.google.com";
        const string SERVER_KEY_FILE = "testserver.key.pem";

        private readonly byte[] ServerPrivateKey = new byte[32];
        private KeyPair ServerKeyPair { get; }

        public TestServer()
        {
            var key = Convert.FromBase64String(File.ReadAllText(SERVER_KEY_FILE));

            // Copy only the last 32 bytes as that is the key.
            // https://stackoverflow.com/questions/58191402/parse-curve25519-keys-generated-using-openssl-in-go
            Array.ConstrainedCopy(key, key.Length - ServerPrivateKey.Length, ServerPrivateKey, 0, ServerPrivateKey.Length);
            ServerKeyPair = PublicKeyBox.GenerateKeyPair(ServerPrivateKey);
        }

        /// <summary>
        /// Performs a DH key exchange with the given client public key. The shared secret is then used as a key to 
        /// AES-CBC with a random IV to encrypt a message. The response consists of the public key of server, encrypted message and iv
        /// all encoded in Base-64.
        /// </summary>
        /// <param name="publicKey">Base-64 encoded client x25519 public key.</param>
        /// <returns>
        /// ServerResponse containing the following
        /// - Server's x25519 public key 
        /// - Encrypted message
        /// - Initialization vector used with the AES-CBC algorithm to generate the encrypted message.
        /// </returns>
        /// <remarks>
        /// With the response parameters, client should be able to peform DH key exchange and decrypt the original message.
        /// </remarks>
        public DHServerResponse GetMessage(string publicKey)
        {
            var clientPublicKeyBytes = Convert.FromBase64String(publicKey);
            var dhSecretKey = ScalarMult.Mult(ServerKeyPair.PrivateKey, clientPublicKeyBytes);

            using (var aes = new AesCbcUtil(dhSecretKey))
            {
                var iv = aes.GenerateIV();
                var encryptedMessage = aes.Encrypt(MESSAGE, iv);
                return new DHServerResponse(Convert.ToBase64String(ServerKeyPair.PublicKey), encryptedMessage, Convert.ToBase64String(iv));
            }
        }
    }
}
