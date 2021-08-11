using Newtonsoft.Json;
using Sodium;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace DiffieHellmanCurveLib
{
    public class TestClient
    {
        const string CLIENT_KEY_FILE = "testclient.key.pem";

        private KeyPair ClientKeyPair { get; }

        public TestClient()
        {
            var key = Convert.FromBase64String(File.ReadAllText(CLIENT_KEY_FILE));

            byte[] clientPrivateKey = new byte[32];

            // Copy only the last 32 bytes as that is the key.
            // https://stackoverflow.com/questions/58191402/parse-curve25519-keys-generated-using-openssl-in-go
            Array.ConstrainedCopy(key, key.Length - clientPrivateKey.Length, clientPrivateKey, 0, clientPrivateKey.Length);
            ClientKeyPair = PublicKeyBox.GenerateKeyPair(clientPrivateKey);
        }

        /// <summary>
        /// Performs Diffie-Hellman key exchange with server using x25519 certs and retrieves an encrypted message.
        /// The encrypted message is then decrypted using the DH shared secret as key into AES-CBC and the plaintext message is returned.
        /// </summary>
        /// <returns>Plaintext message from server.</returns>
        /// <remarks>Runs against the local TestServer.</remarks>
        public string RetrieveMessage(TestServer server)
        {
            var response = server.GetMessage(Convert.ToBase64String(this.ClientKeyPair.PublicKey));
            return DecryptMessage(response);
        }

        /// <summary>
        /// Performs Diffie-Hellman key exchange with server using x25519 certs and retrieves an encrypted message.
        /// The encrypted message is then decrypted using the DH shared secret as key into AES-CBC and the plaintext message is returned.
        /// </summary>
        /// <returns>Plaintext message from server.</returns>
        /// <remarks>Runs against the server at url.</remarks>
         public async Task<string> RetrieveMessage(string url)
         {
            if (string.IsNullOrEmpty(url))
            {
                throw new ArgumentException(nameof(url));
            }

            HttpClient httpClient = new HttpClient();
            var content = new StringContent(Convert.ToBase64String(ClientKeyPair.PublicKey));
            DHServerResponse response = null;

            using (var responseContent = await httpClient.PostAsync(url, content))
            {
                var responseBody = await responseContent.Content.ReadAsStringAsync();
                Debug.WriteLine($"Response from DH server: \n{responseBody}");
                response = ParseJsonResponse(responseBody);
            }

            return DecryptMessage(response);
        }

        /// <summary>
        /// Deserializes the input message body into a ServerResponse object.
        /// </summary>
        /// <param name="messageBody">Json response from server.</param>
        /// <returns></returns>
        private DHServerResponse ParseJsonResponse(string messageBody)
        {
            try
            {
                Debug.WriteLine($"Deserialize message \n{messageBody}");
                return JsonConvert.DeserializeObject<DHServerResponse>(messageBody);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Failed to parse server response with error\n{ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Performs Diffie-Hellman key exchange with server using x25519 certs and retrieves an encrypted message.
        /// The encrypted message is then decrypted using the DH shared secret as key into AES-CBC and the plaintext message is returned.
        /// </summary>
        /// <param name="serverResponse">Response from server with the following items
        /// - Item1 = server public key
        /// - Item2 = encrypted message
        /// - Item3 = initialization vector
        /// </param>
        /// <returns>The plaintext message</returns>
        public string DecryptMessage(DHServerResponse response)
        {
            var serverPublicKeyBytes = Convert.FromBase64String(response.ServerPublicKey);
            var dhSecretKey = ScalarMult.Mult(ClientKeyPair.PrivateKey, serverPublicKeyBytes);

            using (var aes = new AesCbcUtil(dhSecretKey))
            {
                var originalMessage = aes.Decrypt(response.EncryptedMessage, Convert.FromBase64String(response.IV));
                return originalMessage;
            }
        }
    }
}
