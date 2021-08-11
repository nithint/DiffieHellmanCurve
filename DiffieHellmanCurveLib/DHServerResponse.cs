using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Text;

namespace DiffieHellmanCurveLib
{
    /// <summary>
    /// Wraps a response from a DH server.
    /// </summary>
    public sealed class DHServerResponse
    {
        /// <summary>
        /// Base64 encoded server x25519 public key.
        /// </summary>
        [JsonProperty(PropertyName = "publicKey")]
        public string ServerPublicKey
        {
            get; set;
        }

        /// <summary>
        /// Base64 encoded encrypted message from server.
        /// </summary>
        [JsonProperty(PropertyName = "encryptedMsg")]
        public string EncryptedMessage
        {
            get; set;
        }

        /// <summary>
        /// Base64 encoded initialization vector used by server to encrypt its message.
        /// </summary>
        [JsonProperty(PropertyName = "iv")]
        public string IV
        {
            get; set;
        }

        /// <summary>
        /// Initializes a new instance of ServerResponse with empty properties.
        /// </summary>
        public DHServerResponse()
        {
        }

        /// <summary>
        /// Initializes a new instance of ServerResponse.
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="message"></param>
        /// <param name="iv"></param>
        public DHServerResponse(string publicKey, string message, string iv)
        {
            this.ServerPublicKey = publicKey;
            this.EncryptedMessage = message;
            this.IV = iv;
        }
    }
}
