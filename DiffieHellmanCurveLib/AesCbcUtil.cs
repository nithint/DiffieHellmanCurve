using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace DiffieHellmanCurveLib
{
    /// <summary>
    /// AES-CBC implementation copied from https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.aes?view=net-5.0.
    /// </summary>
    public class AesCbcUtil : IDisposable
    {
        private Aes AesAlgo { get; }

        private readonly byte[] Key;

        private bool disposedValue = false;

        public AesCbcUtil(byte[] key)
        {
            this.Key = key;
            AesAlgo = Aes.Create();
            AesAlgo.Key = this.Key;
            AesAlgo.Mode = CipherMode.CBC;
        }

        public byte[] GenerateIV()
        {
            AesAlgo.GenerateIV();
            return AesAlgo.IV;
        }

        /// <summary>
        /// Encrypt the given message using AES-CBC using the given initialization vector and return the encrypted message in Base64 form.
        /// </summary>
        /// <returns>Base-64 encoded encrypted message.</returns>
        public string Encrypt(string message, byte[] iv)
        {
            if (message == null || message.Length <= 0)
            {
                throw new ArgumentNullException("message");
            }

            if (iv == null || iv.Length <= 0)
            {
                throw new ArgumentNullException("iv");
            }

            AesAlgo.IV = iv;
            byte[] encrypted;
            ICryptoTransform encryptor = this.AesAlgo.CreateEncryptor(this.AesAlgo.Key, this.AesAlgo.IV);

            // Create the streams used for encryption.
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        //Write all data to the stream.
                        swEncrypt.Write(message);
                    }
                    encrypted = msEncrypt.ToArray();
                }
            }

            return Convert.ToBase64String(encrypted);
        }

        /// <summary>
        /// Decrypt the given message using AES-CBC using the given initialization vector and return the original plaintext message.
        /// </summary>
        /// <param name="encryptedMessage">Encrypted message in Base64 encoding.</param>
        /// <param name="iv">Initialization vector that was originally used to encrypt this message.</param>
        /// <returns>plaintext message</returns>
        public string Decrypt(string encryptedMessage, byte[] iv)
        {
            if (string.IsNullOrEmpty(encryptedMessage))
            {
                throw new ArgumentNullException("encryptedMessage");
            }

            if (iv == null || iv.Length <= 0)
            {
                throw new ArgumentNullException("iv");
            }

            this.AesAlgo.IV = iv;
            byte[] encryptedMessageBytes = Convert.FromBase64String(encryptedMessage);
            string message = null;

            // Create a decryptor to perform the stream transform.
            ICryptoTransform decryptor = this.AesAlgo.CreateDecryptor(this.AesAlgo.Key, this.AesAlgo.IV);

            // Create the streams used for decryption.
            using (MemoryStream msDecrypt = new MemoryStream(encryptedMessageBytes))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {

                        // Read the decrypted bytes from the decrypting stream
                        // and place them in a string.
                        message = srDecrypt.ReadToEnd();
                    }
                }
            }

            return message;
        }
        
        private void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    AesAlgo.Clear();
                    AesAlgo.Dispose();
                }

                disposedValue = true;
            }
        }

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

    }
}
