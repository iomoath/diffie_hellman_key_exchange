using System;
using System.Security.Cryptography;
using System.Text;

namespace diffie_hellman_key_exchange_client
{
    internal static class AesUtils
    {
        public static string AES_encrypt(string input, string key, string iv)
        {
            byte[] byteData;
            using (var aesProvider = CreateAesProvider())
            {
                var byteText = Encoding.UTF8.GetBytes(input);

                aesProvider.Key = GetBytes(key, 32);
                aesProvider.IV = GetBytes(iv, 16);

                byteData = aesProvider.CreateEncryptor().TransformFinalBlock(byteText, 0, byteText.Length);
            }
            return ToBase64String(byteData);
        }

        public static string AES_decrypt(string input, string key, string iv)
        {
            byte[] byteText;
            using (var aesProvider = CreateAesProvider())
            {
                var byteData = FromBase64String(input);
                aesProvider.Key = GetBytes(key, 32);
                aesProvider.IV = GetBytes(iv, 16);

                byteText = aesProvider.CreateDecryptor().TransformFinalBlock(byteData, 0, byteData.Length);
            }

            return Encoding.UTF8.GetString(byteText);
        }

        /// <summary>
        /// Item1: Key
        /// Item2: IV
        /// </summary>
        public static Tuple<string, string> GenerateAesKeys()
        {
            var rand = Guid.NewGuid().ToString() + DateTime.Now.Ticks;
            rand = Helpers.Sha256(rand);

            var key = rand.Substring(0, 32);

            rand = Guid.NewGuid().ToString() + DateTime.Now.Ticks;
            rand = Helpers.Sha256(rand);

            var iv = rand.Substring(0, 16);

            return Tuple.Create(key, iv);
        }


        public static string RSA_Encrypt(string plainText, string publicKey)
        {
            // Our bytearray to hold all of our data after the encryption
            byte[] encryptedBytes;

            using (var rsa = new RSACryptoServiceProvider())
            {
                try
                {
                    // Create a new instance of RSACryptoServiceProvider.
                    var encoder = new UTF8Encoding();

                    var encryptThis = encoder.GetBytes(plainText);

                    // Import the public key
                    rsa.FromXmlString(publicKey);

                    var blockSize = (rsa.KeySize / 8) - 32;

                    // buffer to write byte sequence of the given block_size
                    var buffer = new byte[blockSize];

                    // Initializing our encryptedBytes array to a suitable size, depending on the size of data to be encrypted
                    encryptedBytes = new byte[encryptThis.Length + blockSize - (encryptThis.Length % blockSize) + 32];

                    for (var i = 0; i < encryptThis.Length; i += blockSize)
                    {
                        // If there is extra info to be parsed, but not enough to fill out a complete bytearray, fit array for last bit of data
                        if (2 * i > encryptThis.Length && ((encryptThis.Length - i) % blockSize != 0))
                        {
                            buffer = new byte[encryptThis.Length - i];
                            blockSize = encryptThis.Length - i;
                        }

                        // If the amount of bytes we need to decrypt isn't enough to fill out a block, only decrypt part of it
                        if (encryptThis.Length < blockSize)
                        {
                            buffer = new byte[encryptThis.Length];
                            blockSize = encryptThis.Length;
                        }

                        // encrypt the specified size of data, then add to final array.
                        Buffer.BlockCopy(encryptThis, i, buffer, 0, blockSize);
                        var encryptedBuffer = rsa.Encrypt(buffer, false);
                        encryptedBuffer.CopyTo(encryptedBytes, i);
                    }
                }
                catch (Exception)
                {
                    // log error
                    return null;
                }
                finally
                {
                    // Clear the RSA key container, deleting generated keys.
                    rsa.PersistKeyInCsp = false;
                }
            }

            // Convert the byteArray using Base64 and returns as an encrypted string
            return ToBase64String(encryptedBytes);
        }


        public static bool RSA_Verify(string message, string signature, string publicKey)
        {
            if (string.IsNullOrEmpty(message))
                return false;

            var b = false;
            try
            {
                var data = Encoding.UTF8.GetBytes(message);
                var signatureBytes = FromBase64String(signature);

                using (var rsa = new RSACryptoServiceProvider(4096))
                {
                    // Import public key
                    rsa.FromXmlString(publicKey);

                    b = rsa.VerifyData(data, "SHA256", signatureBytes);
                }
                return b;
            }
            catch (Exception)
            {
                //
            }
            return b;
        }


        private static AesCryptoServiceProvider CreateAesProvider()
        {
            return new AesCryptoServiceProvider
            {
                KeySize = 256,
                BlockSize = 128,
                Padding = PaddingMode.PKCS7,
                Mode = CipherMode.CBC
            };
        }

        private static byte[] GetBytes(string str, int chars)
        {
            var byteKey = Encoding.UTF8.GetBytes(str.PadRight(chars, '\0'));

            if (byteKey.Length < chars) return byteKey;
            var bytePass = new byte[chars];
            Buffer.BlockCopy(byteKey, 0, bytePass, 0, chars);
            byteKey = bytePass;

            return byteKey;
        }

        public static string ToBase64String(byte[] bytes)
        {
            var data = Convert.ToBase64String(bytes);

            data = data.Replace("/", "_");
            data = data.Replace("+", "-");
            return data;
        }


        public static byte[] FromBase64String(string base64Str)
        {
            try
            {
                if (string.IsNullOrEmpty(base64Str))
                {
                    return null;
                }
                base64Str = base64Str.Replace("_", "/");
                base64Str = base64Str.Replace("-", "+");
                return Convert.FromBase64String(base64Str);
            }
            catch (Exception)
            {
                return null;
            }
        }
    }
}
