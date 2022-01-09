using System;
using System.Collections.Generic;
using System.Globalization;
using System.Numerics;

namespace diffie_hellman_key_exchange_client
{
    /// <summary>
    ///  Basic implementation of Diffie–Hellman key exchange algorithm
    ///  Fix --> Improved control & security: The session Id to be provided by the server instead
    /// G: Generator G
    /// P: Large Prime Number
    /// Private Key: Client Generated Private key
    /// Public Key: Client Generated Public Key
    /// Server Public Key: Server Public Key
    /// Shared Key: result of mathematics calculations on both sides [Client & Server]
    /// Action: enum => 'iv' or 'key'
    /// </summary>
    internal class DiffieHellman
    {
        private string _exchangeUrl;
        private string _sessionId;

        // Generator G
        private const int G = 9;

        // 'key' or 'iv'
        private string _action;


        /// <summary>
        /// Performs Diffie-Hellman key exchange with a backup server
        /// </summary>
        /// <param name="exchangeUrl">Key exchange service URL</param>
        /// <param name="sessionId">Session ID for the backup session</param>
        /// <param name="action">action type, valid values: 'iv' and 'pub'.
        /// 'iv' for key size of 64-bit
        /// 'pub' for key size of 128-bit
        /// server returns </param>
        /// <returns>128-bit Shared key with the public server.</returns>
        public string GetKey(string exchangeUrl, string sessionId, string action)
        {
            _exchangeUrl = exchangeUrl;
            _sessionId = sessionId;
            _action = action;
            // Valid actions: 'key', 'iv'

            Console.WriteLine($"[*] Action: Exchanging AES {action.ToUpper()}");

            var p = GetRandomPrime(new Random());
            Console.WriteLine($"[*] Using the Prime Number: {p}");
            Console.WriteLine();

            var privateKey = GeneratePrivateKey();
            Console.WriteLine($"[+] Generated a Private Key: {privateKey}");
            Console.WriteLine();

            var publicKey = G ^ privateKey % p;
            Console.WriteLine($"[+] Generated a Public Key: {publicKey}");
            Console.WriteLine();

            Console.WriteLine("[*] Requesting Server Public Key...");
            var serverPublicKey = BigInteger.Parse(Post(p, G, publicKey));
            Console.WriteLine($"[+] Got server public key: {serverPublicKey}");
            Console.WriteLine();

            Console.WriteLine("[*] Calculating the secret message..");
            var sharedKey = BigInteger.Abs(serverPublicKey ^ privateKey % p);

            var sharedKeyStr = Helpers.Md5(sharedKey.ToString());
            Console.WriteLine($"[+] Shared Secret: {sharedKeyStr}");
            Console.WriteLine();
            Console.WriteLine();
            if (action == "iv") sharedKeyStr = sharedKeyStr.Substring(sharedKeyStr.Length - 16);
            return sharedKeyStr.ToLower();
        }


        private BigInteger GeneratePrivateKey()
        {
            var randHash = Helpers.RandomSha256(3);
            var key = BigInteger.Parse(randHash, NumberStyles.HexNumber);
            return BigInteger.Abs(key);
        }


        // pre generated
        private readonly string[] _primes =
        {
            "0400CB2B5C6FEAA3E74C95A8EA55B560370D55775D1829D4B7159040CF8BDEAF69051694694387D4B94D63260E1BD2F6F4F040E93F1631B53599B8359D802C31774655EEF849FAA56D8BEAEC6EDBC49745741A323D52473015B0B70C4CBD54CBA98B5538B7592E220C14AA980EB35FD1E68EE94DE325177994042E5319E41D2DB0DB",
            "04008FE4930BEA96B5287EB0B6CE26D03295626AC25C393A6755580256A42A92BF8BD7C5D088A90CA1EE8E54E44ED213D208D4FCE314F72EAA3AA532D34D7FB91B033CB35CA73F875F95E48F25667705997006F8D01E4DDF41A92111993456A55137455B2AC8C6AAE9CCA7E404E987BDA6304B40CD2F629ACAE0BE8A068D9CF6181B",
            "0400BB4FC2D1303010F03005A6692E79610E9B7C543664AFEB7DABAC8068457CA42BDAB402B426E14DEE9291808A77D7F8B2A0BFF52EC9ABFA9D6A77B7104A4ACE61DA3D1F590AC94DA95CE680CBAD098650CBA598D7FFA2792F398B8DF41B47F09C75CE987C16645B9DEAE9BABEBF295EED559654430F7A42206452F7DBFA640D83",
            "0400EDD3F14001A0FD1E393B0D709481116DA93CD91A48FC8E2FC2404C43AB1ACF6108D578D837FD00C7D2747CBF5B1C2665FB9A5D4C68B89F32C7EB5A9AF2239E22E04111FCBC511A5921D3D94339B8E2C116DEF72FCE6C3CB377A2623873E5AB0632C45F2DE40AA8E7AA50E0E18A2C6C614776186BC48EEA3F1FAEAAE7D357BE7B",
        };


        private BigInteger GetRandomPrime(Random r)
        {
            var index = r.Next(_primes.Length);
            return BigInteger.Parse(_primes[index], NumberStyles.HexNumber);
        }

        private string Post(BigInteger p, int g, BigInteger pubKey)
        {
            var param = new Dictionary<string, object>
            {
                {"p", p},
                {"g",  g},
                {"k", pubKey},
                {"session_id", _sessionId},
                {"action", _action}
            };
            return Helpers.HttpPost<string>(_exchangeUrl, param, null);
        }


        public static bool IsValidKey(string key, string type)
        {
            if (type == "key")
            {
                return !string.IsNullOrEmpty(key) && key.Length == 32 && Helpers.IsHex(key);
            }
            if (type == "iv")
            {
                return !string.IsNullOrEmpty(key) && key.Length == 16 && Helpers.IsHex(key);
            }

            return false;
        }


    }
}
