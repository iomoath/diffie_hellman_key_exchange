using System;
using System.Collections.Generic;


namespace diffie_hellman_key_exchange_client
{
    /// <summary>
    ///  Fix --> Improved control & security: The session Id to be provided by the server instead
    /// </summary>
    internal class Program
    {
        private static readonly string ServerBaseUrl = "http://192.168.40.25/diffie_hellman_key_exchange_server/";
        private static string _sessionId = string.Empty;
        private static string _aesKey = string.Empty;
        private static string _aesIv = string.Empty;

        private static void Main()
        {
            Console.WriteLine("------------------------------------------------------");

            Console.WriteLine($"[*] Performing Diffie-Hellman Key Exchange with http://192.168.40.25");
            var ses = $"{Guid.NewGuid()}-{Helpers.Get_Computer_UUID()}-{Guid.NewGuid()}";
            _sessionId = Helpers.Sha256(ses);
            Console.WriteLine($"[+] Generated a Unique Client Session Identifier: {_sessionId}");
            Console.WriteLine();

            var exchangeOk = ExchangeAesKey();
            if (exchangeOk)
            {
                Console.WriteLine("------------------------------------------------------");
                Console.WriteLine("[+] Key Exchange Complete!");
                Console.WriteLine($"[+] AES Key: {_aesKey}");
                Console.WriteLine($"[+] AES IV: {_aesIv}");
            }
            else
            {
                Console.WriteLine("[-] Key Exchange Fail!");
                return;
            }
            Console.WriteLine("------------------------------------------------------");

            Console.WriteLine();
            Console.WriteLine("[*] Sending an encrypted 'HELLO!' message..");
            var helloResponse = Hello();
            Console.WriteLine($"[+] Server Response: {helloResponse}");
            Console.WriteLine("------------------------------------------------------");

            Console.Read();
        }

        private static string Hello()
        {
            var param = new Dictionary<string, object> {["data"] = AesUtils.AES_encrypt("HELLO!", _aesKey, _aesIv)};
            var headers = new Dictionary<string, string> {["SessionId"] = _sessionId};
            var result = Helpers.HttpPost<string>(ServerBaseUrl + "api.php", param, headers);
            return result;
        }

        private static bool ExchangeAesKey()
        {
            try
            {
                var exchangeUrl = ServerBaseUrl + "exchange.php";
                var dh = new DiffieHellman();
                var key = dh.GetKey(exchangeUrl, _sessionId, "key");
                var iv = dh.GetKey(exchangeUrl, _sessionId, "iv");
                if (!DiffieHellman.IsValidKey(key, "key")) return false;
                if (!DiffieHellman.IsValidKey(iv, "iv")) return false;
                _aesKey = key;
                _aesIv = iv;


                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}
