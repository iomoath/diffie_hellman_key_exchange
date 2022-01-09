using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace diffie_hellman_key_exchange_client
{
    internal static class Helpers
    {

        public static T HttpPost<T>(string url, Dictionary<string, object> parameters, Dictionary<string, string> headers)
        {
            try
            {

                using (var wb = new WebClient())
                {
                    foreach (var kvp in headers ?? new Dictionary<string, string>())
                    {
                        wb.Headers.Add(kvp.Key, kvp.Value);
                    }

                    var data = new NameValueCollection();

                    if (parameters != null)
                    {
                        foreach (var o in parameters)
                        {
                            if (o.Value == null)
                                continue;

                            data.Add(o.Key, o.Value?.ToString());
                        }
                    }

                    var responseBytes = wb.UploadValues(url, "POST", data);
                    var responseStr = Encoding.UTF8.GetString(responseBytes);
                    return (T)Convert.ChangeType(responseStr, typeof(T));
                }
            }
            catch (Exception)
            {
                return default(T);
            }
        }

        private static string EncodeBase64QueryString(string queryString)
        {
            return queryString.Replace("+", "%2B");
        }

        private static string ToQueryString(IDictionary<string, object> paramDictionary)
        {
            var list = paramDictionary.Select(item => item.Key + "=" + item.Value).ToList();
            return string.Join("&", list);
        }


        public static string Sha256(string msg)
        {
            var crypt = new SHA256Managed();
            var hash = string.Empty;
            var crypto = crypt.ComputeHash(Encoding.Unicode.GetBytes(msg), 0, Encoding.Unicode.GetByteCount(msg));
            return crypto.Aggregate(hash, (current, theByte) => current + theByte.ToString("x2"));
        }

        public static string RandomSha256(int doublingCount)
        {
            var hash = string.Empty;
            var random = new Random();
            for (var i = 0; i < doublingCount; i++)
            {
                hash += Sha256(DateTime.Now.Ticks.ToString() + random.Next(100000, 9000000));
            }
            return hash;
        }

        public static string Md5(string input)
        {
            string hash;
            using (var md5 = MD5.Create())
            {
                hash = BitConverter.ToString(
                    md5.ComputeHash(Encoding.UTF8.GetBytes(input))
                ).Replace("-", string.Empty);
            }
            return hash;
        }

        public static bool IsHex(string test)
        {
            return Regex.IsMatch(test, @"\A\b[0-9a-fA-F]+\b\Z");
        }

        public static string Get_Computer_UUID()
        {
            try
            {
                using (var mc = new ManagementClass("Win32_ComputerSystemProduct"))
                {
                    foreach (var mo in mc.GetInstances())
                    {
                        try
                        {
                            var value = mo["UUID"] as string;
                            if (!string.IsNullOrEmpty(value))
                            {
                                return value;
                            }
                        }
                        finally
                        {
                            mo.Dispose();
                        }
                    }
                }

            }
            catch (Exception)
            {
                //
            }

            return string.Empty;
        }
    }
}
