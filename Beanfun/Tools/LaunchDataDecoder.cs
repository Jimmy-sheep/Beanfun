using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.RegularExpressions;

namespace Beanfun
{
    public enum LaunchPayloadType
    {
        Ticket,
        Legacy
    }

    public class LegacyOtpParams
    {
        public string Ppppp { get; set; }
        public string ServiceCode { get; set; }
        public string ServiceRegion { get; set; }
        public string ServiceAccount { get; set; }
        public string CreateTime { get; set; }
    }

    public class LaunchPayload
    {
        public LaunchPayloadType Type { get; set; }
        public string LaunchTicket { get; set; }
        public LegacyOtpParams LegacyParams { get; set; }
        public string RawPlaintext { get; set; }
    }

    public static class LaunchDataDecoder
    {
        /// <summary>
        /// The eight substitution alphabets extracted from the GGM launcher's Command.DecryptParam().
        /// Each table is a 16-character permutation of the hex digits.
        /// </summary>
        public static readonly string[] TABLES = new string[]
        {
            "bac987d65e432f10",
            "3bc4d5e6f2a79108",
            "cdbeaf9012456378",
            "4e6fb81a3c5d7092",
            "bdef1246789ac530",
            "5f82cb4093e71d6a",
            "df1468ace0357b92",
            "b50c61a4f93e82d7",
        };

        private const int KEY_LEN = 8;

        /// <summary>
        /// Decodes obfuscated data from m_objData.data in game_start_step2.aspx.
        /// </summary>
        public static LaunchPayload Decode(string data)
        {
            if (string.IsNullOrWhiteSpace(data) || data.Length < 2)
            {
                return null;
            }

            char selectorChar = data[0];
            if (!int.TryParse(selectorChar.ToString(), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int selector))
            {
                return null;
            }

            string rest = data.Substring(1);

            // Determine candidate order: selector % 4, selector % 8, then remaining tables
            List<int> order = new List<int>
            {
                selector % 4,
                selector % TABLES.Length
            };
            for (int i = 0; i < TABLES.Length; i++)
            {
                if (!order.Contains(i))
                {
                    order.Add(i);
                }
            }

            foreach (int tableIndex in order)
            {
                string plaintext = DecodeWithTable(rest, selector, tableIndex);
                if (string.IsNullOrEmpty(plaintext))
                {
                    continue;
                }

                if (plaintext.Contains("LaunchTicket="))
                {
                    string ticket = ExtractFieldValue(plaintext, "LaunchTicket");
                    if (!string.IsNullOrEmpty(ticket))
                    {
                        return new LaunchPayload
                        {
                            Type = LaunchPayloadType.Ticket,
                            LaunchTicket = ticket,
                            RawPlaintext = plaintext
                        };
                    }
                }
                else if (plaintext.Contains("ppppp="))
                {
                    var legacy = new LegacyOtpParams
                    {
                        Ppppp = ExtractFieldValue(plaintext, "ppppp"),
                        ServiceCode = ExtractFieldValue(plaintext, "ServiceCode"),
                        ServiceRegion = ExtractFieldValue(plaintext, "ServiceRegion"),
                        ServiceAccount = ExtractFieldValue(plaintext, "ServiceAccount"),
                        CreateTime = ExtractFieldValue(plaintext, "CreateTime")
                    };

                    return new LaunchPayload
                    {
                        Type = LaunchPayloadType.Legacy,
                        LegacyParams = legacy,
                        RawPlaintext = plaintext
                    };
                }
            }

            return null;
        }

        private static string DecodeWithTable(string body, int selector, int tableIndex)
        {
            try
            {
                string table = TABLES[tableIndex];
                char[] normalizedChars = new char[body.Length];

                for (int i = 0; i < body.Length; i++)
                {
                    int idx = table.IndexOf(body[i]);
                    if (idx < 0)
                    {
                        return null; // Character not in table
                    }
                    normalizedChars[i] = idx.ToString("x")[0];
                }

                string normalized = new string(normalizedChars);
                int offset = selector + 1;
                if (normalized.Length < offset + KEY_LEN)
                {
                    return null;
                }

                string key = normalized.Substring(offset, KEY_LEN);
                string cipherHex = normalized.Substring(0, offset) + normalized.Substring(offset + KEY_LEN);

                if (cipherHex.Length % 2 != 0 || (cipherHex.Length / 2) % 8 != 0)
                {
                    return null;
                }

                string decrypted = WCDESComp.DecryStrHex(cipherHex, key);
                if (decrypted == null)
                {
                    return null;
                }

                return decrypted.TrimEnd('\0');
            }
            catch (Exception ex)
            {
                Console.WriteLine("DecodeWithTable error: " + ex.Message);
                return null;
            }
        }

        private static string ExtractFieldValue(string plaintext, string fieldName)
        {
            // Fields might be separated by ';' then '&' or '&&&&'
            string clean = plaintext.Split(';')[0];
            // Split by either '&&&&' or '&'
            string[] pairs = Regex.Split(clean, @"&&&&|&");
            foreach (string pair in pairs)
            {
                string prefix = fieldName + "=";
                if (pair.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    return pair.Substring(prefix.Length);
                }
            }
            return null;
        }
    }
}
