using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

namespace Beanfun
{
    public class ClientIntegrity
    {
        public const string GGM_DLL_NAME = "GGMWebStart.dll";
        public const string DEFAULT_CV = "1.5.0.2";
        public const string DEFAULT_HASH = "dfd568a69d87abcd8f4a93d1a4481ebb57712d1d28ab0b6fc018fcf140101e06";

        public string CV { get; set; } = DEFAULT_CV;
        public string Hash { get; set; } = DEFAULT_HASH;
        public string Arch { get; set; } = Environment.Is64BitOperatingSystem ? "x64" : "x86";

        /// <summary>
        /// Resolves client integrity information from local GGM installation or fallback constants.
        /// </summary>
        public static ClientIntegrity Resolve()
        {
            try
            {
                string dllPath = LocateGgmDll();
                if (!string.IsNullOrEmpty(dllPath) && File.Exists(dllPath))
                {
                    FileVersionInfo versionInfo = FileVersionInfo.GetVersionInfo(dllPath);
                    string version = $"{versionInfo.FileMajorPart}.{versionInfo.FileMinorPart}.{versionInfo.FileBuildPart}.{versionInfo.FilePrivatePart}";
                    string hash = ComputeFileSha256(dllPath);

                    if (!string.IsNullOrEmpty(version) && !string.IsNullOrEmpty(hash) && hash.Length == 64)
                    {
                        return new ClientIntegrity
                        {
                            CV = version,
                            Hash = hash.ToLowerInvariant(),
                            Arch = Environment.Is64BitOperatingSystem ? "x64" : "x86"
                        };
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("ClientIntegrity.Resolve failed: " + ex.Message);
            }

            return new ClientIntegrity();
        }

        private static string LocateGgmDll()
        {
            foreach (string dir in GetGgmDirectories())
            {
                if (!string.IsNullOrEmpty(dir))
                {
                    string candidate = Path.Combine(dir, GGM_DLL_NAME);
                    if (File.Exists(candidate))
                    {
                        return candidate;
                    }
                }
            }
            return null;
        }

        private static IEnumerable<string> GetGgmDirectories()
        {
            List<string> dirs = new List<string>();

            // 1. From registry protocol handler
            string handlerPath = FindGGMExecutablePath();
            if (!string.IsNullOrEmpty(handlerPath))
            {
                string dir = Path.GetDirectoryName(handlerPath);
                if (!string.IsNullOrEmpty(dir))
                {
                    dirs.Add(dir);
                }
            }

            // 2. Default installation locations
            string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            if (!string.IsNullOrEmpty(pf))
            {
                dirs.Add(Path.Combine(pf, "gamania Games", "gamania Games Manager"));
            }

            string pfX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            if (!string.IsNullOrEmpty(pfX86))
            {
                dirs.Add(Path.Combine(pfX86, "gamania Games", "gamania Games Manager"));
            }

            return dirs;
        }

        private static string FindGGMExecutablePath()
        {
            try
            {
                using RegistryKey key = Registry.ClassesRoot.OpenSubKey(@"gamaniagames\shell\open\command");
                if (key != null)
                {
                    string command = key.GetValue("") as string;
                    if (!string.IsNullOrWhiteSpace(command))
                    {
                        command = command.Trim();
                        if (command.StartsWith("\""))
                        {
                            int nextQuote = command.IndexOf('\"', 1);
                            if (nextQuote > 1)
                            {
                                return command.Substring(1, nextQuote - 1);
                            }
                        }
                        else
                        {
                            string[] parts = command.Split(' ');
                            if (parts.Length > 0)
                            {
                                return parts[0];
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("FindGGMExecutablePath error: " + ex.Message);
            }

            return null;
        }

        private static string ComputeFileSha256(string filePath)
        {
            try
            {
                using SHA256 sha256 = SHA256.Create();
                using FileStream stream = File.OpenRead(filePath);
                byte[] hashBytes = sha256.ComputeHash(stream);
                StringBuilder sb = new StringBuilder(64);
                foreach (byte b in hashBytes)
                {
                    sb.Append(b.ToString("x2"));
                }
                return sb.ToString();
            }
            catch (Exception ex)
            {
                Console.WriteLine("ComputeFileSha256 error: " + ex.Message);
                return null;
            }
        }
    }
}
