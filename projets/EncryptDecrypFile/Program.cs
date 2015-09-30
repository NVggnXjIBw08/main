using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;

namespace EncryptDecrypFile
{
    class Program
    {

        static string iv = "****************";

        static void Main(string[] args)
        {
            if (args.Length == 1 && File.Exists(args[0]))
            {
                string file = args[0];
                int index = file.LastIndexOf('\\');
                if (index != -1)
                {
                    string fileName = file.Substring(index + 1);
                    string key = fileName;
                    if (key.Length > 16)
                    {
                        key = key.Substring(0, 16);
                    }
                    StreamReader sr = new StreamReader(file);
                    string input = sr.ReadToEnd();
                    sr.Close();
                    bool crypt = (input.IndexOf(' ') != -1) ? true : false;
                    string output = (crypt) ? EncryptString(input, key, iv) : DecryptString(input, key, iv);
                    StreamWriter sw = new StreamWriter(file, false);
                    sw.Write(output);
                    sw.Close();
                }
            }
        }

        /// 
        /// Chiffre une chaîne de caractère
        /// 
        /// Texte clair à chiffrer
        /// Clé de chiffrement
        /// Vecteur d'initialisation
        /// Retourne le texte chiffré
        private static string EncryptString(string clearText, string strKey, string strIv)
        {
            // Place le texte à chiffrer dans un tableau d'octets
            byte[] plainText = Encoding.UTF8.GetBytes(clearText);
            // Place la clé de chiffrement dans un tableau d'octets
            byte[] key = Encoding.UTF8.GetBytes(strKey);
            // Place le vecteur d'initialisation dans un tableau d'octets
            byte[] iv = Encoding.UTF8.GetBytes(strIv);
            RijndaelManaged rijndael = new RijndaelManaged();
            // Définit le mode utilisé
            rijndael.Mode = CipherMode.CBC;
            // Crée le chiffreur AES - Rijndael
            ICryptoTransform aesEncryptor = rijndael.CreateEncryptor(key, iv);
            MemoryStream ms = new MemoryStream();
            // Ecris les données chiffrées dans le MemoryStream
            CryptoStream cs = new CryptoStream(ms, aesEncryptor, CryptoStreamMode.Write);
            cs.Write(plainText, 0, plainText.Length);
            cs.FlushFinalBlock();
            // Place les données chiffrées dans un tableau d'octet
            byte[] CipherBytes = ms.ToArray();
            ms.Close();
            cs.Close();
            // Place les données chiffrées dans une chaine encodée en Base64
            return Convert.ToBase64String(CipherBytes);
        }

        /// <summary>
        /// Déchiffre une chaîne de caractère
        /// </summary>
        /// <param name="cipherText">Texte chiffré</param>
        /// <param name="strKey">Clé de déchiffrement</param>
        /// <param name="strIv">Vecteur d'initialisation</param>
        /// <returns></returns>
        public static string DecryptString(string cipherText, string strKey, string strIv)
        {
            // Place le texte à déchiffrer dans un tableau d'octets
            byte[] cipheredData = Convert.FromBase64String(cipherText);
            // Place la clé de déchiffrement dans un tableau d'octets
            byte[] key = Encoding.UTF8.GetBytes(strKey);
            // Place le vecteur d'initialisation dans un tableau d'octets
            byte[] iv = Encoding.UTF8.GetBytes(strIv);
            RijndaelManaged rijndael = new RijndaelManaged();
            rijndael.Mode = CipherMode.CBC;
            // Ecris les données déchiffrées dans le MemoryStream
            ICryptoTransform decryptor = rijndael.CreateDecryptor(key, iv);
            MemoryStream ms = new MemoryStream(cipheredData);
            CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
            // Place les données déchiffrées dans un tableau d'octet
            byte[] plainTextData = new byte[cipheredData.Length];
            int decryptedByteCount = cs.Read(plainTextData, 0, plainTextData.Length);
            ms.Close();
            cs.Close();
            return Encoding.UTF8.GetString(plainTextData, 0, decryptedByteCount);
        }

    }
}
