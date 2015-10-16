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

        static string iv = "S5Y4Jg4eSv5sPy44";

        /// <summary>
        /// 
        /// </summary>
        /// <param name="args"></param>
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
                    StreamReader sr = new StreamReader(file, Encoding.Default);
                    string input = sr.ReadToEnd();
                    sr.Close();
                    string output = "";
                    int n1 = DecryptString(input, key, iv, out output);
                    int n2 = -20;
                    if (n1 != 0)
                    {
                        n2 = EncryptString(input, key, iv, out output);
                    }
                    if (n1 == 0 || n2 == 0)
                    {
                        StreamWriter sw = new StreamWriter(file, false, Encoding.Default);
                        sw.Write(output);
                        sw.Close();
                    }
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
        private static int EncryptString(string clearText, string strKey, string strIv, out string ret)
        {
            int n = 0;
            ret = "";

            try
            {

                // Place le texte à chiffrer dans un tableau d'octets
                byte[] plainText = Encoding.Default.GetBytes(clearText);
                // Place la clé de chiffrement dans un tableau d'octets
                byte[] key = Encoding.Default.GetBytes(strKey);
                // Place le vecteur d'initialisation dans un tableau d'octets
                byte[] iv = Encoding.Default.GetBytes(strIv);
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
                ret = Convert.ToBase64String(CipherBytes);
            }
            catch (Exception e)
            {
                n = -10;
            }

            return n;
        }

        /// <summary>
        /// Déchiffre une chaîne de caractère
        /// </summary>
        /// <param name="cipherText">Texte chiffré</param>
        /// <param name="strKey">Clé de déchiffrement</param>
        /// <param name="strIv">Vecteur d'initialisation</param>
        /// <returns></returns>
        public static int DecryptString(string cipherText, string strKey, string strIv, out string ret)
        {
            int n = 0;
            ret = "";

            try
            {
                // Place le texte à déchiffrer dans un tableau d'octets
                byte[] cipheredData = Convert.FromBase64String(cipherText);
                // Place la clé de déchiffrement dans un tableau d'octets
                byte[] key = Encoding.Default.GetBytes(strKey);
                // Place le vecteur d'initialisation dans un tableau d'octets
                byte[] iv = Encoding.Default.GetBytes(strIv);
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
                ret = Encoding.Default.GetString(plainTextData, 0, decryptedByteCount);
            }
            catch (Exception e)
            {
                //-2146233296
                //Le remplissage n'est pas valide et ne peut pas être supprimé.
                if (e.HResult == -2146233296)
                {
                    n = -10;
                }
                else
                {
                    n = -20;
                }
            }

            return n;
        }

    }
}
