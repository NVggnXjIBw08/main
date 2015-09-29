using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Net;
using System.Xml;

namespace spe.main
{
    class Identity
    {

        #region Types
        
        public enum EnumSexe
        {
            Masculin = 0,
            Feminin = 1
        }

        #endregion

        #region Attributs

        #region Attributs.Privés

        private Random Random = new Random();
        private XmlDocument XmlNoms = new XmlDocument();
        private XmlNodeList XmlNodeListNoms = null;
        private XmlDocument XmlPrenoms = new XmlDocument();
        private XmlDocument XmlVilles = new XmlDocument();
        private XmlNodeList XmlNodeListVilles = null;
        private char[] __speciaux = { '~', '!', '@', '#', '$', '%', '^', '*', '(', ')', '_', '-', '+', '=', '{', '}', '[', ']', '|', ':', ';', '"', ',', '?' };
        private char[] __entiers = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };
        private char[] __majuscules = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
        private char[] __majusculesConsonnes = { 'B', 'C', 'D', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'V', 'W', 'X', 'Z' };
        private char[] __majusculesVoyelles = { 'A', 'E', 'I', 'O', 'U', 'Y' };
        private char[] __minuscules = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
        private char[] __minusculesConsonnes = { 'b', 'c', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'm', 'n', 'p', 'q', 'r', 's', 't', 'v', 'w', 'x', 'z' };
        private char[] __minusculesVoyelles = { 'a', 'e', 'i', 'o', 'u', 'y' };
        private string[] __typesVoies = { "Rue", "Boulevard", "Avenue", "Impasse", "Square" };
        private string[] __indicatifsTelephoniques = { "06" };

        #endregion

        #region Attributs.Publiques

        public DateTime DateNaissance { get; set; }
        public EnumSexe Sexe { get; set; }
        public string Nom { get; set; }
        public string Prenom { get; set; }
        public string Mail { get; set; }
        public string Login { get; set; }
        public string Password { get; set; }
        public string Adresse { get; set; }
        public string CodePostal { get; set; }
        public string Ville { get; set; }
        public string Telephone { get; set; }

        #endregion

        #endregion

        #region Constructeurs

        /// <summary>
        /// 
        /// </summary>
        public Identity()
        {
            XmlNoms.Load("input\\noms.xml");
            if (XmlNoms != null)
            {
                XmlNodeListNoms = XmlNoms.SelectNodes("noms/nom");
            }
            XmlPrenoms.Load("input\\prenoms.xml");
            XmlVilles.Load("input\\villes.xml");
            if (XmlVilles != null)
            {
                XmlNodeListVilles = XmlVilles.SelectNodes("villes/ville");
            }
        }

        #endregion

        #region Fonctions

        #region Fonctions.Publiques

        public void create()
        {
            DateNaissance = getDateNaissance(18, 80);
            Sexe = (Random.Next(2) == 0) ? EnumSexe.Masculin : EnumSexe.Feminin;
            Nom = getNom();
            Prenom = getPrenom(Sexe, DateNaissance);
            Mail = supprimeCaracteresSpeciaux(Prenom.ToLower() + "." + Nom.ToLower()) + "@unimedia.fr";
            Login = getLogin();
            Password = getPassword();
            getAdresse();
            Telephone = getTelephone();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="__string"></param>
        /// <returns></returns>
        private string supprimeCaracteresSpeciaux(string __string)
        {
            string __ret = "";
            int __index = 0;
            while (__index < __string.Length)
            {
                string __caractere = __string.Substring(__index, 1);
                if ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".IndexOf(__caractere) != -1)
                {
                    __ret += __caractere;
                }
                else
                {
                    __ret += ".";
                }
                __index++;
            }
            while (__ret.IndexOf("..") != -1)
            {
                __ret = __ret.Replace("..", ".");
            }

            return __ret;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="__file"></param>
        public void save(string __file = "")
        {
            if (__file == "")
            {
                __file = String.Format("../../output/identity.{0:yyyyMMddHHmmssfff}.txt", DateTime.Now);
            }
            StreamWriter __sr = new StreamWriter(__file, false);
            __sr.WriteLine(String.Format("DateNaissance : {0}", DateNaissance));
            string __temp = (Sexe == EnumSexe.Masculin) ? "Masculin" : "Feminin";
            __sr.WriteLine(String.Format("Sexe : {0}", __temp));
            __sr.WriteLine(String.Format("Nom : {0}", Nom));
            __sr.WriteLine(String.Format("Prenom : {0}", Prenom));
            __sr.WriteLine(String.Format("Adresse : {0} - {1} {2}", Adresse, CodePostal, Ville));
            __sr.WriteLine(String.Format("Telephone : {0}", Telephone));
            __sr.WriteLine(String.Format("Mail : {0}", Mail));
            __sr.WriteLine(String.Format("Login : {0}", Login));
            __sr.WriteLine(String.Format("Password : {0}", Password));
            __sr.Close();
            __sr.Dispose();
        }

        #endregion

        #region Fonctions.Privés

        private string getNomAleatoire()
        {
            string __nom = "";
            int __longueur = 5 + Random.Next(10);
            while (__nom.Length < __longueur)
            {
                if (__nom.Length % 2 == 0)
                {
                    __nom += __majusculesConsonnes[Random.Next(__majusculesConsonnes.Length)];
                }
                else
                {
                    __nom += __majusculesVoyelles[Random.Next(__majusculesVoyelles.Length)];
                }
            }

            return __nom;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="__longueur"></param>
        /// <returns></returns>
        private string getNom()
        {
            string __nom = getNomAleatoire();

            if (XmlNoms != null && XmlNodeListNoms != null && XmlNodeListNoms.Count > 0)
            {
                __nom = XmlNodeListNoms[Random.Next(XmlNodeListNoms.Count)].InnerText.ToUpper().Replace("-", " ");
            }
            #region Ancienne Méthode LIVE
            /*WebClient __wc = new WebClient();
            string __url = "http://www.nom-famille.com/noms-les-plus-portes-en-france.html";
            string __source = __wc.DownloadString(__url);
            List<string> __liste = new List<string>();
            getListeFromModele(__source, "...  <a class=\"page\" href=\"http://www.nom-famille.com/noms-les-plus-portes-en-france-[*].html\">", ref __liste, false, true);
            if (__liste.Count == 1)
            {
                int __count = 0;
                if (int.TryParse(__liste[0], out __count))
                {
                    int __page = Random.Next(__count);
                    __url = String.Format("http://www.nom-famille.com/noms-les-plus-portes-en-france-{0}.html", __page);
                    __source = __wc.DownloadString(__url);
                    getListeFromModele(__source, "<a class=\"nom\" href=\"http://www.nom-famille.com/nom-[*].html\">", ref __liste, false, true);
                    if (__liste.Count > 0)
                    {
                        __nom = __liste[Random.Next(__liste.Count)].ToUpper().Replace("-" , " ");
                    }
                }
            }
            __wc.Dispose();*/
            #endregion

            return __nom;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="__longueur"></param>
        /// <returns></returns>
        private string getPrenomAleatoire(int __longueur)
        {
            string __prenom = "";
            if (Random.Next(10) % 2 == 0)
            {
                __prenom += __majusculesConsonnes[Random.Next(__majusculesConsonnes.Length)];
            }
            else
            {
                __prenom += __majusculesVoyelles[Random.Next(__majusculesVoyelles.Length)];
            }
            while (__prenom.Length < __longueur)
            {
                if (__prenom.Length % 2 == 0)
                {
                    __prenom += __minusculesConsonnes[Random.Next(__minusculesConsonnes.Length)];
                }
                else
                {
                    __prenom += __minusculesVoyelles[Random.Next(__minusculesVoyelles.Length)];
                }
            }

            return __prenom;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        private string getPrenom(EnumSexe __sexe, DateTime __date)
        {
            string __prenom = getPrenomAleatoire(5 + Random.Next(10));
            if (XmlPrenoms != null)
            {
                string __idSexe = (__sexe == EnumSexe.Feminin) ? "Feminin" : "Masculin";
                XmlNodeList __prenoms = XmlPrenoms.SelectNodes(String.Format("prenoms/top[@annee='{0}']/sexe[@id='{1}']/prenom", __date.Year, __idSexe));
                if (__prenoms.Count > 0)
                {
                    __prenom = __prenoms[Random.Next(__prenoms.Count)].InnerText;
                }
            }
            #region Ancienne Méthode LIVE
            /*// http://meilleursprenoms.com
            int __page = 1;
            int __pageMax = Random.Next(5) + 1;
            List<string> __prenoms = new List<string>();
            WebClient __wc = new WebClient();
            bool __trouve = true;
            while (__trouve && __page <= __pageMax)
            {
                __trouve = false;
                string __source = __wc.DownloadString(String.Format("http://meilleursprenoms.com/stats/topannee.php3?annee={0}&page={1}", DateNaissance.Year, __page));
                List<string> __valeurs = new List<string>();
                getListeFromModele(__source, "<table width=\"300\" border=\"0\" cellspacing=\"0\" cellpadding=\"0\" align=\"center\">[*]</table>", ref __valeurs, true);
                if (__valeurs.Count == 1)
                {
                    __source = __valeurs[0];
                    getListeFromModele(__source, "<td class=\"mpfont\">[*]</td>", ref __valeurs, true);
                    if (__valeurs.Count == 3)
                    {
                        __source = (__sexe == EnumSexe.Masculin) ? __source = __valeurs[1] : __source = __valeurs[2];
                        getListeFromModele(__source, "<a href=\"/stats/prenom.php3/[*]\">", ref __valeurs, false);
                        __prenoms.AddRange(__valeurs);
                        __trouve = true;
                        __page++;
                    }
                }
            }
            __wc.Dispose();
            if (__prenoms.Count > 0)
            {
                __prenom = __prenoms[Random.Next(__prenoms.Count)];
            }*/
            #endregion

            return majusculeApresTiretOuEspace(__prenom);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="__string"></param>
        /// <returns></returns>
        private string majusculeApresTiretOuEspace(string __string)
        {
            string __ret = "";
            bool __majuscule = false;
            int __index = 0;
            while (__index < __string.Length)
            {
                string __char = __string.Substring(__index, 1);
                if (__majuscule && __char != "-" && __char != " ")
                {
                    __char = __char.ToUpper();
                    __majuscule = false;
                }
                if (__char == "-" || __char == " ")
                {
                    __majuscule = true;
                }
                __ret += __char;
                __index++;
            }

            return __ret;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="__ageMin"></param>
        /// <param name="__ageMax"></param>
        /// <returns></returns>
        private DateTime getDateNaissance(int __ageMin, int __ageMax)
        {
            DateTime __dateNaissance = DateTime.Now;
            __dateNaissance = __dateNaissance.AddYears(-__ageMin - Random.Next(__ageMax - __ageMin));
            int __signe = (Random.Next(10) % 2 == 0) ? 1 : -1;
            __dateNaissance = __dateNaissance.AddDays(__signe * Random.Next(365));
            __signe = (Random.Next(10) % 2 == 0) ? 1 : -1;
            __dateNaissance = __dateNaissance.AddHours(__signe * Random.Next(24));
            __signe = (Random.Next(10) % 2 == 0) ? 1 : -1;
            __dateNaissance = __dateNaissance.AddMinutes(__signe * Random.Next(60));
            __signe = (Random.Next(10) % 2 == 0) ? 1 : -1;
            __dateNaissance = __dateNaissance.AddSeconds(__signe * Random.Next(60));
            __signe = (Random.Next(10) % 2 == 0) ? 1 : -1;
            __dateNaissance = __dateNaissance.AddMilliseconds(__signe * Random.Next(1000));

            return __dateNaissance;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        private string getLogin()
        {
            string __login = "";
            string __loginTemp = "";
            int __nbre = 1;
            while (__nbre <= 5)
            {
                __loginTemp += __majuscules[Random.Next(__majuscules.Length)];
                __nbre++;
            }
            __nbre = 1;
            while (__nbre <= 5)
            {
                __loginTemp += __minuscules[Random.Next(__minuscules.Length)];
                __nbre++;
            }
            while (__loginTemp != "")
            {
                int __index = Random.Next(__loginTemp.Length);
                __login += __loginTemp[__index];
                if (__index == 0)
                {
                    __loginTemp = __loginTemp.Substring(1);
                }
                else
                {
                    if (__index == __loginTemp.Length - 1)
                    {
                        __loginTemp = __loginTemp.Substring(0, __index);
                    }
                    else
                    {
                        __loginTemp = __loginTemp.Substring(0, __index) + __loginTemp.Substring(__index + 1);
                    }
                }
            }
            __login += __entiers[Random.Next(__entiers.Length)];
            __login += __entiers[Random.Next(__entiers.Length)];

            return __login;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        private string getPassword()
        {
            /*
                https://www.microsoft.com/security/pc-security/password-checker.aspx
                http://www.passwordmeter.com
                http://rumkin.com/tools/password/passchk.php
            */
            string __password = "";
            string __passwordTemp = "";
            int __nbre = 1;
            while (__nbre <= 7)
            {
                __passwordTemp += __majuscules[Random.Next(__majuscules.Length)];
                __nbre++;
            }
            __nbre = 1;
            while (__nbre <= 7)
            {
                __passwordTemp += __minuscules[Random.Next(__minuscules.Length)];
                __nbre++;
            }
            __nbre = 1;
            while (__nbre <= 5)
            {
                __passwordTemp += __entiers[Random.Next(__entiers.Length)];
                __nbre++;
            }
            __nbre = 1;
            while (__nbre <= 5)
            {
                __passwordTemp += __speciaux[Random.Next(__speciaux.Length)];
                __nbre++;
            }
            while (__passwordTemp != "")
            {
                int __index = Random.Next(__passwordTemp.Length);
                __password += __passwordTemp[__index];
                if (__index == 0)
                {
                    __passwordTemp = __passwordTemp.Substring(1);
                }
                else
                {
                    if (__index == __passwordTemp.Length - 1)
                    {
                        __passwordTemp = __passwordTemp.Substring(0, __index);
                    }
                    else
                    {
                        __passwordTemp = __passwordTemp.Substring(0, __index) + __passwordTemp.Substring(__index + 1);
                    }
                }
            }

            return __password;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="__source"></param>
        /// <param name="__modele"></param>
        /// <param name="__liste"></param>
        /// <param name="__avec"></param>
        private void getListeFromModele(string __source, string __modele, ref List<string> __liste, bool __avec)
        {
            getListeFromModele(__source, __modele, ref __liste, __avec, false);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="__source"></param>
        /// <param name="__modele"></param>
        /// <param name="__liste"></param>
        /// <param name="__avec"></param>
        private void getListeFromModele(string __source, string __modele, ref List<string> __liste, bool __avec, bool __distinct)
        {
            __liste.Clear();
            string __debut = "";
            string __fin = "";
            int __index = __modele.IndexOf("[*]");
            if (__index != -1)
            {
                __debut = __modele.Substring(0, __index);
                __fin = __modele.Substring(__index + 3);
                string __valeur = "";
                int __indexDebut = 0;
                int __indexFin = 0;
                __indexDebut = __source.IndexOf(__debut);
                if (__indexDebut != -1)
                {
                    __indexFin = __source.IndexOf(__fin, __indexDebut + __debut.Length);
                    while (__indexDebut != -1 && __indexFin != -1)
                    {
                        if (__avec)
                            __valeur = __source.Substring(__indexDebut, (__indexFin - __indexDebut) + __fin.Length);
                        else
                            __valeur = __source.Substring(__indexDebut + __debut.Length, __indexFin - __indexDebut - __debut.Length);
                        if (__distinct)
                        {
                            if (__liste.IndexOf(__valeur) == -1)
                            {
                                __liste.Add(__valeur);
                            }
                        }
                        else
                        {
                            __liste.Add(__valeur);
                        }
                        __indexDebut = __source.IndexOf(__debut, __indexFin + __fin.Length);
                        if (__indexDebut != -1)
                        {
                            __indexFin = __source.IndexOf(__fin, __indexDebut + __debut.Length);
                        }
                    }
                }
            }
        }

        private void getAdresse()
        {
            EnumSexe __sexe = (Random.Next(2) == 0) ? EnumSexe.Masculin : EnumSexe.Feminin;
            Adresse = String.Format("{0}, {1} {2} {3}", Random.Next(99) + 1, __typesVoies[Random.Next(__typesVoies.Length)], getPrenom(__sexe, getDateNaissance(18, 80)), getNom());
            CodePostal = "";
            Ville = "";
            if (XmlVilles != null && XmlNodeListVilles != null && XmlNodeListVilles.Count > 0)
            {
                string __idSexe = (__sexe == EnumSexe.Feminin) ? "Feminin" : "Masculin";
                int __index = Random.Next(XmlNodeListVilles.Count);
                Ville = XmlNodeListVilles[__index].InnerText;
                CodePostal = XmlNodeListVilles[__index].Attributes["codePostal"].Value;
            }
            #region Ancienne Méthode LIVE
            /*// http://www.codeposte.com
            List<string> __departements = new List<string>();
            WebClient __wc = new WebClient();
            string __source = __wc.DownloadString(String.Format("http://www.codeposte.com/codeposte_dept_fr.htm"));
            getListeFromModele(__source, "\"http://www.codeposte.com/home.php?s_keyword=[*]\"", ref __departements, false);
            if (__departements.Count > 0)
            {
                string __departement = __departements[Random.Next(__departements.Count)];
                __source = __wc.DownloadString(String.Format("http://www.codeposte.com/home.php?s_keyword={0}", __departement));

                List<string> __villesTemp = new List<string>();
                List<string> __codesTemp = new List<string>();
                getListeFromModele(__source, "<td class=\"row\" width=\"260\" align=\"center\">[*]</td>", ref __villesTemp, false);
                getListeFromModele(__source, "<td class=\"row\" align=\"center\" width=\"58\">[*]</td> ", ref __codesTemp, false);
                if (__villesTemp.Count == __codesTemp.Count)
                {
                    List<string> __villes = new List<string>();
                    List<string> __codes = new List<string>();
                    int __index = 0;
                    while (__index < __villesTemp.Count)
                    {
                        if (__villesTemp[__index] != "")
                        {
                            __villes.Add(__villesTemp[__index]);
                            __codes.Add(__codesTemp[__index]);
                        }
                        __index++;
                    }
                    int __hasard = Random.Next(__villes.Count);
                    CodePostal = __codes[__hasard];
                    Ville = __villes[__hasard].ToUpper();
                    EnumSexe __sexe = (Random.Next(2) == 0) ? EnumSexe.Masculin : EnumSexe.Feminin;
                    Adresse = String.Format("{0}, {1} {2} {3}", Random.Next(99) + 1, __typesVoies[Random.Next(__typesVoies.Length)], getPrenom(__sexe, getDateNaissance(18, 80)), getNom());
                }
            }
            __wc.Dispose();*/
            #endregion

            return;
        }

        private string getTelephone()
        {
            string __telephone = __indicatifsTelephoniques[Random.Next(__indicatifsTelephoniques.Length)];
            while (__telephone.Length < 10)
            {
                __telephone += __entiers[Random.Next(__entiers.Length)];
            }

            return __telephone;
        }

        #endregion

        #endregion

    }
}
