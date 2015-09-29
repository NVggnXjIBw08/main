using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace POB
{
    public class Utile
    {

        public static string delTags(string __html)
        {
            string __ret = __html;

            List<string> __valeurs = new List<string>();
            getListeFromModele(__html, "<[*]>", ref __valeurs, true);
            foreach (string __valeur in __valeurs)
            {
                __ret = __ret.Replace(__valeur, "");
            }

            return __ret;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="__source"></param>
        /// <param name="__modele"></param>
        /// <param name="__liste"></param>
        /// <param name="__avec"></param>
        public static void getListeFromModele(string __source, string __modele, ref List<string> __liste, bool __avec)
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
        public static void getListeFromModele(string __source, string __modele, ref List<string> __liste, bool __avec, bool __distinct)
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

    }
}
