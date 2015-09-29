using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Xml;

namespace POB
{
    public class Page
    {
        public static Page fromFile(string __file)
        {
            if (File.Exists(__file))
            {
                StreamReader __sr = new StreamReader(__file);
                string __source = __sr.ReadToEnd();

                /*
                    Méthode DIV Début
                 */
                __source = __source.Replace("<script", "<!-- <script");
                __source = __source.Replace("/script>", "/script> -->");
                __source = __source.Replace("&nbsp;", " ");
                __source = __source.Replace("&nbsp;", " ");
                __source = __source.Replace("<br>", "<br />");
                __source = __source.Replace("<col>", "<col />");
                __source = __source.Replace("<hr>", "<hr />");
                List<string> __valeurs = new List<string>();
                string[] __modeles = { "<img [*]>", "<col [*]>", "<hr [*]>", "<link [*]>" };
                foreach (string __modele in __modeles)
                {
                    Utile.getListeFromModele(__source, __modele, ref __valeurs, true);
                    foreach (string __valeur in __valeurs)
                    {
                        if (!(__valeur.EndsWith("/>")) && !(__valeur.EndsWith("/ >")))
                        {
                            __source = __source.Replace(__valeur, __valeur.Replace(">", "/>"));
                        }
                    }
                }
                XmlDocument __xml = new XmlDocument();
                __xml.LoadXml(String.Format("<{0}>{1}</{0}>", "html", __source));
                XmlNodeList __xmlListDiv1 = __xml.SelectNodes("//html/div");
                foreach (XmlNode __xmlDiv1 in __xmlListDiv1)
                {
                    if (__xmlDiv1.Attributes["id"] != null && __xmlDiv1.Attributes["id"].Value == "SITE_STRUCTURE")
                    {
                        XmlNodeList __xmlListDiv2 = __xmlDiv1.SelectNodes("div");
                        foreach (XmlNode __xmlDiv2 in __xmlListDiv2)
                        {
                            if (__xmlDiv2.Attributes["id"] != null && __xmlDiv2.Attributes["id"].Value == "PAGES_CONTAINER")
                            {
                                XmlNodeList __xmlListDiv3 = __xmlDiv2.SelectNodes("div");
                                foreach (XmlNode __xmlDiv3 in __xmlListDiv3)
                                {
                                    XmlNodeList __xmlListDiv4 = __xmlDiv3.SelectNodes("div");
                                    foreach (XmlNode __xmlDiv4 in __xmlListDiv4)
                                    {
                                        XmlNodeList __xmlListDiv5 = __xmlDiv4.SelectNodes("div");
                                        foreach (XmlNode __xmlDiv5 in __xmlListDiv5)
                                        {
                                            if (__xmlDiv5.OuterXml.IndexOf("concours de Pétanque") != -1)
                                            {
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                /*
                    Méthode DIV Fin
                 */

                // left: 0px; top: 0px; width: 980px; visibility: visible;
                Utile.getListeFromModele(__source, "<table[*]</table>", ref __valeurs, true);
                foreach (string __valeur in __valeurs)
                {
                    string __valeurReplace = __valeur;
                    __valeurReplace = __valeurReplace.Replace("<p", "<*p");
                    __valeurReplace = __valeurReplace.Replace("</p>", "</*p>");
                    __source = __source.Replace(__valeur, __valeurReplace);
                }
                __source = __source.Replace("<table", "<ptable");
                __source = __source.Replace("</table>", "</ptable>");
                __source = __source.Replace("<h", "<p");
                __source = __source.Replace("</h", "</p");
                Utile.getListeFromModele(__source, "<p[*]</p", ref __valeurs, true);
                List<string> __paragraphes = new List<string>();
                foreach (string __valeur in __valeurs)
                {
                    string __valeurTemp = __valeur;
                    if (!__valeurTemp.EndsWith(">"))
                    {
                        __valeurTemp += ">";
                    }
                    __valeurTemp = Utile.delTags(__valeurTemp);
                    __valeurTemp = __valeurTemp.Replace("&nbsp;", " ");
                    __valeurTemp = __valeurTemp.Replace("\n", "");
                    __valeurTemp = __valeurTemp.Replace("\t", " ");
                    while (__valeurTemp.IndexOf("  ") != -1)
                    {
                        __valeurTemp = __valeurTemp.Replace("  ", " ");
                    }
                    __valeurTemp = __valeurTemp.Trim(' ');
                    if (__valeurTemp.Length > 1)
                    {
                        __paragraphes.Add(__valeurTemp);
                    }
                }
                __sr.Close();
                __sr.Dispose();
                string __fileOut = __file.Replace(".htm", ".txt");
                StreamWriter __sw = new StreamWriter(__fileOut, false, Encoding.UTF8);
                foreach (string __paragraphe in __paragraphes)
                {
                    __sw.WriteLine(__paragraphe);
                }
                __sw.Close();
                __sw.Dispose();
            }

            return new Page();
        }
    }
}
