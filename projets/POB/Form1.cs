using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;

namespace WindowsFormsApplicationIE
{
    public partial class Form1 : Form
    {

        private bool First = true;
        private List<string> Liens = new List<string>();
        private int Index = 0;

        public Form1()
        {
            InitializeComponent();
        }

        private void webBrowser1_DocumentCompleted(object sender, WebBrowserDocumentCompletedEventArgs e)
        {
            timer1.Start();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            timer1.Interval = 10000;
            timer1.Stop();
            webBrowser1.Navigate("http://www.pob-basket.com");
        }

        private void timer1_Tick(object sender, EventArgs e)
        {
            timer1.Stop();
            string __title = webBrowser1.Document.Title.Replace("|", "-");
            string __body = webBrowser1.Document.Body.InnerHtml;
            if (First)
            {
                getListeFromModele(__body, "href=\"#![*]\"", ref Liens, false, true);
                First = false;
            }
            string __path = @"C:\Temp\_pob\output";
            string __file = String.Format(@"{0}\{1}.htm", __path, __title);
            if (File.Exists(__file))
            {
                __file = String.Format(@"{0}\{1}.{2}.htm", __path, __title, Index);
            }
            StreamWriter __sr = new StreamWriter(__file, false, Encoding.UTF8);
            __sr.Write(__body);
            __sr.Close();
            suivant();
        }

        private void suivant()
        {
            if (Index < Liens.Count - 1)
            {
                string __lien = Liens[Index];
                string __url = "http://www.pob-basket.com/#!" + __lien;
                webBrowser1.Navigate(__url);
                Application.DoEvents();
                Index++;
            }
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

    }
}
