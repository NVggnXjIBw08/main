using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace POB
{
    public class Main
    {

        const string PathTemp = @"C:\Temp\_pob\output";

        public void exportJson()
        {
            List<Page> __pages = new List<Page>();
            string[] __files = Directory.GetFiles(PathTemp, "*.htm");
            foreach (string __file in __files)
            {
                __pages.Add(Page.fromFile(__file));
            }
        }

    }
}
