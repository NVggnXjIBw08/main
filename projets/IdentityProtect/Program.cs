using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Net;
using System.Threading;

namespace spe.main
{
    class Program
    {
        static void Main(string[] args)
        {
            Identity __identity = new Identity();
            int __index = 0;
            while (__index < 1)
            {
                __identity.create();
                __identity.save();
                Thread.Sleep(1);
                __index++;
            }
        }
    }
}
