using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;

namespace MongoDB.MongoCrypt
{
    /*
     * Windows:
     * https://stackoverflow.com/questions/2864673/specify-the-search-path-for-dllimport-in-net
     *
     * See for better ways
     * https://github.com/dotnet/coreclr/issues/930
     * https://github.com/dotnet/corefx/issues/32015
     *
     */
    public class Library
    {
        static Library()
        {
            LibraryLoader loader = new LibraryLoader();

            mongocrypt_init = loader.getFunction<Delegates.mongocrypt_init>("mongocrypt_init");
            mongocrypt_version = loader.getFunction<Delegates.mongocrypt_version>("mongocrypt_version");
        }

        public static string Version
        {
            get {
                IntPtr p = mongocrypt_version();
                return Marshal.PtrToStringAnsi(p);
            }
        }

        public static readonly Delegates.mongocrypt_init mongocrypt_init;
        public static readonly Delegates.mongocrypt_version mongocrypt_version;

        public class Delegates
        {
            public delegate void mongocrypt_init();
            public delegate IntPtr mongocrypt_version();
        }
    }
}