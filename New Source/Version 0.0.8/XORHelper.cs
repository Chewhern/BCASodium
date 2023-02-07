using System;
using System.Linq;
using System.Runtime.InteropServices;
using ASodium;

namespace BCASodium
{
    public static class XORHelper
    {
        //There're many XOR versions
        //One require developer to XOR between 2 byte[] array
        //The other one was shown below
        //Any users who use this XOR function for cryptographical use, please do bear in mind this is only 50% secure/safe.
        //All possible data have been cleared in memory but there may be other factors which makes it not secure.
        public static Byte[] XOR(Byte[] Source1, Byte[] Source2)
        {
            if (Source1 == null)
            {
                throw new ArgumentException("Error: Source1 byte array can't be null");
            }
            if (Source2 == null)
            {
                throw new ArgumentException("Error: Source2 byte array can't be null");
            }
            if (Source1.Length != Source2.Length)
            {
                throw new ArgumentException("Error: Source1 and source2 byte array length must be the same");
            }
            int Loop = 0;
            Byte[] XOREDByte = new Byte[Source1.Length];
            while (Loop < XOREDByte.Length)
            {
                XOREDByte[Loop] = (Byte)(Source1[Loop] ^ Source2[Loop]);
                Loop += 1;
            }
            return XOREDByte;
        }
    }
}
