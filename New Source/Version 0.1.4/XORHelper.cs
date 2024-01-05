using System;

namespace BCASodium
{
    public static class XORHelper
    {
        //General purpose XOR
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

        //Cryptographical XOR
        //Slightly constant time and using array 1 as both input and output destination
        //It's also recommended to not expose the result array length
        public static void SCTXOR(Byte[] InputAndOutputSource, Byte[] Source2)
        {
            if (InputAndOutputSource == null)
            {
                throw new ArgumentException("Error: Input and output source byte array can't be null");
            }
            if (Source2 == null)
            {
                throw new ArgumentException("Error: Source2 byte array can't be null");
            }
            if (InputAndOutputSource.Length != Source2.Length)
            {
                throw new ArgumentException("Error: Input and output source and source2 byte array length must be the same");
            }
            int Loop = 0;
            while (Loop < InputAndOutputSource.Length)
            {
                InputAndOutputSource[Loop] ^= Source2[Loop];
                Loop += 1;
            }
        }
    }
}
