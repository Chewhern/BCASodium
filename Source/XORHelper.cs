using System;
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
            uint[] Source1uint = new uint[Source1.Length];
            uint[] Source2uint = new uint[Source2.Length];
            uint[] xoreduint = new uint[Source1.Length];
            int Loop = 0;
            Byte[] XOREDByte = new Byte[Source1.Length];
            GCHandle MyGeneralGCHandle;
            Array.Copy(Source1, Source1uint, Source1.Length);
            Array.Copy(Source2, Source2uint, Source2.Length);
            while (Loop < Source1uint.Length)
            {
                xoreduint[Loop] = Source1uint[Loop] ^ Source2uint[Loop];
                Loop += 1;
            }
            Loop = 0;
            while (Loop < XOREDByte.Length)
            {
                XOREDByte[Loop] = (Byte)xoreduint[Loop];
                Loop += 1;
            }
            MyGeneralGCHandle = GCHandle.Alloc(Source1uint, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Source1uint.Length * 4);
            MyGeneralGCHandle.Free();
            MyGeneralGCHandle = GCHandle.Alloc(Source2uint, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), Source2uint.Length * 4);
            MyGeneralGCHandle.Free();
            MyGeneralGCHandle = GCHandle.Alloc(xoreduint, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), xoreduint.Length * 4);
            MyGeneralGCHandle.Free();
            return XOREDByte;
        }
    }
}
