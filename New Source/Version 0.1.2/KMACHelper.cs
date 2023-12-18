using System;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using ASodium;
using System.Runtime.InteropServices;

namespace BCASodium
{
    public static class KMACHelper
    {
        private static KMac GlobalKMAC = new KMac(256,null);
        private static Boolean IsKMACInitialized = false;

        public static Byte[] ComputeKMAC(Byte[] Key,Byte[] Message,Boolean ClearKey=false)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message can't be null");
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key can't be null");
            }
            else 
            {
                if (Key.Length < 32) 
                {
                    throw new ArgumentException("Error: Original KMAC in BouncyCastle allows for keys that has weak length,I have make a condition here by forcing its minimum length as 32 bytes or 256 bits");
                }
            }
            KMac myKMAC = new KMac(256, null);

            myKMAC.Init(new KeyParameter(Key,0,Key.Length));

            myKMAC.BlockUpdate(Message, 0, Message.Length);

            Byte[] KMAC = new Byte[32];

            myKMAC.DoOutput(KMAC, 0, KMAC.Length);

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }

            return KMAC;
        }

        //MPM = Multi Part Message
        public static Byte[] ComputeKMACMPM(Byte[] Message, Boolean IsFinal = false, Byte[] Key=null,Boolean ClearKey=false)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message can't be null");
            }
            if (Key == null)
            {
                if (IsKMACInitialized == false) 
                {
                    throw new ArgumentException("Error: Key can't be null");
                }
            }
            else
            {
                if (Key.Length < 32)
                {
                    throw new ArgumentException("Error: Original KMAC in BouncyCastle allows for keys that has weak length,I have make a condition here by forcing its minimum length as 32 bytes or 256 bits");
                }
            }

            if (IsKMACInitialized == false)
            {
                IsKMACInitialized = true;
                GlobalKMAC.Init(new KeyParameter(Key, 0, Key.Length));
            }

            Byte[] KMAC = new Byte[32];

            GlobalKMAC.BlockUpdate(Message,0, Message.Length);

            if (IsFinal == true) 
            {
                GlobalKMAC.DoFinal(KMAC, 0, KMAC.Length);
                GlobalKMAC.Reset();
            }

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
                IsKMACInitialized = false;
            }

            return KMAC;
        }

        public static Boolean VerifyKMAC(Byte[] KMAC, Byte[] Message, Byte[] Key,Boolean ClearKey=false) 
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message can't be null");
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key can't be null");
            }
            else
            {
                if (Key.Length < 32)
                {
                    throw new ArgumentException("Error: Original KMAC in BouncyCastle allows for keys that has weak length,I have make a condition here by forcing its minimum length as 32 bytes or 256 bits");
                }
            }
            if (KMAC == null)
            {
                throw new ArgumentException("Error: KMAC can't be null");
            }
            else 
            {
                if (KMAC.Length != 32) 
                {
                    throw new ArgumentException("Error: KMAC length must exactly be 32 bytes or 256 bits in length");
                }
            }

            Byte[] CKMAC = ComputeKMAC(Key, Message);

            GCHandle MyGeneralGCHandle = GCHandle.Alloc(CKMAC, GCHandleType.Pinned);
            
            GCHandle MyGeneralGCHandle1 = GCHandle.Alloc(KMAC, GCHandleType.Pinned);
            
            SodiumHelper.Sodium_Memory_Compare(MyGeneralGCHandle.AddrOfPinnedObject(), MyGeneralGCHandle1.AddrOfPinnedObject(), 32);

            MyGeneralGCHandle.Free();
            MyGeneralGCHandle1.Free();
            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
                IsKMACInitialized = false;
            }

            return true;
        }
    }
}
