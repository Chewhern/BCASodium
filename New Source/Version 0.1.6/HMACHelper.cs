using ASodium;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Security.Cryptography;

namespace BCASodium
{
    public static class HMACHelper
    {
        public static Byte[] ComputeHMAC(IDigest myDigest,Byte[] Message, Byte[] Key, Boolean ClearKey = false)
        {
            if (myDigest == null) 
            {
                throw new ArgumentException("Error: You must specify a digest");
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key can't be null");
            }
            if (Key.Length % 16 != 0)
            {
                throw new ArgumentException("Error: Key length must be divisible by 16");
            }
            if (Message == null)
            {
                throw new ArgumentException("Error: Message can't be null");
            }
            HMac myHMAC = new HMac(myDigest);
            myHMAC.Init(new KeyParameter(Key));
            myHMAC.BlockUpdate(Message, 0, Message.Length);
            Byte[] HMAC = new Byte[myHMAC.GetMacSize()];
            myHMAC.DoFinal(HMAC, 0);
            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }
            return HMAC;
        }

        public static Boolean VerifyHMAC(IDigest myDigest, Byte[] Message, Byte[] SHMAC ,Byte[] Key, Boolean ClearKey = false)
        {
            if (myDigest == null)
            {
                throw new ArgumentException("Error: You must specify a digest");
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key can't be null");
            }
            if (Key.Length % 16 != 0)
            {
                throw new ArgumentException("Error: Key length must be divisible by 16");
            }
            if (Message == null)
            {
                throw new ArgumentException("Error: Message can't be null");
            }
            if (SHMAC == null)
            {
                throw new ArgumentException("Error: Supplied HMAC must not be null");
            }
            HMac myHMAC = new HMac(myDigest);
            myHMAC.Init(new KeyParameter(Key));
            myHMAC.BlockUpdate(Message, 0, Message.Length);
            Byte[] HMAC = new Byte[myHMAC.GetMacSize()];
            if (HMAC.Length != SHMAC.Length)
            {
                throw new ArgumentException("Error: HMAC length and supplied HMAC length must be the same.");
            }
            myHMAC.DoFinal(HMAC, 0);
            try
            {
                SodiumHelper.Sodium_Memory_Compare(SHMAC, HMAC);
            }
            catch
            {
                throw new CryptographicException("Error: Ciphertext had been tampered");
            }
            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }
            return true;
        }
    }
}
