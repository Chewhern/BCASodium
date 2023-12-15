using System;
using System.Linq;
using Org.BouncyCastle.Crypto.Digests;
using ASodium;

namespace BCASodium
{
    public static class CNSM3Digest
    {
        private static SM3Digest GlobalDigest = new SM3Digest();

        public static Byte[] ComputeHash(Byte[] Message)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message must not be null");
            }
            SM3Digest Digest = new SM3Digest();
            Byte[] HashedMessage = new Byte[Digest.GetDigestSize()];
            Digest.BlockUpdate(Message, 0, Message.Length);
            Digest.DoFinal(HashedMessage, 0);
            Digest.Reset();
            return HashedMessage;
        }

        public static Byte[] ComputeHashForNonFinalizedData(Byte[] Message, Boolean IsFinal = false)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message must not be null");
            }
            Byte[] HashedMessage = new Byte[GlobalDigest.GetDigestSize()];
            GlobalDigest.BlockUpdate(Message, 0, Message.Length);
            
            if (IsFinal == true)
            {
                GlobalDigest.DoFinal(HashedMessage, 0);
                GlobalDigest.Reset();
            }
            return HashedMessage;
        }

        public static Byte[] ComputeHMAC(Byte[] Message, Byte[] Key, Boolean UsePrivateContext = false ,Boolean ClearKey = false)
        {
            //Nothing up my sleeve numbers that was taken from HMAC-SHA wikipedia
            //As SM3Digest uses Merkle-Damgard construction like MD4, MD5, SHA-1 and SHA-2, it might also be vulnerable to length extension attack
            if (Key == null) 
            {
                throw new ArgumentException("Error: Key can't be null");
            }
            if (Key.Length % 16 != 0) 
            {
                throw new ArgumentException("Error: Key length must be divisible by 16");
            }
            Byte[] KeyWithoutContexts = new Byte[] { } ;
            Byte[] Context1 = SodiumHelper.HexToBinary("3348019bbca7e4c2");
            Byte[] Context2 = SodiumHelper.HexToBinary("49ff254b646e339e");
            Byte[] PreIKey = new Byte[] { };
            Byte[] PreOKey = new Byte[] { };
            if (UsePrivateContext == true)
            {
                KeyWithoutContexts = new Byte[Key.Length - 16];
                Array.Copy(Key, Key.Length - 16, Context1, 0, 8);
                Array.Copy(Key, Key.Length - 8, Context2, 0, 8);
                Array.Copy(Key, 0, KeyWithoutContexts, 0, Key.Length - 16);
                PreIKey = SodiumKDF.KDFFunction(16, 1, Context1, KeyWithoutContexts);
                PreOKey = SodiumKDF.KDFFunction(16, 1, Context2, KeyWithoutContexts);
                SodiumSecureMemory.SecureClearBytes(Context1);
                SodiumSecureMemory.SecureClearBytes(Context2);
            }
            else 
            {
                PreIKey = SodiumKDF.KDFFunction(16, 1, Context1, Key);
                PreOKey = SodiumKDF.KDFFunction(16, 1, Context2, Key);
            }
            Byte[] IPAD = new Byte[] { 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36 };
            Byte[] OPAD = new Byte[] { 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c };
            //Derive 2 keys by XOR-ing O/IPAD with the key
            Byte[] IKey = XORHelper.XOR(OPAD, PreIKey);
            Byte[] OKey = XORHelper.XOR(IPAD, PreOKey);
            Byte[] ConcatedMessageP2 = Message.Concat(OKey).ToArray();
            SM3Digest Digest = new SM3Digest();
            Digest.BlockUpdate(ConcatedMessageP2,0,ConcatedMessageP2.Length);
            Byte[] HashedCMessageP2 = new Byte[Digest.GetDigestSize()];
            Digest.DoFinal(HashedCMessageP2,0);
            Byte[] ConcatedMessage = IKey.Concat(HashedCMessageP2).ToArray();
            Digest.BlockUpdate(ConcatedMessage, 0, ConcatedMessage.Length);
            Byte[] MAC = new byte[32];
            Digest.DoFinal(MAC, 0);
            Digest.Reset();
            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }
            SodiumSecureMemory.SecureClearBytes(IKey);
            SodiumSecureMemory.SecureClearBytes(OKey);
            SodiumSecureMemory.SecureClearBytes(PreIKey);
            SodiumSecureMemory.SecureClearBytes(PreOKey);
            return MAC;
        }
    }
}
