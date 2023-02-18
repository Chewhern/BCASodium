using System;
using System.Linq;
using Org.BouncyCastle.Crypto.Digests;
using ASodium;

namespace BCASodium
{
    public static class SHAKEDigest
    {
        private static ShakeDigest GlobalDigest = new ShakeDigest(256);

        public enum Digest_Length
        {
            Digest_128bits,
            Digest_256bits
        }

        public static Byte[] ComputeHash(Byte[] Message, Digest_Length MyDL = Digest_Length.Digest_128bits)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message can't be null");
            }
            Byte[] HashedMessage = new Byte[] { };
            int DigestLengthInBytes = 0;
            int DigestLengthInBits = 0;
            if (MyDL == Digest_Length.Digest_128bits)
            {
                DigestLengthInBytes = 128 / 8;
                DigestLengthInBits = 128;
            }
            else
            {
                DigestLengthInBytes = 256 / 8;
                DigestLengthInBits = 256;
            }
            HashedMessage = new Byte[DigestLengthInBytes];
            ShakeDigest MyDigest = new ShakeDigest(DigestLengthInBits);
            MyDigest.BlockUpdate(Message, 0, Message.Length);
            MyDigest.DoFinal(HashedMessage, 0);
            MyDigest.Reset();

            return HashedMessage;
        }

        public static Byte[] ComputeHashForNonFinalizedData(Byte[] Message, Boolean IsFinal = false)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message can't be null");
            }
            Byte[] HashedMessage = new Byte[GlobalDigest.GetDigestSize()];
            GlobalDigest.BlockUpdate(Message, 0, Message.Length);
            GlobalDigest.DoFinal(HashedMessage, 0);
            if (IsFinal == true)
            {
                GlobalDigest.Reset();
            }

            return HashedMessage;
        }

        public static Byte[] ComputeHMAC(Byte[] Message, Byte[] Key,Boolean UsePrivateContext = false ,Boolean ClearKey = false)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message must not be null");
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key must not be null");
            }
            else
            {
                if (Key.Length > 32)
                {
                    if (Key.Length % 16 != 0)
                    {
                        throw new ArgumentException("Error: Key length must be divisible by 16");
                    }
                }
                else if (Key.Length != 32) 
                {
                    throw new ArgumentException("Error: Key must exactly be 32 bytes long or 256 bits long");
                }
            }
            Byte[] KeyWithoutContexts = new Byte[] { };
            //Nothing up my sleeve numbers
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
                PreIKey = SodiumKDF.KDFFunction(32, 1, Context1, KeyWithoutContexts);
                PreOKey = SodiumKDF.KDFFunction(32, 1, Context2, KeyWithoutContexts);
                SodiumSecureMemory.SecureClearBytes(Context1);
                SodiumSecureMemory.SecureClearBytes(Context2);
            }
            else
            {
                PreIKey = SodiumKDF.KDFFunction(32, 1, Context1, Key);
                PreOKey = SodiumKDF.KDFFunction(32, 1, Context2, Key);
            }
            //Nothing up my sleeve numbers that was taken from HMAC-SHA wikipedia
            Byte[] IPAD = new Byte[] { 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36 };
            Byte[] OPAD = new Byte[] { 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c };
            Byte[] IKey = XORHelper.XOR(OPAD, Key);
            Byte[] OKey = XORHelper.XOR(IPAD, Key);
            Byte[] ConcatedMessageP2 = Message.Concat(OKey).ToArray();
            Byte[] HashedCMessageP2 = ComputeHashForNonFinalizedData(ConcatedMessageP2);
            Byte[] ConcatedMessage = IKey.Concat(HashedCMessageP2).ToArray();
            Byte[] MAC = ComputeHashForNonFinalizedData(ConcatedMessage, true);
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
