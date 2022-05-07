using System;
using System.Linq;
using Org.BouncyCastle.Crypto.Digests;
using ASodium;

namespace BCASodium
{
    public static class KeccakDigestAlgorithm
    {
        public enum Digest_Length
        {
            Digest_128bits,
            Digest_224bits,
            Digest_256bits,
            Digest_288bits,
            Digest_384bits,
            Digest_512bits
        }

        public static KeccakDigest CreateKeccakDigest(Digest_Length MyDL = Digest_Length.Digest_128bits)
        {
            KeccakDigest MyDigest;
            if (MyDL == Digest_Length.Digest_128bits)
            {
                MyDigest = new KeccakDigest(128);
            }
            else if (MyDL == Digest_Length.Digest_224bits)
            {
                MyDigest = new KeccakDigest(224);
            }
            else if (MyDL == Digest_Length.Digest_256bits)
            {
                MyDigest = new KeccakDigest(256);
            }
            else if (MyDL == Digest_Length.Digest_288bits)
            {
                MyDigest = new KeccakDigest(288);
            }
            else if (MyDL == Digest_Length.Digest_384bits)
            {
                MyDigest = new KeccakDigest(384);
            }
            else
            {
                MyDigest = new KeccakDigest(512);
            }
            return MyDigest;
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
            else if (MyDL == Digest_Length.Digest_224bits)
            {
                DigestLengthInBytes = 224 / 8;
                DigestLengthInBits = 224;
            }
            else if (MyDL == Digest_Length.Digest_256bits)
            {
                DigestLengthInBytes = 256 / 8;
                DigestLengthInBits = 256;
            }
            else if (MyDL == Digest_Length.Digest_288bits)
            {
                DigestLengthInBytes = 288 / 8;
                DigestLengthInBits = 288;
            }
            else if (MyDL == Digest_Length.Digest_384bits)
            {
                DigestLengthInBytes = 384 / 8;
                DigestLengthInBits = 384;
            }
            else
            {
                DigestLengthInBytes = 512 / 8;
                DigestLengthInBits = 512;
            }
            HashedMessage = new Byte[DigestLengthInBytes];
            KeccakDigest MyDigest = new KeccakDigest(DigestLengthInBits);
            MyDigest.BlockUpdate(Message, 0, Message.Length);
            MyDigest.DoFinal(HashedMessage, 0);
            MyDigest.Reset();

            return HashedMessage;
        }

        public static Byte[] ComputeHashForNonFinalizedData(Byte[] Message, ref KeccakDigest MyDigest, Boolean IsFinal = false)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message can't be null");
            }
            Byte[] HashedMessage = new Byte[MyDigest.GetDigestSize()];
            MyDigest.BlockUpdate(Message, 0, Message.Length);
            MyDigest.DoFinal(HashedMessage, 0);
            if (IsFinal == true)
            {
                MyDigest.Reset();
            }

            return HashedMessage;
        }

        public static Byte[] ComputeHMAC(Byte[] Message, Byte[] Key, Boolean ClearKey = false)
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
                if (Key.Length != 32)
                {
                    throw new ArgumentException("Error: Key must exactly be 32 bytes long or 256 bits long");
                }
            }
            KeccakDigest MyDigest = new KeccakDigest(256);
            //Nothing up my sleeve numbers that was taken from HMAC-SHA wikipedia
            Byte[] IPAD = new Byte[] { 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36 };
            Byte[] OPAD = new Byte[] { 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c };
            Byte[] K1 = XORHelper.XOR(OPAD, Key);
            Byte[] K2 = XORHelper.XOR(IPAD, Key);
            Byte[] ConcatedMessageP2 = Message.Concat(K2).ToArray();
            Byte[] HashedCMessageP2 = ComputeHashForNonFinalizedData(ConcatedMessageP2, ref MyDigest);
            Byte[] ConcatedMessage = K1.Concat(HashedCMessageP2).ToArray();
            Byte[] MAC = ComputeHashForNonFinalizedData(ConcatedMessage, ref MyDigest, true);
            MyDigest.Reset();
            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }
            return MAC;
        }
    }
}
