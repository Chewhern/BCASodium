using System;
using System.Linq;
using Org.BouncyCastle.Crypto.Digests;
using ASodium;

namespace BCASodium
{
    public static class CNSM3Digest
    {
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

        public static Byte[] ComputeHashForNonFinalState(Byte[] Message, SM3Digest MyDigest, Boolean IsFinal = false)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message must not be null");
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

        public static Byte[] ComputeMAC(Byte[] Message, Byte[] Key, Boolean ClearKey = false)
        {
            SM3Digest MyDigest = new SM3Digest();
            //Nothing up my sleeve numbers that was taken from HMAC-SHA wikipedia
            //As SM3Digest uses Merkle-Damgard construction like MD4, MD5, SHA-1 and SHA-2, it might also be vulnerable to length extension attack
            Byte[] IPAD = new Byte[] { 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36 };
            Byte[] OPAD = new Byte[] { 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c };
            //Derive 2 keys by XOR-ing O/IPAD with the key
            Byte[] K1 = XORHelper.XOR(OPAD, Key);
            Byte[] K2 = XORHelper.XOR(IPAD, Key);
            Byte[] ConcatedMessageP2 = Message.Concat(K2).ToArray();
            Byte[] HashedCMessageP2 = CNSM3Digest.ComputeHashForNonFinalState(ConcatedMessageP2, MyDigest);
            Byte[] ConcatedMessage = K1.Concat(HashedCMessageP2).ToArray();
            Byte[] MAC = CNSM3Digest.ComputeHashForNonFinalState(ConcatedMessage, MyDigest, true);
            MyDigest.Reset();
            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }
            return MAC;
        }
    }
}
