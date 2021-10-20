using System;
using Org.BouncyCastle.Crypto.Digests;

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

        public static Byte[] ComputeHashForMAC(Byte[] Message, SM3Digest MyDigest, Boolean IsFinal = false)
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
    }
}
