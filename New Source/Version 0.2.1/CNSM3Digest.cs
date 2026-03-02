using System;
using Org.BouncyCastle.Crypto.Digests;

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
    }
}
