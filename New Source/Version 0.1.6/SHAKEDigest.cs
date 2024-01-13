using System;
using Org.BouncyCastle.Crypto.Digests;

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
            
            if (IsFinal == true)
            {
                GlobalDigest.DoFinal(HashedMessage, 0);
                GlobalDigest.Reset();
            }

            return HashedMessage;
        }
    }
}
