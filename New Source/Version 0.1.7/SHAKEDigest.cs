using System;
using Org.BouncyCastle.Crypto.Digests;

namespace BCASodium
{
    public static class SHAKEDigest
    {
        private static ShakeDigest GlobalDigest = new ShakeDigest(256);

        //Actually, it's true that SHAKE accepts only 128 bits and 256 bits if you were to
        //declare a size for the SHAKE algorithm(BouncyCastle).
        //However, the actual output of the SHAKE algorithm is the declared size * 2.
        //If developer declared the size of the SHAKE is 128 bits, then the output size of
        //the hashed message will be 256 bits.
        //Similar situations can be said to 256 bits. 
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
            int DigestLengthInBits = 0;
            if (MyDL == Digest_Length.Digest_128bits)
            {
                DigestLengthInBits = 128;
            }
            else
            {
                DigestLengthInBits = 256;
            }
            ShakeDigest MyDigest = new ShakeDigest(DigestLengthInBits);
            HashedMessage = new Byte[MyDigest.GetDigestSize()];
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
