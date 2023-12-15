using System;
using Org.BouncyCastle.Crypto.Digests;

namespace BCASodium
{
    public static class KeccakDigestAlgorithm
    {
        private static KeccakDigest GlobalDigest = new KeccakDigest(256);
        public enum Digest_Length
        {
            Digest_128bits,
            Digest_224bits,
            Digest_256bits,
            Digest_288bits,
            Digest_384bits,
            Digest_512bits
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
