using System;
using System.Runtime.InteropServices;
using ASodium;

namespace BCASodium
{
    public class ED448RevampedKeyPair
    {
        private readonly byte[] _publicKey;
        private readonly byte[] _privateKey;

        public ED448RevampedKeyPair(byte[] publicKey, byte[] privateKey)
        {
            //verify that the private key length is exactly 57 bytes
            if (privateKey.Length != 57)
                throw new ArgumentException("Private Key length must be 57 bytes.");

            _publicKey = publicKey;

            _privateKey = privateKey;
        }

        ~ED448RevampedKeyPair()
        {
            Clear();
        }

        /// <summary>Gets the Public Key.</summary>
        public byte[] PublicKey
        {
            get { return _publicKey; }
        }

        /// <summary>Gets the Private Key.</summary>
        public byte[] PrivateKey
        {
            get
            {
                return _privateKey;
            }
        }

        /// <summary>Clear private key and public key through cryptographically secure way.</summary>
        public void Clear()
        {
            GCHandle MyGeneralGCHandle = GCHandle.Alloc(_privateKey, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), _privateKey.Length);
            MyGeneralGCHandle.Free();
            MyGeneralGCHandle = GCHandle.Alloc(_publicKey, GCHandleType.Pinned);
            SodiumSecureMemory.MemZero(MyGeneralGCHandle.AddrOfPinnedObject(), _publicKey.Length);
            MyGeneralGCHandle.Free();
        }
    }
}
