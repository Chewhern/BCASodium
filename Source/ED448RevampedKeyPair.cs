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
                throw new ArgumentException("Private Key length must be a multiple of 57 bytes.");

            _publicKey = publicKey;

            _privateKey = privateKey;
            _ProtectKey();
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
                _UnprotectKey();
                var tmp = new byte[_privateKey.Length];
                Array.Copy(_privateKey, tmp, tmp.Length);
                _ProtectKey();

                return tmp;
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

        private void _ProtectKey()
        {
            #if NET461
                ProtectedMemory.Protect(_privateKey, MemoryProtectionScope.SameProcess);
            #endif
        }

        private void _UnprotectKey()
        {
            #if NET461
                ProtectedMemory.Unprotect(_privateKey, MemoryProtectionScope.SameProcess);
            #endif
        }
    }
}
