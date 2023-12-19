using System;
using ASodium;
using System.Runtime.InteropServices;
using Org.BouncyCastle.Math.EC.Rfc7748;

namespace BCASodium
{
    public class X448RevampedKeyPair
    {
        private readonly byte[] _publicKey;
        private readonly byte[] _privateKey;

        public X448RevampedKeyPair(byte[] publicKey, byte[] privateKey)
        {
            //verify that the private key length is exactly 56 bytes
            if (privateKey.Length != X448.ScalarSize)
                throw new ArgumentException("Private Key length must be 56 bytes long.");

            if(publicKey.Length != X448.PointSize) 
            {
                throw new ArgumentException("Public Key length must be 56 bytes long.");
            }

            _publicKey = publicKey;

            _privateKey = privateKey;
        }

        ~X448RevampedKeyPair()
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
            SodiumSecureMemory.SecureClearBytes(_publicKey);
            SodiumSecureMemory.SecureClearBytes(_privateKey);
        }
    }
}
