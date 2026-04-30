using System;
using ASodium;
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

        public X448RevampedKeyPair()
        {
            _publicKey = null;
            _privateKey = null;
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
            if (CheckIsNull() == false)
            {
                SodiumSecureMemory.SecureClearBytes(_privateKey);
                SodiumSecureMemory.SecureClearBytes(_publicKey);
            }
        }

        public Boolean CheckIsNull()
        {
            return _publicKey == null || _privateKey == null;
        }
    }
}
