using System;
using Org.BouncyCastle.Math.EC.Rfc7748;
using ASodium;
using System.Runtime.InteropServices;

namespace BCASodium
{
    public class SecureX448
    {
        public static X448RevampedKeyPair GenerateX448RevampedKeyPair()
        {
            Byte[] X448SK = SodiumRNG.GetRandomBytes(X448.ScalarSize);
            Byte[] X448PK = new Byte[X448.PointSize];

            X448.GeneratePublicKey(X448SK, 0, X448PK, 0);

            X448RevampedKeyPair MyKeyPair = new X448RevampedKeyPair(X448PK, X448SK);

            return MyKeyPair;
        }

        public static KeyPair GenerateKeyPair()
        {
            Byte[] X448SK = SodiumRNG.GetRandomBytes(X448.ScalarSize);
            Byte[] X448PK = new Byte[X448.PointSize];

            X448.GeneratePublicKey(X448SK, 0, X448PK, 0);

            KeyPair MyKeyPair;
            Boolean IsZero1 = true;
            Boolean IsZero2 = true;
            IntPtr SecretKeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero1, X448SK.Length);
            IntPtr PublicKeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero2, X448PK.Length);

            if (IsZero1 == false && IsZero2 == false)
            {
                Marshal.Copy(X448PK, 0, PublicKeyIntPtr, X448PK.Length);
                Marshal.Copy(X448SK, 0, SecretKeyIntPtr, X448SK.Length);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(PublicKeyIntPtr);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(SecretKeyIntPtr);
                MyKeyPair = new KeyPair(SecretKeyIntPtr, X448SK.Length, PublicKeyIntPtr, X448PK.Length);
            }
            else
            {
                MyKeyPair = new KeyPair(IntPtr.Zero, 0, IntPtr.Zero, 0);
            }

            SodiumSecureMemory.SecureClearBytes(X448SK);
            SodiumSecureMemory.SecureClearBytes(X448PK);

            return MyKeyPair;
        }

        public static Byte[] GeneratePublicKey(Byte[] X448SK, Boolean ClearKey = false)
        {
            Byte[] X448PK = new Byte[X448.PointSize];

            if (X448SK == null)
            {
                throw new ArgumentException("Error: X448SK can't be null");
            }
            if (X448SK.Length != X448.ScalarSize)
            {
                throw new ArgumentException("Error: X448SK must exactly be " + X448.ScalarSize + " bytes in length");
            }

            X448.GeneratePublicKey(X448SK, 0, X448PK, 0);

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(X448SK);
            }
            return X448PK;
        }

        public static Byte[] CalculateSecret(Byte[] OthersPublicKey, Byte[] YourPrivateKey, Boolean ClearPrivateKey = false)
        {
            if (YourPrivateKey.Length != X448.ScalarSize)
            {
                throw new ArgumentException("Error: Private key length must be exactly " + X448.ScalarSize.ToString() + " bytes");
            }
            if (OthersPublicKey.Length != X448.PointSize)
            {
                throw new ArgumentException("Error: Public key length must be exactly " + X448.PointSize.ToString() + " bytes");
            }

            Byte[] SharedSecret = new Byte[56];
            if (!X448.CalculateAgreement(YourPrivateKey, 0, OthersPublicKey, 0, SharedSecret, 0))
            {
                throw new InvalidOperationException("X448 agreement failed");
            }
            if (ClearPrivateKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(YourPrivateKey);
            }
            return SharedSecret;
        }
    }
}
