using System;
using System.Linq;
using Org.BouncyCastle.Math.EC.Rfc8032;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using ASodium;

namespace BCASodium
{
    public static class SecureED448
    {
        public enum PRFFunctionChooser 
        {
            XChaCha20=1,
            XSalsa20=2,
            ChaCha20=3,
            Salsa20=4
        }

        public static ED448RevampedKeyPair GenerateED448RevampedKeyPair()
        {
            Byte[] ED448SK = SodiumRNG.GetRandomBytes(Ed448.SecretKeySize);
            Byte[] ED448PK = new Byte[Ed448.PublicKeySize];

            Ed448.GeneratePublicKey(ED448SK, 0, ED448PK, 0);

            ED448RevampedKeyPair MyKeyPair = new ED448RevampedKeyPair(ED448PK, ED448SK);

            return MyKeyPair;
        }

        public static Byte[] GeneratePublicKey(Byte[] ED448SK, Boolean ClearKey = false)
        {
            Byte[] ED448PK = new Byte[Ed448.PublicKeySize];

            if (ED448SK == null)
            {
                throw new ArgumentException("Error: ED448SK can't be null");
            }
            if (ED448SK.Length != Ed448.SecretKeySize)
            {
                throw new ArgumentException("Error: ED448SK must exactly be " + Ed448.SecretKeySize + " bytes in length");
            }

            Ed448.GeneratePublicKey(ED448SK, 0, ED448PK, 0);
            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(ED448SK);
            }
            return ED448PK;
        }

        public static KeyPair GenerateKeyPair()
        {
            Byte[] ED448SK = SodiumRNG.GetRandomBytes(Ed448.SecretKeySize);
            Byte[] ED448PK = new Byte[Ed448.PublicKeySize];

            Ed448.GeneratePublicKey(ED448SK, 0, ED448PK, 0);

            KeyPair MyKeyPair;
            Boolean IsZero1 = true;
            Boolean IsZero2 = true;
            IntPtr SecretKeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero1, ED448SK.Length);
            IntPtr PublicKeyIntPtr = SodiumGuardedHeapAllocation.Sodium_Malloc(ref IsZero2, ED448PK.Length);

            if (IsZero1 == false && IsZero2 == false)
            {
                Marshal.Copy(ED448PK, 0, PublicKeyIntPtr, ED448PK.Length);
                Marshal.Copy(ED448SK, 0, SecretKeyIntPtr, ED448SK.Length);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(PublicKeyIntPtr);
                SodiumGuardedHeapAllocation.Sodium_MProtect_NoAccess(SecretKeyIntPtr);
                MyKeyPair = new KeyPair(SecretKeyIntPtr, ED448SK.Length, PublicKeyIntPtr, ED448PK.Length);
            }
            else
            {
                MyKeyPair = new KeyPair(IntPtr.Zero, 0, IntPtr.Zero, 0);
            }

            SodiumSecureMemory.SecureClearBytes(ED448SK);
            SodiumSecureMemory.SecureClearBytes(ED448PK);

            return MyKeyPair;
        }

        public static Byte[] Sign(Byte[] SecretKey, Byte[] Message, Byte[] Context, Boolean ClearKey = false,PRFFunctionChooser chooser=PRFFunctionChooser.XChaCha20)
        {
            if (SecretKey.Length != Ed448.SecretKeySize)
            {
                throw new ArgumentException("Error: Secret Key must be " + Ed448.SecretKeySize.ToString() + " bytes in length");
            }
            if (Message == null)
            {
                throw new ArgumentException("Error: Message can't be null");
            }
            Byte[] Signature = new Byte[Ed448.SignatureSize];
            Byte[] PublicKey = GeneratePublicKey(SecretKey);
            Byte[] HashedPublicKey = SodiumGenericHash.ComputeHash(32, PublicKey);
            Byte[] RandomPaddingData = new Byte[] { };
            Byte[] XNonce = SodiumHelper.HexToBinary("5ccfd45f3b32216fc5e1a866ef3be9695fd39a956d2ce1b1");
            Byte[] Nonce = SodiumHelper.HexToBinary("042f8cd8a24b263f");

            if (Message.Length <= 114) 
            {
                if (chooser == PRFFunctionChooser.XChaCha20)
                {
                    RandomPaddingData = SodiumPRF.XChaCha20PRF(115-Message.Length, XNonce, HashedPublicKey, true);
                }
                else if (chooser == PRFFunctionChooser.XSalsa20)
                {
                    RandomPaddingData = SodiumPRF.XSalsa20PRF(115 - Message.Length, XNonce, HashedPublicKey, true);
                }
                else if (chooser == PRFFunctionChooser.ChaCha20)
                {
                    RandomPaddingData = SodiumPRF.ChaCha20PRF(115 - Message.Length, Nonce, HashedPublicKey, true);
                }
                else
                {
                    RandomPaddingData = SodiumPRF.Salsa20PRF(115 - Message.Length, Nonce, HashedPublicKey, true);
                }
                Message = Message.Concat(RandomPaddingData).ToArray();
            }            

            Ed448.Sign(SecretKey, 0, Context, Message, 0, Message.Length, Signature, 0);
            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(SecretKey);
            }
            return Signature;
        }

        public static Boolean Verify(Byte[] PublicKey, Byte[] Message, Byte[] Signature, Byte[] Context, PRFFunctionChooser chooser = PRFFunctionChooser.XChaCha20)
        {
            if (PublicKey.Length != Ed448.PublicKeySize)
            {
                throw new ArgumentException("Error: Public Key must be " + Ed448.PublicKeySize.ToString() + " bytes in length");
            }
            if (Message == null)
            {
                throw new ArgumentException("Error: Message can't be null");
            }
            if (Signature.Length != Ed448.SignatureSize)
            {
                throw new ArgumentException("Error: Signature must be " + Ed448.SignatureSize.ToString() + " bytes in length");
            }
            Boolean CanVerify = true;

            Byte[] HashedPublicKey = SodiumGenericHash.ComputeHash(32, PublicKey);
            Byte[] RandomPaddingData = new Byte[] { };
            Byte[] XNonce = SodiumHelper.HexToBinary("5ccfd45f3b32216fc5e1a866ef3be9695fd39a956d2ce1b1");
            Byte[] Nonce = SodiumHelper.HexToBinary("042f8cd8a24b263f");

            if (Message.Length <= 114)
            {
                if (chooser == PRFFunctionChooser.XChaCha20)
                {
                    RandomPaddingData = SodiumPRF.XChaCha20PRF(115 - Message.Length, XNonce, HashedPublicKey, true);
                }
                else if (chooser == PRFFunctionChooser.XSalsa20)
                {
                    RandomPaddingData = SodiumPRF.XSalsa20PRF(115 - Message.Length, XNonce, HashedPublicKey, true);
                }
                else if (chooser == PRFFunctionChooser.ChaCha20)
                {
                    RandomPaddingData = SodiumPRF.ChaCha20PRF(115 - Message.Length, Nonce, HashedPublicKey, true);
                }
                else
                {
                    RandomPaddingData = SodiumPRF.Salsa20PRF(115 - Message.Length, Nonce, HashedPublicKey, true);
                }
                Message = Message.Concat(RandomPaddingData).ToArray();
            }

            CanVerify = Ed448.Verify(Signature, 0, PublicKey, 0, Context, Message, 0, Message.Length);

            return CanVerify;
        }

        public static Byte[] GenerateSignatureMessage(Byte[] SecretKey, Byte[] Message, Byte[] Context, Boolean ClearKey = false) 
        {
            if (SecretKey.Length != Ed448.SecretKeySize)
            {
                throw new ArgumentException("Error: Secret Key must be " + Ed448.SecretKeySize.ToString() + " bytes in length");
            }
            if (Message == null)
            {
                throw new ArgumentException("Error: Message can't be null");
            }
            Byte[] Signature = Sign(SecretKey, Message, Context);
            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(SecretKey);
            }
            Byte[] SignatureMessage = Signature.Concat(Message).ToArray();
            return SignatureMessage;
        }

        public static Byte[] GetMessageFromSignatureMessage(Byte[] PublicKey, Byte[] SignatureMessage, Byte[] Context) 
        {
            if (PublicKey.Length != Ed448.PublicKeySize)
            {
                throw new ArgumentException("Error: Public Key must be " + Ed448.PublicKeySize.ToString() + " bytes in length");
            }
            Byte[] Signature = new Byte[Ed448.SignatureSize];
            Byte[] Message = new Byte[SignatureMessage.Length - Ed448.SignatureSize];
            Array.Copy(SignatureMessage, 0, Signature, 0, Ed448.SignatureSize);
            Array.Copy(SignatureMessage, Ed448.SignatureSize, Message, 0, Message.Length);
            Boolean AbleToVerify = Verify(PublicKey, Message, Signature, Context);
            if (AbleToVerify != true) 
            {
                throw new CryptographicException("Error: Unable to verify the signature in signaturemessage");
            }
            return Message;
        }
    }
}
