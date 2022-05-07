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

        public static Byte[] Sign(Byte[] SecretKey, Byte[] Message, Byte[] Context, Boolean ClearKey = false)
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
            if (Message.Length % 2 == 0)
            {
                if (Message.Length > 114)
                {
                    Ed448.Sign(SecretKey, 0, Context, Message, 0, Message.Length, Signature, 0);
                }
                else
                {
                    Byte[] SplittedMessage1 = new Byte[Message.Length / 2];
                    Byte[] SplittedMessage2 = new Byte[Message.Length / 2];
                    Array.Copy(Message, 0, SplittedMessage1, 0, SplittedMessage1.Length);
                    Array.Copy(Message, 0, SplittedMessage2, 0, SplittedMessage2.Length);
                    Byte[] HashedMessage1 = SodiumGenericHash.ComputeHash(57, SplittedMessage1);
                    Byte[] HashedMessage2 = SodiumGenericHash.ComputeHash(57, SplittedMessage2);
                    Byte[] HashedMessage = HashedMessage1.Concat(HashedMessage2).ToArray();
                    Ed448.Sign(SecretKey, 0, Context, HashedMessage, 0, HashedMessage.Length, Signature, 0);
                }
            }
            else
            {
                if (Message.Length > 114)
                {
                    Ed448.Sign(SecretKey, 0, Context, Message, 0, Message.Length, Signature, 0);
                }
                else
                {
                    int DividedResult = Message.Length / 2;
                    int Remainder = Message.Length % 2;
                    int Count = 1;
                    int LoopCount = 0;
                    int Counter = 0;
                    Byte[] SplittedMessage = new Byte[] { };
                    Byte[] TempHashedMessage = new Byte[] { };
                    Byte[] HashedMessage = new Byte[] { };
                    Byte[] SplittedHashedMessage1 = new Byte[] { };
                    Byte[] SplittedHashedMessage2 = new Byte[] { };
                    Byte[] FinalHashedMessage1 = new Byte[] { };
                    Byte[] FinalHashedMessage2 = new Byte[] { };
                    Byte[] FinalHashedMessage = new Byte[] { };
                    if (DividedResult != 0)
                    {
                        Counter = DividedResult;
                        while (Counter <= Message.Length - Remainder)
                        {
                            Count += 1;
                            Counter += DividedResult;
                        }
                    }
                    Counter = DividedResult;
                    while (LoopCount < Count)
                    {
                        if (Count == 1)
                        {
                            SplittedMessage = new Byte[Remainder];
                            Array.Copy(Message, 0, SplittedMessage, 0, SplittedMessage.Length);
                        }
                        else
                        {
                            if (LoopCount + 1 == Count)
                            {
                                SplittedMessage = new Byte[Remainder];
                                Array.Copy(Message, Counter, SplittedMessage, 0, SplittedMessage.Length);
                            }
                            else
                            {
                                SplittedMessage = new Byte[DividedResult];
                                if (LoopCount == 0)
                                {
                                    Array.Copy(Message, 0, SplittedMessage, 0, SplittedMessage.Length);
                                }
                                else
                                {
                                    Array.Copy(Message, Counter, SplittedMessage, 0, SplittedMessage.Length);
                                    Counter += DividedResult;
                                }
                            }
                        }
                        TempHashedMessage = SodiumGenericHash.ComputeHash(64, SplittedMessage);
                        HashedMessage = HashedMessage.Concat(TempHashedMessage).ToArray();
                        LoopCount += 1;
                    }
                    SplittedHashedMessage1 = new Byte[HashedMessage.Length / 2];
                    SplittedHashedMessage2 = new Byte[HashedMessage.Length / 2];
                    Array.Copy(HashedMessage, 0, SplittedHashedMessage1, 0, SplittedHashedMessage1.Length);
                    Array.Copy(HashedMessage, SplittedHashedMessage2.Length, SplittedHashedMessage2, 0, SplittedHashedMessage2.Length);
                    FinalHashedMessage1 = SodiumGenericHash.ComputeHash(57, SplittedHashedMessage1);
                    FinalHashedMessage2 = SodiumGenericHash.ComputeHash(57, SplittedHashedMessage2);
                    FinalHashedMessage = FinalHashedMessage1.Concat(FinalHashedMessage2).ToArray();
                    Ed448.Sign(SecretKey, 0, Context, FinalHashedMessage, 0, FinalHashedMessage.Length, Signature, 0);
                }
            }
            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(SecretKey);
            }
            return Signature;
        }

        public static Boolean Verify(Byte[] PublicKey, Byte[] Message, Byte[] Signature, Byte[] Context)
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
            if (Message.Length % 2 == 0)
            {
                if (Message.Length > 114)
                {
                    CanVerify = Ed448.Verify(Signature, 0, PublicKey, 0, Context, Message, 0, Message.Length);
                }
                else
                {
                    Byte[] SplittedMessage1 = new Byte[Message.Length / 2];
                    Byte[] SplittedMessage2 = new Byte[Message.Length / 2];
                    Array.Copy(Message, 0, SplittedMessage1, 0, SplittedMessage1.Length);
                    Array.Copy(Message, 0, SplittedMessage2, 0, SplittedMessage2.Length);
                    Byte[] HashedMessage1 = SodiumGenericHash.ComputeHash(57, SplittedMessage1);
                    Byte[] HashedMessage2 = SodiumGenericHash.ComputeHash(57, SplittedMessage2);
                    Byte[] HashedMessage = HashedMessage1.Concat(HashedMessage2).ToArray();
                    CanVerify = Ed448.Verify(Signature, 0, PublicKey, 0, Context, HashedMessage, 0, HashedMessage.Length);
                }
            }
            else
            {
                if (Message.Length > 114)
                {
                    CanVerify = Ed448.Verify(Signature, 0, PublicKey, 0, Context, Message, 0, Message.Length);
                }
                else
                {
                    int DividedResult = Message.Length / 2;
                    int Remainder = Message.Length % 2;
                    int Count = 1;
                    int LoopCount = 0;
                    int Counter = 0;
                    Byte[] SplittedMessage = new Byte[] { };
                    Byte[] TempHashedMessage = new Byte[] { };
                    Byte[] HashedMessage = new Byte[] { };
                    Byte[] SplittedHashedMessage1 = new Byte[] { };
                    Byte[] SplittedHashedMessage2 = new Byte[] { };
                    Byte[] FinalHashedMessage1 = new Byte[] { };
                    Byte[] FinalHashedMessage2 = new Byte[] { };
                    Byte[] FinalHashedMessage = new Byte[] { };
                    if (DividedResult != 0)
                    {
                        Counter = DividedResult;
                        while (Counter <= Message.Length - Remainder)
                        {
                            Count += 1;
                            Counter += DividedResult;
                        }
                    }
                    Counter = DividedResult;
                    while (LoopCount < Count)
                    {
                        if (Count == 1)
                        {
                            SplittedMessage = new Byte[Remainder];
                            Array.Copy(Message, 0, SplittedMessage, 0, SplittedMessage.Length);
                        }
                        else
                        {
                            if (LoopCount + 1 == Count)
                            {
                                SplittedMessage = new Byte[Remainder];
                                Array.Copy(Message, Counter, SplittedMessage, 0, SplittedMessage.Length);
                            }
                            else
                            {
                                SplittedMessage = new Byte[DividedResult];
                                if (LoopCount == 0)
                                {
                                    Array.Copy(Message, 0, SplittedMessage, 0, SplittedMessage.Length);
                                }
                                else
                                {
                                    Array.Copy(Message, Counter, SplittedMessage, 0, SplittedMessage.Length);
                                    Counter += DividedResult;
                                }
                            }
                        }
                        TempHashedMessage = SodiumGenericHash.ComputeHash(64, SplittedMessage);
                        HashedMessage = HashedMessage.Concat(TempHashedMessage).ToArray();
                        LoopCount += 1;
                    }
                    SplittedHashedMessage1 = new Byte[HashedMessage.Length / 2];
                    SplittedHashedMessage2 = new Byte[HashedMessage.Length / 2];
                    Array.Copy(HashedMessage, 0, SplittedHashedMessage1, 0, SplittedHashedMessage1.Length);
                    Array.Copy(HashedMessage, SplittedHashedMessage2.Length, SplittedHashedMessage2, 0, SplittedHashedMessage2.Length);
                    FinalHashedMessage1 = SodiumGenericHash.ComputeHash(57, SplittedHashedMessage1);
                    FinalHashedMessage2 = SodiumGenericHash.ComputeHash(57, SplittedHashedMessage2);
                    FinalHashedMessage = FinalHashedMessage1.Concat(FinalHashedMessage2).ToArray();
                    CanVerify = Ed448.Verify(Signature, 0, PublicKey, 0, Context, FinalHashedMessage, 0, FinalHashedMessage.Length);
                }
            }
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
