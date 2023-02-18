using System;
using System.Linq;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using ASodium;
using System.Runtime.InteropServices;

namespace BCASodium
{
    public static class CNSM4
    {
        public static Byte[] GenerateKey()
        {
            return SodiumRNG.GetRandomBytes(16);
        }

        public static Byte[] GenerateNonce(int Length) 
        {
            if (Length % 16 != 0) 
            {
                throw new ArgumentException("Error: Nonce length must be a multiple of 16 bytes");
            }
            return SodiumRNG.GetRandomBytes(Length);
        }

        public static Byte[] CNSM4Encrypt(Byte[] Message, Byte[] Key, Boolean ClearKey = false)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message can't be null");
            }
            if (Message.Length != 16) 
            {
                throw new ArgumentException("Error: Message must be 16 bytes in length");
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key can't be null");
            }
            if (Key.Length != 16)
            {
                throw new ArgumentException("Error: Key must be exactly 16 bytes or 128 bits in length");
            }
            Byte[] CipherText = new Byte[Message.Length];
            IBlockCipher engine = new SM4Engine();
            engine.Init(true, new KeyParameter(Key));
            engine.ProcessBlock(Message, 0, CipherText, 0);
            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }
            return CipherText;
        }

        public static Byte[] CNSM4Decrypt(Byte[] CipherText, Byte[] Key, Boolean ClearKey = false)
        {
            if (CipherText == null)
            {
                throw new ArgumentException("Error: CipherText can't be null");
            }
            if (CipherText.Length != 16) 
            {
                throw new ArgumentException("Error: CipherText must be 16 bytes in length");
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key can't be null");
            }
            if (Key.Length != 16)
            {
                throw new ArgumentException("Error: Key must be exactly 16 bytes or 128 bits in length");
            }
            Byte[] Message = new Byte[CipherText.Length];
            IBlockCipher engine = new SM4Engine();
            engine.Init(false, new KeyParameter(Key));
            engine.ProcessBlock(CipherText, 0, Message, 0);
            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }
            return Message;
        }

        //Fix some bug
        //The code below is slightly constant time performance
        public static Byte[] CTR_Mode_Encrypt(Byte[] Message, Byte[] Nonce, Byte[] Key, Byte[] HMACKey , Boolean ClearKey = false)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message can't be null");
            }
            if (Message.Length == 0)
            {
                throw new ArgumentException("Error: Message length must not be 0");
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key can't be null");
            }
            if (Key.Length != 16)
            {
                throw new ArgumentException("Error: Key must be exactly 16 bytes or 128 bits in length");
            }
            if (HMACKey == null)
            {
                throw new ArgumentException("Error: HMACKey can't be null");
            }
            if (HMACKey.Length % 16 != 0)
            {
                throw new ArgumentException("Error: HMACKey length must be divisible 16 bytes in length");
            }
            if (Nonce == null)
            {
                throw new ArgumentException("Error: Nonce can't be null");
            }
            int BlockSize = 16;
            int DividedBlocks = 0;
            Byte[] PreviousEKey = new Byte[] { };
            Byte[] PreviousMKey = new Byte[] { };
            Byte[] NewEKey = new Byte[] { };
            Byte[] NewMKey = new Byte[] { };
            Byte[] DividedNonce = new Byte[16];
            Byte[] EncryptedDividedNonce = new Byte[16];
            Byte[] EncryptedNonce = new Byte[Nonce.Length];
            Byte[] SubEncryptedNonce = new Byte[Message.Length];
            if (Message.Length % BlockSize == 0)
            {
                DividedBlocks = Message.Length / BlockSize;
            }
            else
            {
                DividedBlocks = Message.Length / BlockSize;
                DividedBlocks += 1;
            }
            if (Nonce.Length != DividedBlocks * 16) 
            {
                throw new ArgumentException("Error: Nonce length must exactly be " + DividedBlocks * 16 + " bytes in length");
            }
            NewEKey = SodiumGenericHash.ComputeHash(16, Key, HMACKey);
            NewMKey = SodiumGenericHash.ComputeHash(64, NewEKey, HMACKey);
            Byte[] CipherText = new Byte[Message.Length];
            int Loop = 0;
            while (Loop < DividedBlocks)
            {
                Buffer.BlockCopy(Nonce, (Loop*16), DividedNonce, 0, DividedNonce.Length);
                EncryptedDividedNonce = CNSM4Encrypt(DividedNonce, NewEKey);
                Buffer.BlockCopy(EncryptedDividedNonce, 0, EncryptedNonce, (Loop * 16), 16);                
                PreviousEKey = NewEKey;
                PreviousMKey = NewMKey;
                NewEKey = SodiumGenericHash.ComputeHash(16, PreviousEKey, PreviousMKey);
                NewMKey = SodiumGenericHash.ComputeHash(64, NewEKey, PreviousMKey, true);
                Loop += 1;
            }
            Buffer.BlockCopy(Message, 0, CipherText,0, CipherText.Length);
            if (EncryptedNonce.Length > Message.Length)
            {
                Buffer.BlockCopy(EncryptedNonce, 0, SubEncryptedNonce, 0, SubEncryptedNonce.Length);
                XORHelper.SCTXOR(CipherText, SubEncryptedNonce);
                SodiumSecureMemory.SecureClearBytes(SubEncryptedNonce);
            }
            else
            {
                XORHelper.SCTXOR(CipherText, EncryptedNonce);
            }
            SodiumSecureMemory.SecureClearBytes(EncryptedNonce);
            SodiumSecureMemory.SecureClearBytes(PreviousEKey);
            SodiumSecureMemory.SecureClearBytes(PreviousMKey);
            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
                SodiumSecureMemory.SecureClearBytes(HMACKey);
            }
            return CipherText;
        }

        public static Byte[] CTR_Mode_Decrypt(Byte[] CipherText, Byte[] Nonce, Byte[] Key, Byte[] HMACKey ,Boolean ClearKey = false)
        {
            return CTR_Mode_Encrypt(CipherText, Nonce, Key, HMACKey,ClearKey);
        }

        public static Byte[] HMACCTRModeEncrypt(Byte[] Message, Byte[] Nonce, Byte[] Key, Byte[] HMACKey, Boolean UsePrivateContext = false, Boolean ClearKey = false)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message can't be null");
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key can't be null");
            }
            if (Key.Length != 16)
            {
                throw new ArgumentException("Error: Key must be exactly 16 bytes or 128 bits in length");
            }
            if (HMACKey == null)
            {
                throw new ArgumentException("Error: HMACKey can't be null");
            }
            if (HMACKey.Length%16!=0) 
            {
                throw new ArgumentException("Error: HMACKey length must be divisible 16 bytes in length");
            }            
            if (Nonce == null)
            {
                throw new ArgumentException("Error: Nonce can't be null");
            }
            if (Nonce.Length != 16)
            {
                throw new ArgumentException("Error: Nonce must exactly be 16 bytes or 128 bits in length");
            }
            Byte[] CipherText = CTR_Mode_Encrypt(Message, Nonce, HMACKey ,Key);
            Byte[] MAC = CNSM3Digest.ComputeHMAC(CipherText, HMACKey,UsePrivateContext);
            Byte[] CipherTextWithMAC = MAC.Concat(CipherText).ToArray();
            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
                SodiumSecureMemory.SecureClearBytes(HMACKey);
            }
            return CipherTextWithMAC;
        }

        public static Byte[] HMACCTRModeDecrypt(Byte[] CipherTextWithMAC, Byte[] Nonce, Byte[] Key, Byte[] HMACKey ,Boolean UsePrivateContext = false ,Boolean ClearKey = false)
        {
            if (CipherTextWithMAC == null)
            {
                throw new ArgumentException("Error: CipherTextWithMAC can't be null");
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key can't be null");
            }
            if (Key.Length != 16)
            {
                throw new ArgumentException("Error: Key must be exactly 16 bytes or 128 bits in length");
            }
            if (HMACKey == null)
            {
                throw new ArgumentException("Error: HMACKey can't be null");
            }
            if (HMACKey.Length % 16 != 0)
            {
                throw new ArgumentException("Error: HMACKey length must be divisible 16 bytes in length");
            }
            if (Nonce == null)
            {
                throw new ArgumentException("Error: Nonce can't be null");
            }
            if (Nonce.Length != 16)
            {
                throw new ArgumentException("Error: Nonce must exactly be 16 bytes or 128 bits in length");
            }
            Byte[] CipherText = new Byte[CipherTextWithMAC.Length - 32];
            Byte[] CipherTextMAC = new Byte[32];
            Array.Copy(CipherTextWithMAC, CipherTextMAC, 32);
            Array.Copy(CipherTextWithMAC, 32, CipherText, 0, CipherText.Length);
            Byte[] MAC = CNSM3Digest.ComputeHMAC(CipherText, HMACKey, UsePrivateContext);
            GCHandle CipherTextMACGCHandle = GCHandle.Alloc(CipherTextMAC, GCHandleType.Pinned);
            GCHandle MACGCHandle = GCHandle.Alloc(MAC, GCHandleType.Pinned);
            try
            {
                SodiumHelper.Sodium_Memory_Compare(CipherTextMACGCHandle.AddrOfPinnedObject(), MACGCHandle.AddrOfPinnedObject(), MAC.Length);
            }
            catch
            {
                throw new CryptographicException("Error: Message have been tampered");
            }
            CipherTextMACGCHandle.Free();
            MACGCHandle.Free();
            Byte[] Message = CTR_Mode_Decrypt(CipherText, Nonce, Key,HMACKey);
            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
                SodiumSecureMemory.SecureClearBytes(HMACKey);
            }
            return Message;
        }
    }
}
