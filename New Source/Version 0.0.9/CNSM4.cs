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
        public static Byte[] GenerateKeyOrNonce()
        {
            return SodiumRNG.GetRandomBytes(16);
        }

        public static Byte[] CNSM4Encrypt(Byte[] Message, Byte[] Key, Boolean ClearKey = false)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message can't be null");
            }
            if (Message.Length % 16 != 0) 
            {
                throw new ArgumentException("Error: Message must be divisible by 16 bytes in length");
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

        public static Byte[] CTR_Mode_Encrypt(Byte[] Message, Byte[] Nonce, Byte[] Key, Byte[] HMACKey , Boolean ClearKey = false)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message can't be null");
            }
            if (Message.Length % 16 != 0)
            {
                throw new ArgumentException("Error: Message must be divisible by 16 bytes in length");
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
            int BlockSize = 16;
            int DividedBlocks = 0;
            Boolean HasRemainder = true;
            Byte[] PreviousEKey = new Byte[] { };
            Byte[] PreviousMKey = new Byte[] { };
            Byte[] NewEKey = new Byte[] { };
            Byte[] NewMKey = new Byte[] { };
            if (Message.Length % BlockSize == 0)
            {
                DividedBlocks = Message.Length / BlockSize;
                HasRemainder = false;
            }
            else
            {
                DividedBlocks = Message.Length / BlockSize;
                DividedBlocks += 1;
            }
            NewEKey = SodiumGenericHash.ComputeHash(16, Key, HMACKey);
            NewMKey = SodiumGenericHash.ComputeHash(16, NewEKey, HMACKey);
            Byte[] SubKey = CNSM4Encrypt(Nonce, NewEKey);
            Byte[] SubNonce = new Byte[16];
            Byte[] TempSubKey = new Byte[] { };
            Byte[] SubMessage = new Byte[16];
            Byte[] TempBuff = new Byte[] { };
            Byte[] Buff = new Byte[] { };
            int Loop = 0;
            while (Loop < DividedBlocks)
            {
                if (Loop == 0)
                {
                    if (DividedBlocks == 1)
                    {
                        SubMessage = new Byte[Message.Length];
                        Array.Copy(Message, SubMessage, SubMessage.Length);
                        if (HasRemainder == true)
                        {
                            TempSubKey = new Byte[SubMessage.Length];
                            Array.Copy(SubKey, TempSubKey, TempSubKey.Length);
                            TempBuff = XORHelper.XOR(TempSubKey, SubMessage);
                            SodiumSecureMemory.SecureClearBytes(TempSubKey);
                        }
                        else
                        {
                            TempBuff = XORHelper.XOR(SubKey, SubMessage);
                        }
                    }
                    else
                    {
                        SubMessage = new Byte[16];
                        Array.Copy(Message, 0, SubMessage, 0, SubMessage.Length);
                        TempBuff = XORHelper.XOR(SubKey, SubMessage);
                    }
                    SodiumSecureMemory.SecureClearBytes(SubKey);
                }
                else
                {
                    //Can't clear NewEKey as it's required by each process
                    //But I can clear previous MKey
                    NewEKey = SodiumGenericHash.ComputeHash(16, PreviousEKey, PreviousMKey);
                    NewMKey = SodiumGenericHash.ComputeHash(16, NewEKey, PreviousMKey,true);
                    Nonce = CNSM3Digest.ComputeHash(Nonce);
                    SubKey = CNSM4Encrypt(Nonce,NewEKey);
                    if (Message.Length - BlockSize * Loop == 16)
                    {
                        SubMessage = new Byte[16];
                    }
                    else
                    {
                        if (HasRemainder == true && (Loop + 1) == DividedBlocks)
                        {
                            SubMessage = new Byte[Message.Length - BlockSize * Loop];
                        }
                        else
                        {
                            SubMessage = new Byte[16];
                        }
                    }
                    Array.Copy(Message, BlockSize * Loop, SubMessage, 0, SubMessage.Length);
                    if (HasRemainder == true && (Loop + 1) == DividedBlocks)
                    {
                        TempSubKey = new Byte[SubMessage.Length];
                        Array.Copy(SubKey, TempSubKey, TempSubKey.Length);
                        TempBuff = XORHelper.XOR(TempSubKey, SubMessage);
                        SodiumSecureMemory.SecureClearBytes(TempSubKey);
                    }
                    else
                    {
                        TempBuff = XORHelper.XOR(SubKey, SubMessage);
                    }
                    SodiumSecureMemory.SecureClearBytes(SubKey);
                }
                PreviousEKey = NewEKey;
                PreviousMKey = NewMKey;
                Buff = Buff.Concat(TempBuff).ToArray();
                Loop += 1;
            }
            SodiumSecureMemory.SecureClearBytes(PreviousEKey);
            SodiumSecureMemory.SecureClearBytes(PreviousMKey);
            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
                SodiumSecureMemory.SecureClearBytes(HMACKey);
            }
            return Buff;
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
