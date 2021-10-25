using System;
using System.Linq;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using ASodium;

namespace BCASodium
{
    public static class CNSM4
    {
        //Unsafe Encrypt use ECB or CTR or HMACCTRMode or GCM_Encrypt
        public static Byte[] Unsafe_Encrypt(Byte[] Message, Byte[] Key, Boolean ClearKey = false)
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

        //Unsafe Decrypt use ECB or CTR or HMACCTRMode or GCM_Decrypt
        public static Byte[] Unsafe_Decrypt(Byte[] CipherText, Byte[] Key, Boolean ClearKey = false)
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

        public static Byte[] ECB_Mode_Encrypt(Byte[] Message, Byte[] Key, Boolean ClearKey = false)
        {
            Boolean HasPadding = false;
            if (Message == null)
            {
                throw new ArgumentException("Error: Message can't be null");
            }
            if (Message.Length % 16 != 0)
            {
                Message = PKCS5PaddingClass.PKCS5Padding(Message);
                HasPadding = true;
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key can't be null");
            }
            if (Key.Length != 16)
            {
                throw new ArgumentException("Error: Key must be exactly 16 bytes or 128 bits in length");
            }
            Byte[] ActualMessage = new Byte[] { };
            if (HasPadding == true)
            {
                ActualMessage = new Byte[Message.Length - 1];
                Array.Copy(Message, 1, ActualMessage, 0, ActualMessage.Length);
            }
            else
            {
                ActualMessage = Message;
            }
            Byte[] TempCipherText = new Byte[] { };
            Byte[] CipherText = new Byte[] { };
            Byte[] SubMessage = new Byte[] { };
            int BlockSize = 16;
            int DividedBlocks = 0;
            int Loop = 0;
            DividedBlocks = ActualMessage.Length / BlockSize;
            while (Loop < DividedBlocks)
            {
                if (Loop == 0)
                {
                    SubMessage = new Byte[16];
                    Array.Copy(ActualMessage, 0, SubMessage, 0, 16);
                    TempCipherText = Unsafe_Encrypt(SubMessage, Key);
                }
                else
                {
                    Array.Copy(ActualMessage, BlockSize * Loop, SubMessage, 0, 16);
                    TempCipherText = Unsafe_Encrypt(SubMessage, Key);
                }
                CipherText = CipherText.Concat(TempCipherText).ToArray();
                Loop += 1;
            }
            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }
            if (HasPadding == true)
            {
                Byte[] PaddingCount = new Byte[] { Message[0] };
                CipherText = PaddingCount.Concat(CipherText).ToArray();
            }
            return CipherText;
        }

        public static Byte[] ECB_Mode_Decrypt(Byte[] CipherText, Byte[] Key, Boolean ClearKey = false)
        {
            Boolean HasPadding = false;
            if (CipherText == null)
            {
                throw new ArgumentException("Error: Cipher Text can't be null");
            }
            if (CipherText.Length % 16 != 0)
            {
                HasPadding = true;
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key can't be null");
            }
            if (Key.Length != 16)
            {
                throw new ArgumentException("Error: Key must be exactly 16 bytes or 128 bits in length");
            }
            Byte[] ActualCipherText = new Byte[] { };
            if (HasPadding == true)
            {
                ActualCipherText = new Byte[CipherText.Length - 1];
                Array.Copy(CipherText, 1, ActualCipherText, 0, ActualCipherText.Length);
            }
            else
            {
                ActualCipherText = CipherText;
            }
            Byte[] TempPlainText = new Byte[] { };
            Byte[] PlainText = new Byte[] { };
            Byte[] SubCipherText = new Byte[] { };
            int BlockSize = 16;
            int DividedBlocks = 0;
            int Loop = 0;
            DividedBlocks = CipherText.Length / BlockSize;
            while (Loop < DividedBlocks)
            {
                if (Loop == 0)
                {
                    SubCipherText = new Byte[16];
                    Array.Copy(ActualCipherText, 0, SubCipherText, 0, 16);
                    TempPlainText = Unsafe_Decrypt(SubCipherText, Key);
                }
                else
                {
                    Array.Copy(ActualCipherText, BlockSize * Loop, SubCipherText, 0, 16);
                    TempPlainText = Unsafe_Decrypt(SubCipherText, Key);
                }
                PlainText = PlainText.Concat(TempPlainText).ToArray();
                Loop += 1;
            }
            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }
            if (HasPadding == true)
            {
                Byte[] ActualPlainText = new Byte[PlainText.Length - CipherText[0]];
                Loop = 0;
                while (Loop < ActualPlainText.Length)
                {
                    ActualPlainText[Loop] = PlainText[Loop];
                    Loop += 1;
                }
                PlainText = ActualPlainText;
            }
            return PlainText;
        }

        //Under maintenance
        //CBC does not work during decryption
        /*
        public static Byte[] CBC_Mode_Encrypt(Byte[] Message, Byte[] Key, Boolean ClearKey = false) 
        {
            Boolean HasPadding = false;
            if (Message == null)
            {
                throw new ArgumentException("Error: Message can't be null");
            }
            if (Message.Length % 16 != 0)
            {
                Message = PKCS5Padding(Message);
                HasPadding = true;
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key can't be null");
            }
            if (Key.Length != 16)
            {
                throw new ArgumentException("Error: Key must be exactly 16 bytes or 128 bits in length");
            }
            Byte[] ActualMessage = new Byte[] { };
            if (HasPadding == true)
            {
                ActualMessage = new Byte[Message.Length - 1];
                Array.Copy(Message, 1, ActualMessage, 0, ActualMessage.Length);
            }
            else
            {
                ActualMessage = Message;
            }
            Byte[] PreviousCipherText = new Byte[] { };
            Byte[] TempPreviousCipherText = new Byte[] { };
            Byte[] CurrentCipherText = new Byte[] { };
            Byte[] CipherText = new Byte[] { };
            Byte[] SubMessage = new Byte[] { };
            Byte[] TempSubMessage = new Byte[] { };
            Byte[] CurrentSubMessage = new Byte[] { };
            int BlockSize = 16;
            int DividedBlocks = 0;
            int Loop = 0;
            DividedBlocks = Message.Length / BlockSize;
            while (Loop < DividedBlocks)
            {
                if (Loop == 0)
                {
                    SubMessage = new Byte[16];
                    Array.Copy(ActualMessage, 0, SubMessage, 0, SubMessage.Length);
                    PreviousCipherText = Unsafe_Encrypt(SubMessage, Key);
                    CipherText = CipherText.Concat(PreviousCipherText).ToArray();
                }
                else
                {
                    Array.Copy(ActualMessage, BlockSize * Loop, SubMessage, 0, 16);
                    CurrentSubMessage = XORHelper.XOR(PreviousCipherText, SubMessage);
                    CurrentCipherText = Unsafe_Encrypt(CurrentSubMessage, Key);
                    PreviousCipherText = CurrentCipherText;
                    CipherText = CipherText.Concat(CurrentCipherText).ToArray();
                }
                Loop += 1;
            }
            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }
            if (HasPadding == true)
            {
                Byte[] PaddingCount = new Byte[] { Message[0] };
                CipherText = PaddingCount.Concat(CipherText).ToArray();
            }
            return CipherText;
        }

        //Under maintenance
        //CBC mode does not work during decryption
        public static Byte[] CBC_Mode_Decrypt(Byte[] CipherText, Byte[] Key, Boolean ClearKey = false) 
        {
            Boolean HasPadding = false;
            if (CipherText == null)
            {
                throw new ArgumentException("Error: Cipher Text can't be null");
            }
            if (CipherText.Length % 16 != 0)
            {
                HasPadding = true;
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key can't be null");
            }
            if (Key.Length != 16)
            {
                throw new ArgumentException("Error: Key must be exactly 16 bytes or 128 bits in length");
            }
            Byte[] ActualCipherText = new Byte[] { };
            if (HasPadding == true)
            {
                ActualCipherText = new Byte[CipherText.Length - 1];
                Array.Copy(CipherText, 1, ActualCipherText, 0, ActualCipherText.Length);
            }
            else
            {
                ActualCipherText = CipherText;
            }
            Byte[] TempPlainText = new Byte[] { };
            Byte[] TempSubPlainText = new Byte[] { };
            Byte[] PlainText = new Byte[] { };
            Byte[] TempSubCipherText = new Byte[] { };
            Byte[] SubCipherText = new Byte[] { };
            Byte[] PreviousCipherText = new Byte[] { };
            int BlockSize = 16;
            int DividedBlocks = 0;
            int Loop = 0;
            DividedBlocks = CipherText.Length / BlockSize;
            while (Loop < DividedBlocks)
            {
                if (Loop == 0)
                {
                    SubCipherText = new Byte[16];
                    Array.Copy(ActualCipherText, 0, SubCipherText, 0, 16);
                    TempPlainText = Unsafe_Decrypt(SubCipherText, Key);
                    PreviousCipherText = SubCipherText;
                }
                else
                {
                    Array.Copy(ActualCipherText, BlockSize * Loop, SubCipherText, 0, 16);
                    TempPlainText = Unsafe_Decrypt(SubCipherText, Key);
                    TempPlainText = XORHelper.XOR(PreviousCipherText, TempPlainText);
                    PreviousCipherText = SubCipherText;
                }
                PlainText = PlainText.Concat(TempPlainText).ToArray();
                Loop += 1;
            }
            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }
            if (HasPadding == true)
            {
                Byte[] ActualPlainText = new Byte[PlainText.Length - CipherText[0]];
                Loop = 0;
                while (Loop < ActualPlainText.Length)
                {
                    ActualPlainText[Loop] = PlainText[Loop];
                    Loop += 1;
                }
                PlainText = ActualPlainText;
            }
            return PlainText;
        }*/

        public static Byte[] CTR_Mode_Encrypt(Byte[] Message, Byte[] Nonce, Byte[] Key, Boolean ClearKey = false)
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
            Byte[] SubKey = Unsafe_Encrypt(Nonce, Key);
            Byte[] SubNonce = new Byte[16];
            Byte[] SubKey1 = new Byte[16];
            Byte[] SubKey2 = new Byte[16];
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
                    Nonce = CNSM3Digest.ComputeHash(Nonce);
                    Array.Copy(Nonce, 0, SubNonce, 0, SubNonce.Length);
                    SubKey1 = Unsafe_Encrypt(SubNonce, Key);
                    Array.Copy(Nonce, 16, SubNonce, 0, SubNonce.Length);
                    SubKey2 = Unsafe_Encrypt(SubNonce, Key);
                    SubKey = XORHelper.XOR(SubKey1, SubKey2);
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
                    SodiumSecureMemory.SecureClearBytes(SubKey1);
                    SodiumSecureMemory.SecureClearBytes(SubKey2);
                }
                Buff = Buff.Concat(TempBuff).ToArray();
                Loop += 1;
            }
            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }
            return Buff;
        }

        public static Byte[] CTR_Mode_Decrypt(Byte[] CipherText, Byte[] Nonce, Byte[] Key, Boolean ClearKey = false)
        {
            return CTR_Mode_Encrypt(CipherText, Nonce, Key, ClearKey);
        }

        public static Byte[] GCM_CTR_Mode_Encrypt(Byte[] Message, Byte[] Nonce, Byte[] Key, Boolean ClearKey = false)
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
            Byte[] SubKey = new Byte[] { };
            Byte[] SubNonce = new Byte[16];
            Byte[] SubKey1 = new Byte[16];
            Byte[] SubKey2 = new Byte[16];
            Byte[] TempSubKey = new Byte[] { };
            Byte[] SubMessage = new Byte[16];
            Byte[] TempBuff = new Byte[] { };
            Byte[] Buff = new Byte[] { };
            int Loop = 0;
            while (Loop < DividedBlocks)
            {
                if (Loop == 0)
                {
                    Nonce = CNSM3Digest.ComputeHash(Nonce);
                    Array.Copy(Nonce, 0, SubNonce, 0, SubNonce.Length);
                    SubKey1 = Unsafe_Encrypt(SubNonce, Key);
                    Array.Copy(Nonce, 16, SubNonce, 0, SubNonce.Length);
                    SubKey2 = Unsafe_Encrypt(SubNonce, Key);
                    SubKey = XORHelper.XOR(SubKey1, SubKey2);
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
                    SodiumSecureMemory.SecureClearBytes(SubKey1);
                    SodiumSecureMemory.SecureClearBytes(SubKey2);
                }
                else
                {
                    Nonce = CNSM3Digest.ComputeHash(Nonce);
                    Array.Copy(Nonce, 0, SubNonce, 0, SubNonce.Length);
                    SubKey1 = Unsafe_Encrypt(SubNonce, Key);
                    Array.Copy(Nonce, 16, SubNonce, 0, SubNonce.Length);
                    SubKey2 = Unsafe_Encrypt(SubNonce, Key);
                    SubKey = XORHelper.XOR(SubKey1, SubKey2);
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
                    SodiumSecureMemory.SecureClearBytes(SubKey1);
                    SodiumSecureMemory.SecureClearBytes(SubKey2);
                }
                Buff = Buff.Concat(TempBuff).ToArray();
                Loop += 1;
            }
            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }
            return Buff;
        }

        public static Byte[] GCM_CTR_Mode_Decrypt(Byte[] CipherText, Byte[] Nonce, Byte[] Key, Boolean ClearKey = false)
        {
            return GCM_CTR_Mode_Encrypt(CipherText, Nonce, Key, ClearKey);
        }

        public static Byte[] GCM_GenerateGMAC(Byte[] CipherText, Byte[] Nonce, Byte[] Key, Byte[] AdditionalData = null, Boolean ClearKey = false)
        {
            if (CipherText == null)
            {
                throw new ArgumentException("Error: Cipher Text can't be null");
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key can't be null");
            }
            if (Key.Length != 16)
            {
                throw new ArgumentException("Error: Key must be exactly 16 bytes or 128 bits in length");
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
            if (CipherText.Length % BlockSize == 0)
            {
                DividedBlocks = CipherText.Length / BlockSize;
            }
            else
            {
                DividedBlocks = CipherText.Length / BlockSize;
                DividedBlocks += 1;
            }
            Byte[] SubKey = Unsafe_Encrypt(Nonce, Key);
            long CipherTextLength = CipherText.LongLength;
            long AdditionalDataLength = 0;
            if (AdditionalData != null)
            {
                AdditionalDataLength = AdditionalData.LongLength;
            }
            Byte[] CipherTextLengthByte = BitConverter.GetBytes(CipherTextLength);
            Byte[] AdditionalDataLengthByte = BitConverter.GetBytes(AdditionalDataLength);
            Byte[] SM3DigestHashedAdditionalData = new Byte[] { };
            if (AdditionalData != null)
            {
                SM3DigestHashedAdditionalData = CNSM3Digest.ComputeHash(AdditionalData);
            }
            else
            {
                SM3DigestHashedAdditionalData = CNSM3Digest.ComputeHash(new Byte[] { });
            }
            Byte[] SubHashedAdditionalData1 = new Byte[16];
            Array.Copy(SM3DigestHashedAdditionalData, 0, SubHashedAdditionalData1, 0, 16);
            Byte[] SubHashedAdditionalData2 = new Byte[16];
            Array.Copy(SM3DigestHashedAdditionalData, 16, SubHashedAdditionalData2, 0, 16);
            Byte[] TempHashedAdditionalData = XORHelper.XOR(SubHashedAdditionalData1, SubHashedAdditionalData2);
            Byte[] PaddedCipherText = new Byte[] { };
            if (CipherText.Length % 16 == 0)
            {
                PaddedCipherText = CipherText;
            }
            else
            {
                PaddedCipherText = PKCS5PaddingClass.PKCS5Padding(CipherText, true);
            }
            Byte[] ConcatedDataLength = CipherTextLengthByte.Concat(AdditionalDataLengthByte).ToArray();
            Byte[] SubPaddedCipherText = new Byte[16];
            Byte[] GMAC = new Byte[] { };
            int Loop = 0;
            while (Loop < DividedBlocks)
            {
                Array.Copy(PaddedCipherText, Loop, SubPaddedCipherText, 0, 16);
                if (Loop + 1 == DividedBlocks)
                {
                    GMAC = XORHelper.XOR(TempHashedAdditionalData, SubPaddedCipherText);
                    GMAC = XORHelper.XOR(GMAC, ConcatedDataLength);
                    GMAC = XORHelper.XOR(GMAC, SubKey);
                }
                else
                {
                    GMAC = XORHelper.XOR(TempHashedAdditionalData, SubPaddedCipherText);
                }
                Loop += 1;
            }

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }
            SodiumSecureMemory.SecureClearBytes(SubKey);

            return GMAC;
        }

        public static Byte[] GCM_Encrypt(Byte[] Message, Byte[] Nonce, Byte[] Key, Byte[] AdditionalData = null, Boolean ClearKey = false)
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
            if (Nonce == null)
            {
                throw new ArgumentException("Error: Nonce can't be null");
            }
            if (Nonce.Length != 16)
            {
                throw new ArgumentException("Error: Nonce must exactly be 16 bytes or 128 bits in length");
            }
            Byte[] CipherText = GCM_CTR_Mode_Encrypt(Message, Nonce, Key);
            Byte[] GMAC = GCM_GenerateGMAC(CipherText, Nonce, Key, AdditionalData);
            Byte[] CipherTextGMAC = GMAC.Concat(CipherText).ToArray();

            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }
            return CipherTextGMAC;
        }

        public static Byte[] GCM_Decrypt(Byte[] CipherTextGMAC, Byte[] Nonce, Byte[] Key, Byte[] AdditionalData = null, Boolean ClearKey = false)
        {
            if (CipherTextGMAC == null)
            {
                throw new ArgumentException("Error: Cipher Text with GMAC can't be null");
            }
            if (Key == null)
            {
                throw new ArgumentException("Error: Key can't be null");
            }
            if (Key.Length != 16)
            {
                throw new ArgumentException("Error: Key must be exactly 16 bytes or 128 bits in length");
            }
            if (Nonce == null)
            {
                throw new ArgumentException("Error: Nonce can't be null");
            }
            if (Nonce.Length != 16)
            {
                throw new ArgumentException("Error: Nonce must exactly be 16 bytes or 128 bits in length");
            }
            Byte[] CTextGMAC = new Byte[16];
            Array.Copy(CipherTextGMAC, 0, CTextGMAC, 0, 16);
            Byte[] CipherText = new Byte[CipherTextGMAC.Length - 16];
            Array.Copy(CipherTextGMAC, 16, CipherText, 0, CipherText.Length);
            Byte[] GMAC = GCM_GenerateGMAC(CipherText, Nonce, Key, AdditionalData);
            Byte[] PlainText = new Byte[] { };
            if (CTextGMAC.SequenceEqual(GMAC) == true)
            {
                PlainText = GCM_CTR_Mode_Decrypt(CipherText, Nonce, Key);
            }
            else
            {
                throw new CryptographicException("Error: Message have been tampered");
            }
            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }
            return PlainText;
        }

        public static Byte[] HMACCTRModeEncrypt(Byte[] Message, Byte[] Nonce, Byte[] Key, Boolean ClearKey = false)
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
            if (Nonce == null)
            {
                throw new ArgumentException("Error: Nonce can't be null");
            }
            if (Nonce.Length != 16)
            {
                throw new ArgumentException("Error: Nonce must exactly be 16 bytes or 128 bits in length");
            }
            Byte[] CipherText = CTR_Mode_Encrypt(Message, Nonce, Key);
            Byte[] MAC = CNSM3Digest.ComputeMAC(CipherText, Key);
            Byte[] CipherTextWithMAC = MAC.Concat(CipherText).ToArray();
            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }
            return CipherTextWithMAC;
        }

        public static Byte[] HMACCTRModeDecrypt(Byte[] CipherTextWithMAC, Byte[] Nonce, Byte[] Key, Boolean ClearKey = false)
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
            Byte[] MAC = CNSM3Digest.ComputeMAC(CipherText, Key);
            if (CipherTextMAC.SequenceEqual(MAC) == false)
            {
                throw new CryptographicException("Error: The message has been tampered");
            }
            Byte[] Message = CTR_Mode_Decrypt(CipherText, Nonce, Key);
            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }
            return Message;
        }
    }
}
