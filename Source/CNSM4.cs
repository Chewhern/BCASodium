using System;
using System.Linq;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using ASodium;

namespace BCASodium
{
    public static class CNSM4
    {
        public static Byte[] GenerateKey() 
        {
            Byte[] Key = SodiumRNG.GetRandomBytes(16);

            return Key;
        }

        public static Byte[] GenerateNonce() 
        {
            Byte[] Nonce = SodiumRNG.GetRandomBytes(16);

            return Nonce;
        }

        public static Byte[] Encrypt(Byte[] Message, Byte[] Key, Boolean ClearKey = false)
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

        public static Byte[] Decrypt(Byte[] CipherText, Byte[] Key, Boolean ClearKey = false)
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

        //US refers to unsafe
        public static Byte[] US_CTR_Mode_Encrypt(Byte[] Message, Byte[] Nonce, Byte[] Key, Boolean ClearKey = false)
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
            Byte[] SubKey = Encrypt(Nonce, Key);
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
                            TempBuff = XOR(TempSubKey, SubMessage, true);
                            SodiumSecureMemory.SecureClearBytes(SubKey);
                        }
                        else
                        {
                            TempBuff = XOR(SubKey, SubMessage, true);
                        }
                    }
                    else
                    {
                        SubMessage = new Byte[16];
                        Array.Copy(Message, 0, SubMessage, 0, SubMessage.Length);
                        if (HasRemainder == true && Loop + 1 == DividedBlocks)
                        {
                            TempSubKey = new Byte[SubMessage.Length];
                            Array.Copy(SubKey, TempSubKey, TempSubKey.Length);
                            TempBuff = XOR(TempSubKey, SubMessage, true);
                            SodiumSecureMemory.SecureClearBytes(SubKey);
                        }
                        else
                        {
                            TempBuff = XOR(SubKey, SubMessage, true);
                        }
                    }
                }
                else
                {
                    Nonce = SodiumGenericHash.ComputeHash(16, Nonce);
                    SubKey = Encrypt(Nonce, Key);
                    if (Message.Length - BlockSize * Loop == 16)
                    {
                        SubMessage = new Byte[16];
                    }
                    else
                    {
                        SubMessage = new Byte[Message.Length - BlockSize * Loop];
                    }
                    Array.Copy(Message, BlockSize * Loop, SubMessage, 0, Message.Length - BlockSize * Loop);
                    if (HasRemainder == true && Loop + 1 == DividedBlocks)
                    {
                        TempSubKey = new Byte[SubMessage.Length];
                        Array.Copy(SubKey, TempSubKey, TempSubKey.Length);
                        TempBuff = XOR(TempSubKey, SubMessage, true);
                        SodiumSecureMemory.SecureClearBytes(SubKey);
                    }
                    else
                    {
                        TempBuff = XOR(SubKey, SubMessage, true);
                    }
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


        public static Byte[] US_CTR_Mode_Decrypt(Byte[] CipherText, Byte[] Nonce, Byte[] Key, Boolean ClearKey = false)
        {
            return US_CTR_Mode_Encrypt(CipherText, Nonce, Key, ClearKey);
        }

        public static Byte[] SM4SM3Encrypt(Byte[] Message, Byte[] Nonce, Byte[] Key, Boolean ClearKey = false)
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
            SM3Digest MyDigest = new SM3Digest();
            Byte[] CipherText = US_CTR_Mode_Encrypt(Message, Nonce, Key);
            //Nothing up my sleeve numbers that was taken from HMAC-SHA wikipedia
            //As SM3Digest uses Merkle-Damgard construction like MD4, MD5, SHA-1 and SHA-2, it might also be vulnerable to length extension attack
            Byte[] IPAD = new Byte[] { 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36 };
            Byte[] OPAD = new Byte[] { 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c };
            //Derive 2 keys by XOR-ing O/IPAD with the key
            Byte[] K1 = XOR(OPAD, Key);
            Byte[] K2 = XOR(IPAD, Key);
            Byte[] ConcatedMessageP2 = CipherText.Concat(K2).ToArray();
            Byte[] HashedCMessageP2 = CNSM3Digest.ComputeHashForMAC(ConcatedMessageP2, MyDigest);
            Byte[] ConcatedMessage = K1.Concat(HashedCMessageP2).ToArray();
            Byte[] MAC = CNSM3Digest.ComputeHashForMAC(ConcatedMessage, MyDigest, true);
            Byte[] CipherTextWithMAC = MAC.Concat(CipherText).ToArray();
            MyDigest.Reset();
            SodiumSecureMemory.SecureClearBytes(K1);
            SodiumSecureMemory.SecureClearBytes(K2);
            SodiumSecureMemory.SecureClearBytes(ConcatedMessageP2);
            SodiumSecureMemory.SecureClearBytes(ConcatedMessage);
            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }
            return CipherTextWithMAC;
        }

        public static Byte[] SM4SM3Decrypt(Byte[] CipherTextWithMAC, Byte[] Nonce, Byte[] Key, Boolean ClearKey = false)
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
            SM3Digest MyDigest = new SM3Digest();
            Byte[] CipherText = new Byte[CipherTextWithMAC.Length - 32];
            Byte[] CipherTextMAC = new Byte[32];
            Array.Copy(CipherTextWithMAC, CipherTextMAC, 32);
            Array.Copy(CipherTextWithMAC, 32, CipherText, 0, CipherText.Length);
            //Nothing up my sleeve numbers that was taken from HMAC-SHA wikipedia
            Byte[] IPAD = new Byte[] { 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36 };
            Byte[] OPAD = new Byte[] { 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c };
            //Derive 2 keys by XOR-ing O/IPAD with the key
            Byte[] K1 = XOR(OPAD, Key);
            Byte[] K2 = XOR(IPAD, Key);
            Byte[] ConcatedMessageP2 = CipherText.Concat(K2).ToArray();
            Byte[] HashedCMessageP2 = CNSM3Digest.ComputeHashForMAC(ConcatedMessageP2, MyDigest);
            Byte[] ConcatedMessage = K1.Concat(HashedCMessageP2).ToArray();
            Byte[] MAC = CNSM3Digest.ComputeHashForMAC(ConcatedMessage, MyDigest, true);
            MyDigest.Reset();
            if (CipherTextMAC.SequenceEqual(MAC) == false)
            {
                throw new CryptographicException("Error: The message has been tampered");
            }
            Byte[] Message = US_CTR_Mode_Decrypt(CipherText, Nonce, Key);
            SodiumSecureMemory.SecureClearBytes(K1);
            SodiumSecureMemory.SecureClearBytes(K2);
            SodiumSecureMemory.SecureClearBytes(ConcatedMessageP2);
            SodiumSecureMemory.SecureClearBytes(ConcatedMessage);
            if (ClearKey == true)
            {
                SodiumSecureMemory.SecureClearBytes(Key);
            }
            return Message;
        }

        //There're many XOR versions
        //One require developer to XOR between 2 byte[] array
        //The other one was shown below
        //However, neither of these 2 are memory safe to use, if you are XOR-ing with cryptography sensitive data
        //Thought of implementing CTR/counter mode in SM4 but the memory safe version is not possible to implement.
        //Any users who use this XOR function for cryptographical use, please do bear in mind this is only 50% secure/safe.
        //Other factors which make it not secure is the way I implement counter mode in SM4.
        public static Byte[] XOR(Byte[] Source1, Byte[] Source2, Boolean ClearSource1 = false)
        {
            if (Source1 == null)
            {
                throw new ArgumentException("Error: Source1 byte array can't be null");
            }
            if (Source2 == null)
            {
                throw new ArgumentException("Error: Source2 byte array can't be null");
            }
            if (Source1.Length != Source2.Length)
            {
                throw new ArgumentException("Error: Source1 and source2 byte array length must be the same");
            }
            uint[] Source1uint = new uint[Source1.Length];
            uint[] Source2uint = new uint[Source2.Length];
            uint[] xoreduint = new uint[Source1.Length];
            int Loop = 0;
            Byte[] XOREDByte = new Byte[Source1.Length];
            Array.Copy(Source1, Source1uint, Source1.Length);
            Array.Copy(Source2, Source2uint, Source2.Length);
            while (Loop < Source1uint.Length)
            {
                xoreduint[Loop] = Source1uint[Loop] ^ Source2uint[Loop];
                Loop += 1;
            }
            Loop = 0;
            while (Loop < XOREDByte.Length)
            {
                XOREDByte[Loop] = (Byte)xoreduint[Loop];
                Loop += 1;
            }
            if (ClearSource1 == true)
            {
                SodiumSecureMemory.SecureClearBytes(Source1);
            }
            return XOREDByte;
        }
    }
}
