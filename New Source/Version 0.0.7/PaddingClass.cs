using System;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Security;


namespace BCASodium
{
    public static class PaddingClass
    {
        public static void ISO10126D2AddPadding(Byte[] Data, int LengthWherePaddingStart)
        {
            if (Data == null)
            {
                throw new ArgumentNullException("Error: Data can't be null");
            }
            if (Data.Length == 0 || LengthWherePaddingStart == 0)
            {
                throw new ArgumentException("Error: Parameter value or length should not be 0");
            }
            ISO10126d2Padding padder = new ISO10126d2Padding();
            SecureRandom myrandom = new SecureRandom();
            padder.Init(myrandom);
            padder.AddPadding(Data, LengthWherePaddingStart);
        }

        public static Byte[] ISO10126D2RemovePadding(Byte[] Data)
        {
            if (Data == null)
            {
                throw new ArgumentNullException("Error: Data can't be null");
            }
            if (Data.Length == 0)
            {
                throw new ArgumentException("Error: Data length should not be 0");
            }
            ISO10126d2Padding padder = new ISO10126d2Padding();
            int padcount = padder.PadCount(Data);
            Byte[] UnpaddedData = new Byte[Data.Length - padcount];
            Array.Copy(Data, 0, UnpaddedData, 0, UnpaddedData.Length);
            return UnpaddedData;
        }

        public static void ISO7816D4AddPadding(Byte[] Data, int LengthWherePaddingStart)
        {
            if (Data == null)
            {
                throw new ArgumentNullException("Error: Data can't be null");
            }
            if (Data.Length == 0 || LengthWherePaddingStart == 0)
            {
                throw new ArgumentException("Error: Parameter value or length should not be 0");
            }
            ISO7816d4Padding padder = new ISO7816d4Padding();
            padder.AddPadding(Data, LengthWherePaddingStart);
        }

        public static Byte[] ISO7816d4PaddingRemovePadding(Byte[] Data)
        {
            if (Data == null)
            {
                throw new ArgumentNullException("Error: Data can't be null");
            }
            if (Data.Length == 0)
            {
                throw new ArgumentException("Error: Data length should not be 0");
            }
            ISO7816d4Padding padder = new ISO7816d4Padding();
            int padcount = padder.PadCount(Data);
            Byte[] UnpaddedData = new Byte[Data.Length - padcount];
            Array.Copy(Data, 0, UnpaddedData, 0, UnpaddedData.Length);
            return UnpaddedData;
        }

        public static void PKCS7AddPadding(Byte[] Data,int LengthWherePaddingStart) 
        {
            if (Data == null) 
            {
                throw new ArgumentNullException("Error: Data can't be null");
            }
            if (Data.Length == 0 || LengthWherePaddingStart == 0) 
            {
                throw new ArgumentException("Error: Parameter value or length should not be 0");
            }
            Pkcs7Padding padder = new Pkcs7Padding();
            padder.AddPadding(Data, LengthWherePaddingStart);
        }

        public static Byte[] PKCS7RemovePadding(Byte[] Data)
        {
            if (Data == null)
            {
                throw new ArgumentNullException("Error: Data can't be null");
            }
            if (Data.Length == 0)
            {
                throw new ArgumentException("Error: Data length should not be 0");
            }
            Pkcs7Padding padder = new Pkcs7Padding();
            int padcount = padder.PadCount(Data);
            Byte[] UnpaddedData = new Byte[Data.Length - padcount];
            Array.Copy(Data, 0, UnpaddedData, 0, UnpaddedData.Length);
            return UnpaddedData;
        }

        public static void TBCAddPadding(Byte[] Data, int LengthWherePaddingStart)
        {
            if (Data == null)
            {
                throw new ArgumentNullException("Error: Data can't be null");
            }
            if (Data.Length == 0 || LengthWherePaddingStart == 0)
            {
                throw new ArgumentException("Error: Parameter value or length should not be 0");
            }
            TbcPadding padder = new TbcPadding();
            padder.AddPadding(Data, LengthWherePaddingStart);
        }

        public static Byte[] TBCRemovePadding(Byte[] Data)
        {
            if (Data == null)
            {
                throw new ArgumentNullException("Error: Data can't be null");
            }
            if (Data.Length == 0)
            {
                throw new ArgumentException("Error: Data length should not be 0");
            }
            TbcPadding padder = new TbcPadding();
            int padcount = padder.PadCount(Data);
            Byte[] UnpaddedData = new Byte[Data.Length - padcount];
            Array.Copy(Data, 0, UnpaddedData, 0, UnpaddedData.Length);
            return UnpaddedData;
        }

        //X923 allows both secure random or CRNG use as its padding
        //or zero bytes as its padding
        public static void X923AddPadding(Byte[] Data, int LengthWherePaddingStart)
        {
            if (Data == null)
            {
                throw new ArgumentNullException("Error: Data can't be null");
            }
            if (Data.Length == 0 || LengthWherePaddingStart == 0)
            {
                throw new ArgumentException("Error: Parameter value or length should not be 0");
            }
            X923Padding padder = new X923Padding();
            SecureRandom myrandom = new SecureRandom();
            padder.Init(myrandom);
            padder.AddPadding(Data, LengthWherePaddingStart);
        }

        public static Byte[] X923RemovePadding(Byte[] Data)
        {
            if (Data == null)
            {
                throw new ArgumentNullException("Error: Data can't be null");
            }
            if (Data.Length == 0)
            {
                throw new ArgumentException("Error: Data length should not be 0");
            }
            X923Padding padder = new X923Padding();
            int padcount = padder.PadCount(Data);
            Byte[] UnpaddedData = new Byte[Data.Length - padcount];
            Array.Copy(Data, 0, UnpaddedData, 0, UnpaddedData.Length);
            return UnpaddedData;
        }

        public static void ZeroByteAddPadding(Byte[] Data, int LengthWherePaddingStart)
        {
            if (Data == null)
            {
                throw new ArgumentNullException("Error: Data can't be null");
            }
            if (Data.Length == 0 || LengthWherePaddingStart == 0)
            {
                throw new ArgumentException("Error: Parameter value or length should not be 0");
            }
            ZeroBytePadding padder = new ZeroBytePadding();
            padder.AddPadding(Data, LengthWherePaddingStart);
        }

        public static Byte[] ZeroByteRemovePadding(Byte[] Data)
        {
            if (Data == null)
            {
                throw new ArgumentNullException("Error: Data can't be null");
            }
            if (Data.Length == 0)
            {
                throw new ArgumentException("Error: Data length should not be 0");
            }
            ZeroBytePadding padder = new ZeroBytePadding();
            int padcount = padder.PadCount(Data);
            Byte[] UnpaddedData = new Byte[Data.Length - padcount];
            Array.Copy(Data, 0, UnpaddedData, 0, UnpaddedData.Length);
            return UnpaddedData;
        }
    }
}
