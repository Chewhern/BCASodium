using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;

namespace BCASodium
{
    public static class PKCS1V15PaddingClass
    {
        //Implemented via this diagram
        //https://crypto.stackexchange.com/questions/61178/why-ps-does-differ-between-pkcs1-v1-5-padding-for-signature-and-for-encryption
        public static Byte[] AddSignaturePadding(Byte[] Message,int Length = 115) 
        {
            Byte[] InitialPadBytes = new Byte[] { 0x00, 0x01 };
            Byte[] FinalPadBytes = new Byte[] {0x00 };
            Byte[] PaddingBytes = new Byte[] { 0xFF };
            Byte[] Padding = new Byte[] { };
            Byte[] PaddedMessage = new Byte[] { };
            int Loop = 0;
            int ActualLength = Length - 3 - (Message.Length);
            if (ActualLength + 3 + Message.Length > Length) 
            {
                throw new ArgumentException("Error: Refer to PKCS1V15 Padding Class method for more information");
            }
            while (Loop < ActualLength) 
            {
                Padding = Padding.Concat(PaddingBytes).ToArray();
                Loop += 1;
            }
            Padding = InitialPadBytes.Concat(Padding).Concat(FinalPadBytes).ToArray();
            PaddedMessage = Padding.Concat(Message).ToArray();
            if (PaddedMessage.Length != Length) 
            {
                throw new ArgumentException("Error: Padded Message length is not the same as specified length");
            }
            return PaddedMessage;
        }
    }
}
