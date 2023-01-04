using System;
using System.Linq;

namespace BCASodium
{
    public static class PKCS5PaddingClass
    {

        //If message is not 128 bits in size after splitting into blocks
        public static Byte[] PKCS5Padding(Byte[] Message, Boolean IsUsedInGCM = false)
        {
            if (Message == null)
            {
                throw new ArgumentException("Error: Message can't be null");
            }
            uint Remainder = (uint)(Message.Length % 16);
            uint ActualRemainder = 16 - Remainder;
            Byte[] ConvertedRemainder = BitConverter.GetBytes(ActualRemainder);
            Byte[] ActualPadding = new Byte[] { ConvertedRemainder[0] };
            Byte[] PaddingCount = new Byte[] { ActualPadding[ActualPadding.Length - 1] };
            Byte[] Padding = new Byte[ActualRemainder];
            int Loop = 0;
            Byte[] PaddedMessage = new Byte[Message.Length + Padding.Length + 1];
            while (Loop < Padding.Length)
            {
                Padding[Loop] = PaddingCount[0];
                Loop += 1;
            }
            if (Remainder == 0)
            {
                return new Byte[] { };
            }
            if (IsUsedInGCM == false)
            {
                PaddedMessage = PaddingCount.Concat(Message).Concat(Padding).ToArray();
            }
            else
            {
                PaddedMessage = Message.Concat(Padding).ToArray();
            }
            return PaddedMessage;
        }
    }
}
