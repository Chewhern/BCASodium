using System;
using ASodium;

namespace BCASodium
{
    public static class SharedSecret56KDF
    {
        public static Byte[] KDFForX448SharedSecret(Byte[] X448SharedSecret, Byte[] Context, Boolean ClearKey)
        {
            if (X448SharedSecret == null)
            {
                throw new ArgumentException("Error: X448SharedSecret can't be null");
            }
            else
            {
                if (X448SharedSecret.Length != 56)
                {
                    throw new ArgumentException("Error: X448SharedSecret must be 56 bytes or 448 bits long");
                }
            }
            if (Context == null)
            {
                throw new ArgumentException("Error: Context can't be null");
            }
            else 
            {
                if (Context.Length > 8) 
                {
                    throw new ArgumentException("Error: Context length can't be bigger than 8 bytes or 64 bits");
                }
            }
            Byte[] SharedSecret = SodiumKDF.KDFFunction(32, 1, Context, X448SharedSecret);

            if (ClearKey == true) 
            {
                SodiumSecureMemory.SecureClearBytes(X448SharedSecret);
            }

            return SharedSecret;
        }
    }
}
