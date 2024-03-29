**Note for all versions\
Please refer to the note on version 0.0.2**

# Version 0.0.1
1. Add ED448
2. Add X448

# Version 0.0.2
1. Add SM4 (China's Block Cipher which declassified in 2006)
2. Add SM3 (China's Hashing algorithm)

**Note specifically for version 0.0.2:\
My implementation may be unsafe, if you just code it on client
application should be fine. If you want to use it on something which's
online like on virtual private server, you are advised not to use it as
there'll be some unforeseen security issues and problems.**

# Version 0.0.3
1. Fixes some issues that causes by absence of padding in SM4
2. Add XOR helper class
3. Add PKCS5 padding (https://www.di-mgt.com.au/cryptopad.html)
4. Add ECB mode
5. Switch the HMAC calculation from SM4 to SM3

# Version 0.0.4
1. Migrate PKCS5Padding function from CNSM4 to a helper class of its own
2. Slight modification to PKCS5Padding
3. Add GCM Mode for SM4
4. Add GCM Counter Mode for SM4
5. Add GCM GMAC function for SM4
6. Remove unnecessary code
7. Add SHAKEDigest and Keccak Digest
8. Add KDF function for shrinking the shared secret calculated from X448 CalculateSharedSecret Function to 32 bytes or 256 bits
9. Add function to calculate Signature+Message
10. Add function to get Message from SignatureMessage if signature verification succeed

# Version 0.0.5
1. Add Nonce and Key Generation function into CNSM4
2. Convert **GCM_CTR_Encrypt,GCM_CTR_Decrypt,GCM_GenerateGMAC** from public into private
3. **sodium_memcmp** was used to replace the **System.Linq.SequenceEqual()** so that it's always **constant time compare**.

# Version 0.0.6
1. Uses libsodium PRF to create additional padding in signing and verifying messages (SecureED448).
2. Slight rework on ED448RevampedKeyPair and X448RevampedKeyPair.

# Version 0.0.7 (Unlisted)
1. Remove libsodium PRF from BCASodium.
2. All paddings were centralized and moved into PaddingClass.
3. Uses bouncycastle's 6 padding schemes to create additional padding in signing and verifying messages (SecureED448).
4. CNSM3Digest,Keccak,SHAKE uses **private static** when dealing with streams of messages.
5. CNSM4 removes all insecure modes of operations.
6. CNSM4 now uses Blake2B and 2 secret keys to create **domain separation** in CTR mode.
7. CNSM3Digest,Keccak,SHAKE now uses public/private context to derive 2 subkeys to xor with IPAD and OPAD in calculating HMAC.
8. Slight rework on XORHelper.
9. BCASodium now uses only **.Net Standard 2.0**.

# Version 0.0.8 (Unlisted)
1. Rename **PaddingClass** into **BlockCipherPaddingClass**.
2. Add **PKCS1V1.5PaddingClass**.
3. **SecureED448** now uses **ZeroPadding** or **PKCS1V1.5PaddingClass**.

# Version 0.0.9 (Unlisted)
1. **SecureED448** now uses bouncycastle's prehash signing and verification.
2. Removed **PKCS1V1.5PaddingClass**.

# Version 0.1.0
1. Fixes some bug in CTR mode.
2. Added a slightly constant time XOR method in **XORHelper** class.
3. CNSM4's CTR mode is now slightly constant time in performance. 

**From 0.1.0 version onwards, there won't be any more unlisting.**

**Replacement of XOR operations in HMAC generation will be replaced with slightly constant time method in future updates.**

# Version 0.1.1
1. Added  **KMAC**
2. Removed **HMAC** from **Keccak** and **SHAKE**.
3. Slightly rework on **ComputeHashForNonFinalizedData** for SM3Digest,Keccak and SHAKE.
4. ED448RevampedKeyPair and X448RevampedKeyPair **Clear()** function has been slightly reworked. 

# Version 0.1.2
1. Removed **HMAC** from SM3Digest.
2. Added **HMACHelper** which allows supported digest algorithms to create HMACs.
3. SM4's **HMACCTREncrypt** and **HMACCTRDecrypt** now uses HMACHelper.

# Version 0.1.3
1. Switched to **.Net 6.0** and extends support for **.Net Standard 2.0**
2. Now uses the official nuget **bouncycastle.cryptography** instead of **Portable.BouncyCastle**.
3. Change the **KMACHelper** from the latter library to first library compatible. 

# Version 0.1.4
1. **KMACHelper** fixes some bug

# Version 0.1.5
1. Upgrades to use latest ASodium (0.5.9)

# Version 0.1.6
1. Upgrades to use latest ASodium (0.6.0)
2. HMACHelper and KMACHelper both uses latest version of ASodium's Sodium_Memory_Compare.

# Version 0.1.7
1. Fixes bug in SHAKEDigest **ComputeHash** function. (For details, kindly read my comments in the code)

# Version 0.1.8
1. Fixes minor bug in KMACHelper function. (For details, kindly read refer to **VerifyKMAC**)
