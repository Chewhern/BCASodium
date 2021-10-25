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

**Note specifically for version 0.0.3:\
Same note as 0.0.2 but the XOR helper class and the CTR mode can now be considered as memory safe.**

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

**Note specifically for version 0.0.4:\
Same note as 0.0.3.**
