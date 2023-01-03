# BCASodium

This is an add on to ASodium, libsodium by default does not have X448 and ED448.
By combining Bouncy Castle and libsodium cryptography library, developers have
now easier access to X448 and ED448.

**Try to avoid using ED448's signing and verifying if your message length is less than 114 bytes. I will try to find some time to fix the bug.**

This is a new add-on, do expect bugs.

If you calculate sharedsecret with X448, do make sure to use KDF to generate a
32 bytes or 256 bits symmetric encryption key as the sharedsecret by default
is 448 bits or 56 bytes long

Do refer to changelog for more information.
