# BCASodium

This is an add on to ASodium, libsodium by default does not have X448 and ED448.
By combining Bouncy Castle and libsodium cryptography library, developers have
now easier access to X448 and ED448.

This is a new add-on, do expect bugs.

If you calculate sharedsecret with X448, do make sure to use KDF to generate a
32 bytes or 256 bits symmetric encryption key as the sharedsecret by default
is 448 bits or 56 bytes long
