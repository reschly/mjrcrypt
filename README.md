mjrcrypt
========

Pure Python crypto library

This library isn't any better than any other library.  I make no claims about speed, memory usage, or any other metric by which you would measure a library.  It's not regularly maintained (I do this in my limited spare time).  It's just a side project I've been meaning to take on for a while.  

This has been a useful side project in that it has:
* forced me to read algorithm specifications, which has demystified those algorithms
* let me experiment with ideas regarding what an easy-to-use crypto API should look like

This library will include algorithms I like, and won't include any I don't.  This means:

Included:
* AES-GCM
* AES-CTR-DRBG

To be included (eventually):
* RSA-PSS
* RSA-OAEP
* SHA-256 (384, 512) 
* Simon, Speck (using HMAC-SHA256 for AE?)
* ECDHE/ECDSA (P-256, 384, 521)

To never be included:
* DES/3DES
* RSA-PKCS1 (sign or encrypt)
* RC4
