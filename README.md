# AES_CBC-CMAC

AES-CBC-128 + AES-CMAC (NIST 800-38B)

K = cbcKey + K1 + K2

Pre encryption(using K1) of the iv, so it can be a sequential number. No need to be a random number.

![Alt text](image/CMAC.png)