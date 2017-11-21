# encrypt_netdisk
An encrypted netdisk. Base on KVM(Key Encapsulation Mechanism) with CP-ABE(Cipher Policy Attribute Encryption) with Verifiable Outsourced Decryption. Multi attributes-set allowed.

It's Cipher Policy Attribute Encryption With Verifiable Outsourced Decryption base on [JunZuo Lai's paper](http://ieeexplore.ieee.org/document/6553162/). This paper is the "outsourced edition" for [Brent Waters' paper](https://eprint.iacr.org/2008/290.pdf).

Computation in bilinear group powered by [Charm-Crypto(0.50)](http://charm-crypto.io/).

The symmetric encryption algorithm is AES, powered by [PyCrypto](https://github.com/dlitz/pycrypto)

