#ifndef _CRYPTO_H_
#define _CRYPTO_H_

int encrypt_data(const unsigned char* plaintext, int plaintext_len,
                 const unsigned char* key,
                 unsigned char* ciphertext,
                 unsigned char* iv, unsigned char* tag);

#endif
