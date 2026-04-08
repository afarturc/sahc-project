#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "crypto.h"

int encrypt_data(const unsigned char* plaintext, int plaintext_len,
                 const unsigned char* key,
                 unsigned char* ciphertext,
                 unsigned char* iv, unsigned char* tag)
{
    if (RAND_bytes(iv, 12) != 1) {
        printf("  ERRO: falha ao gerar IV aleatorio\n");
        return -1;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("  ERRO: falha ao criar contexto de encriptacao\n");
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1) {
        printf("  ERRO: falha ao inicializar cifra GCM\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        printf("  ERRO: falha ao definir chave/IV\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len;
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        printf("  ERRO: falha durante encriptacao\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    int ct_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        printf("  ERRO: falha ao finalizar encriptacao\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ct_len += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);
    return ct_len;
}
