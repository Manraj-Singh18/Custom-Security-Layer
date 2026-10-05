#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/kdf.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include "com.h"
#include "encrypt.h"








int derive_key(unsigned char* encryption_key, unsigned char* mac_key, unsigned char* skey,enum TLSWriter writer){
    unsigned char prk[32];  
    EVP_KDF* kdf = EVP_KDF_fetch(NULL,"HKDF",NULL);
    EVP_KDF_CTX* extract_ctx = EVP_KDF_CTX_new(kdf);
    const char* info;
    const char* mac_info; 
    //Check who writes
    switch(writer){
        case CLIENT:
            info = "CSL Client-to-Server Encryption-Key";
            mac_info = "CSL Client-to-Server MAC-Key";
            break;
        case SERVER:
            info = "CSL Server-to-Client Encryption-Key";
            mac_info = "CSL Server-to-Client MAC-Key";
            break;

    }
    // extract encryption key
    OSSL_PARAM extract_params[]={
        OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_DIGEST,
        "SHA256",
        0
    ),

    OSSL_PARAM_construct_octet_string(
    OSSL_KDF_PARAM_KEY,
    skey,
    32
    ),  
    OSSL_PARAM_construct_utf8_string(
    OSSL_KDF_PARAM_MODE,
    "EXTRACT_ONLY",
    0
    ),

    OSSL_PARAM_construct_end()
    };
    if (EVP_KDF_derive(extract_ctx,prk,sizeof(prk),extract_params) <= 0) {
    fprintf(stderr, "HKDF-Extract failed\n");
    return 1;
}

    EVP_KDF_CTX_free(extract_ctx);
// expand encryption key
    EVP_KDF_CTX* expand_ctx = EVP_KDF_CTX_new(kdf);
    OSSL_PARAM expand_params[]={
        OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_DIGEST,
        "SHA256",
        0
    ),

    OSSL_PARAM_construct_octet_string(
    OSSL_KDF_PARAM_KEY,
    prk,
    sizeof(prk)
    ),
    OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_INFO,
        (void *)info,
        strlen(info)
    ),

    OSSL_PARAM_construct_utf8_string(
    OSSL_KDF_PARAM_MODE,
    "EXPAND_ONLY",
    0
    ),

    OSSL_PARAM_construct_end()
    };
    if (EVP_KDF_derive(expand_ctx, encryption_key, 32, expand_params) <= 0) {
    fprintf(stderr, "HKDF-Expand failed\n");
    EVP_KDF_CTX_free(expand_ctx);
    EVP_KDF_free(kdf);
    return 1;
}
    EVP_KDF_CTX_free(expand_ctx);
// expand mac key
EVP_KDF_CTX* mac_ctx = EVP_KDF_CTX_new(kdf);

    OSSL_PARAM mac_params[]={
        OSSL_PARAM_construct_utf8_string(
        OSSL_KDF_PARAM_DIGEST,
        "SHA256",
        0
    ),

    OSSL_PARAM_construct_octet_string(
    OSSL_KDF_PARAM_KEY,
    prk,
    sizeof(prk)
    ),
    OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_INFO,
        (void *)mac_info,
        strlen(mac_info)
    ),

    OSSL_PARAM_construct_utf8_string(
    OSSL_KDF_PARAM_MODE,
    "EXPAND_ONLY",
    0
    ),

    OSSL_PARAM_construct_end()
    };
    if (EVP_KDF_derive(mac_ctx, mac_key, 32, mac_params) <= 0) {
    fprintf(stderr, "HKDF-Expand MAC key failed\n");

    EVP_KDF_CTX_free(mac_ctx);
    EVP_KDF_free(kdf);
    return 1;
}
EVP_KDF_CTX_free(mac_ctx);
EVP_KDF_free(kdf);
return 0;




}


void make_nonce(unsigned char *nonce,const unsigned char *iv,uint64_t seq)
{
    memcpy(nonce, iv, 12);

    for (int i = 0; i < 8; i++) {
        nonce[11 - i] ^= (seq >> (8 * i)) & 0xff;
    }
}

int encrypt_message(const unsigned char *plaintext,
    int plaintext_len,
    unsigned char* public_write_key,
    const unsigned char *write_key,
    uint64_t seq,
    unsigned char *ciphertext,
    unsigned char *tag){
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        int len;
        int ciphertext_len;
        if (ctx == NULL) {
        fprintf(stderr, "Failed to create cipher context\n");
        return -1;

    }
    unsigned char* nonce[12];
    unsigned char aad[8];
    memcpy(aad, &seq, 8);
    int aad_len = 8;
    make_nonce(nonce,public_write_key,seq);
    if (EVP_EncryptInit_ex(
            ctx,
            EVP_aes_256_gcm(),
            NULL,
            NULL,
            NULL) != 1) {

        fprintf(stderr, "EVP_EncryptInit_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (EVP_EncryptInit_ex(
            ctx,
            NULL,
            NULL,
            NULL,
            nonce) != 1) {
    
        fprintf(stderr, "Failed to set nonce\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
if (EVP_EncryptInit_ex(
            ctx,
            NULL,
            NULL,
            write_key,
            NULL) != 1) {
        fprintf(stderr, "Failed to set key\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
if (aad != NULL && aad_len > 0) {

        if (EVP_EncryptUpdate(
                ctx,
                NULL,
                &len,
                aad,
                aad_len) != 1) {

            fprintf(stderr, "Failed to process AAD\n");
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
    }
  if (EVP_EncryptUpdate(
            ctx,
            ciphertext,
            &len,
            plaintext,
            plaintext_len) != 1) {

        fprintf(stderr, "Encryption failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
ciphertext_len = len;
if (EVP_EncryptFinal_ex(
            ctx,
            ciphertext + ciphertext_len,
            &len) != 1) {

        fprintf(stderr, "Encryption finalization failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    ciphertext_len += len;

    if (EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_GET_TAG,
            TAG_LEN,
            tag) != 1) {

        fprintf(stderr, "Failed to get GCM tag\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;


}

int decrypt_message(
    const unsigned char *ciphertext,
    int ciphertext_len,

    const unsigned char *write_key,
    unsigned char *public_write_key,

    uint64_t seq,

    const unsigned char *tag,

    unsigned char *plaintext
)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;


    ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL) {
        fprintf(stderr, "Failed to create cipher context\n");
        return -1;
    }
    unsigned char* nonce[12];
    unsigned char aad[8];
    memcpy(aad, &seq, 8);
    int aad_len = 8;
    make_nonce(nonce,public_write_key,seq);

    if (EVP_DecryptInit_ex(
            ctx,
            EVP_aes_256_gcm(),
            NULL,
            NULL,
            NULL) != 1) {

        fprintf(stderr, "EVP_DecryptInit_ex failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }


    if (EVP_DecryptInit_ex(
            ctx,
            NULL,
            NULL,
            NULL,
            nonce) != 1) {

        fprintf(stderr, "Failed to set nonce\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }


    if (EVP_DecryptInit_ex(
            ctx,
            NULL,
            NULL,
            write_key,
            NULL) != 1) {

        fprintf(stderr, "Failed to set key\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }


    if (aad != NULL && aad_len > 0) {

        if (EVP_DecryptUpdate(
                ctx,
                NULL,
                &len,
                aad,
                aad_len) != 1) {

            fprintf(stderr, "Failed to process AAD\n");
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
    }


    if (EVP_DecryptUpdate(
            ctx,
            plaintext,
            &len,
            ciphertext,
            ciphertext_len) != 1) {

        fprintf(stderr, "Decryption failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    plaintext_len = len;


    if (EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_GCM_SET_TAG,
            TAG_LEN,
            (void *)tag) != 1) {

        fprintf(stderr, "Failed to set GCM tag\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }


    if (EVP_DecryptFinal_ex(
            ctx,
            plaintext + plaintext_len,
            &len) <= 0) {

        fprintf(stderr, "Authentication FAILED\n");

        EVP_CIPHER_CTX_free(ctx);

        return -1;
    }


    plaintext_len += len;


    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

