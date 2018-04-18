#ifndef UTILS_H
#define UTILS_H
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef __APPLE__
    #include <mm_malloc.h>
#else
    #include <malloc.h>
#endif

#ifdef __cplusplus
extern "C"{
#endif

void base64Encode(const char * input, char** output);
void base64Decode(const char * input, char** output,int* out_size);

/**
 * AES-128-ECB，PKCS5Padding 加密
 * @brief encrypt_AES
 * @param src
 * @param key
 * @param dest
 * @return
 */
extern int encrypt_AES(const char* src,const char* key,char** dest);
/**
 * AES-128-ECB，PKCS5Padding 解密
 * @brief decrypt_AES
 * @param src
 * @param key
 * @param dest
 * @return
 */
extern int decrypt_AES(const char* src,const char* key,char** dest);

#ifdef __cplusplus
}
#endif
#endif //UTILS_H
