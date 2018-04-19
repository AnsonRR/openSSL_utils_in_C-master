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
/**
 * @brief base64_encode
 * @param input
 * @param output
 * @param in_length
 */
void base64_encode(const char * input, char** output,int in_length);

/**
 * @brief base64_decode
 * @param input
 * @param output
 * @param out_length
 */
void base64_decode(const char * input, char** output,int* out_length);

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
