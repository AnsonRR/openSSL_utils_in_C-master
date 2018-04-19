#include "utils.h"

void base64_encode(const char * input,char** output,int in_length)
{
    BIO* bmem = NULL;
    BIO* b64 = NULL;
    BUF_MEM* bptr = NULL;
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input, in_length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    *output = (char *)malloc(bptr->length + 1);
    memcpy(*output, bptr->data, bptr->length);
    (*output)[bptr->length] = 0;
    BIO_free_all(b64);
}

void base64_decode(const char * input, char** output,int* out_length)
{
    BIO* b64 = NULL;
    BIO* bio = NULL;
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new_mem_buf(input, strlen(input));
    bio = BIO_push(b64, bio);
    *output = (char*)malloc(strlen(input));
    *out_length = BIO_read(bio, *output, strlen(input));
    BIO_free_all(bio);
}


int encrypt_AES(const char* src,const char* key,char** dest)
{
    int nLen = strlen(src);//源串实际长度
    if(nLen == 0) return -1;
    AES_KEY aes;
    int nBei = nLen / AES_BLOCK_SIZE + 1;
    int nTotal = nBei * AES_BLOCK_SIZE;//填充之后的实际长度，比实际长度大一个1~AES_BLOCK_SIZE个字节
    if(nTotal < AES_BLOCK_SIZE ||  nTotal % AES_BLOCK_SIZE != 0) return -1;
    unsigned char* enc_s = (unsigned char*)malloc(nTotal);
    int nNumber;
    if (nLen % 16 > 0)
        nNumber = nTotal - nLen;
    else
        nNumber = 16;
    memset(enc_s, nNumber, nTotal);//先填充补位ASCII码:nNumber
    memcpy(enc_s, src, nLen);
    if (AES_set_encrypt_key((const unsigned char*)key, 128, &aes) < 0) {
        return -1;
    }
    unsigned char* encrypt_string = (unsigned char*)malloc(nTotal);//encrypt buffer
    memset(encrypt_string,0,nTotal);
    int block = 0;
    while(block < nTotal){//循环加密
        AES_ecb_encrypt(enc_s + block, encrypt_string + block, &aes, AES_ENCRYPT);
        block = block + AES_BLOCK_SIZE;
    }
    free(enc_s);
    char* base64;
    base64_encode((const char*)encrypt_string,&base64,nTotal);//BASE64 ENCODE
    *dest = (char*)malloc(sizeof(char)*(strlen(base64) + 1));
    memcpy(*dest,base64,strlen(base64));
    (*dest)[strlen(base64) + 1] = 0;
    free(encrypt_string);
    free(base64);
    return 0;
}

int decrypt_AES(const char* src,const char* key,char** dest)
{
    int src_len = strlen(src);
    if(src_len == 0) return -1;
    char* dedata;
    int nTotal=0;
    base64_decode(src,&dedata,&nTotal);//BASE64 DECODE
    if(nTotal == 0) return -1;
    AES_KEY aes;
    if (AES_set_decrypt_key((const unsigned char*)key, 128, &aes) < 0) {
        return -1;
    }
    unsigned char* decrypt_string = (unsigned char*)malloc(nTotal+1);//decrypt buffer
    memset(decrypt_string,0,nTotal+1);
    int block = 0;
    while(block < nTotal){//循环解密
        AES_ecb_encrypt((unsigned char*)dedata + block, decrypt_string + block, &aes, AES_DECRYPT);
        block = block + AES_BLOCK_SIZE;
    }
    *dest = (char*)malloc(sizeof(char)*nTotal+1);
    memcpy((*dest),decrypt_string,nTotal+1);
    free(decrypt_string);
    free(dedata);
    return 0;
}
