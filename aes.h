// aes.h
#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>
#include <stddef.h>

#define AES_BLOCKLEN 16

#if defined(AES256)
  #define AES_KEYLEN 32
  #define AES_keyExpSize 240
#elif defined(AES192)
  #define AES_KEYLEN 24
  #define AES_keyExpSize 208
#else
  #define AES_KEYLEN 16
  #define AES_keyExpSize 176
#endif

struct AES_ctx {
    uint8_t RoundKey[AES_keyExpSize];
#if defined(CBC) && CBC == 1
    uint8_t Iv[AES_BLOCKLEN];
#endif
};

void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);
void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);

#endif
