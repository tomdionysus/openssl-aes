#ifndef AES_CORE
#define AES_CORE

#include "aes.h"

void AES_encrypt(const unsigned char *in, unsigned char *out,const AES_KEY *key);
void AES_decrypt(const unsigned char *in, unsigned char *out,const AES_KEY *key);

#endif