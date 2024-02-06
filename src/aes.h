#ifndef OPENSSL_AES
#define OPENSSL_AES

#define AES_BLOCK_SIZE 16

#define AES_MAXNR 14

/* This should be a hidden type, but EVP requires that the size be known */
struct aes_key_st {
    unsigned int rd_key[4 * (AES_MAXNR + 1)];
    int rounds;
};

typedef struct aes_key_st AES_KEY;

#endif