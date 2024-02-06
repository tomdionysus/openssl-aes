#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "aes_core.h"

void AES_cbc_XOR(unsigned char *out, const unsigned char *in) {
    uint64_t *out64 = (uint64_t *)out;
    const uint64_t *in64 = (const uint64_t *)in;

    for (int j = 0; j < 2; ++j) {
        out64[j] ^= in64[j];
    }
}

void AES_encrypt_cbc(const unsigned char *in, unsigned char *out, unsigned char *iv, const AES_KEY *key, unsigned long size) {
    // Ensure size is a multiple of 16 (AES block length)
    assert(size % 16 == 0);

    // Ensure 'in' and 'out' do not overlap
    assert(in + size <= out || out + size <= in);

    for (unsigned long i = 0; i < size; i += 16) {
        // XOR current block of plaintext with IV/previous ciphertext block
        AES_cbc_XOR(out + i, iv);

        // Encrypt the current block in place
        AES_encrypt(out + i, out + i, key);

        // Update IV with the just encrypted block
        iv = out + i;
    }
}

void AES_decrypt_cbc(const unsigned char *in, unsigned char *out, unsigned char *iv, const AES_KEY *key, unsigned long size) {
    // Ensure size is a multiple of 16 (AES block length)
    assert(size % 16 == 0);

    // Ensure 'in' and 'out' do not overlap
    assert(in + size <= out || out + size <= in);

    for (unsigned long i = 0; i < size; i += 16) {
        // Decrypt the current block
        AES_decrypt(in + i, out + i, key);

        // XOR decrypted block with IV/previous ciphertext block
        AES_cbc_XOR(out + i, iv);

        // Update IV to point to the current ciphertext block
        iv = (unsigned char *)(in + i);
    }
}
