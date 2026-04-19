/*
 * rijndael.c — AES (Rijndael) block cipher, 128/256/512-bit block sizes.
 *
 * STATE LAYOUT: Column-major (NIST FIPS-197 standard).
 *   state[row][col] is at block[row + 4*col]
 *
 * This is byte-for-byte compatible with the boppreh/aes reference and NIST vectors.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rijndael.h"

/* AES S-Box (NIST FIPS-197 Figure 7) */
static const unsigned char sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

/* AES Inverse S-Box (NIST FIPS-197 Figure 14) */
static const unsigned char inv_sbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

/* Round constants (index 0 unused) */
static const unsigned char rcon[30] = {
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,
    0x6c,0xd8,0xab,0x4d,0x9a,0x2f,0x5e,0xbc,0x63,0xc6,
    0x97,0x35,0x6a,0xd4,0xb3,0x7d,0xfa,0xef,0xc5
};

/* ---- Helpers ---- */
size_t block_size_to_bytes(aes_block_size_t block_size) {
    switch (block_size) {
    case AES_BLOCK_128: return 16;
    case AES_BLOCK_256: return 32;
    case AES_BLOCK_512: return 64;
    default: fprintf(stderr,"Invalid block size\n"); exit(1);
    }
}

static int block_num_cols(aes_block_size_t bs) {
    return (int)(block_size_to_bytes(bs) / 4);
}

static int block_num_rounds(aes_block_size_t bs) {
    switch (bs) {
    case AES_BLOCK_128: return 10;
    case AES_BLOCK_256: return 14;
    case AES_BLOCK_512: return 22;
    default: fprintf(stderr,"Invalid block size\n"); exit(1);
    }
}

/*
 * block_access — public API used by main.c.
 * Column-major: state[row][col] = block[row + 4*col].
 * The AES state always has exactly 4 rows.
 */
unsigned char block_access(unsigned char *block, size_t row, size_t col,
                           aes_block_size_t block_size) {
    (void)block_size;
    return block[row + 4 * col];
}

/* ---- GF(2^8) ---- */
static unsigned char xtime(unsigned char a) {
    return (a & 0x80) ? (unsigned char)((a << 1) ^ 0x1b)
                      : (unsigned char)(a << 1);
}

static unsigned char gmul(unsigned char a, unsigned char b) {
    unsigned char p = 0;
    int i;
    for (i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        { unsigned char hi = a & 0x80; a <<= 1; if (hi) a ^= 0x1b; }
        b >>= 1;
    }
    return p;
}

/* ---- SubBytes / InvSubBytes ---- */
void sub_bytes(unsigned char *block, aes_block_size_t block_size) {
    size_t n = block_size_to_bytes(block_size), i;
    for (i = 0; i < n; i++) block[i] = sbox[block[i]];
}

void invert_sub_bytes(unsigned char *block, aes_block_size_t block_size) {
    size_t n = block_size_to_bytes(block_size), i;
    for (i = 0; i < n; i++) block[i] = inv_sbox[block[i]];
}

/*
 * ShiftRows
 * Column-major: row r lives at indices r, r+4, r+8, ..., r+4*(cols-1).
 * Shift row r cyclically LEFT by r column positions.
 */
void shift_rows(unsigned char *block, aes_block_size_t block_size) {
    int cols = block_num_cols(block_size), row, col;
    unsigned char temp[16];
    for (row = 1; row < 4; row++) {
        for (col = 0; col < cols; col++)
            temp[col] = block[row + 4 * ((col + row) % cols)];
        for (col = 0; col < cols; col++)
            block[row + 4 * col] = temp[col];
    }
}

/* InvShiftRows: shift row r cyclically RIGHT by r column positions. */
void invert_shift_rows(unsigned char *block, aes_block_size_t block_size) {
    int cols = block_num_cols(block_size), row, col;
    unsigned char temp[16];
    for (row = 1; row < 4; row++) {
        for (col = 0; col < cols; col++)
            temp[col] = block[row + 4 * ((col - row + cols) % cols)];
        for (col = 0; col < cols; col++)
            block[row + 4 * col] = temp[col];
    }
}

/*
 * MixColumns
 * Column-major: column c = block[4c], block[4c+1], block[4c+2], block[4c+3].
 * Mix each column using the AES MixColumns matrix.
 * Compact form equivalent to matrix multiply with [2,3,1,1 / 1,2,3,1 / 1,1,2,3 / 3,1,1,2].
 */
void mix_columns(unsigned char *block, aes_block_size_t block_size) {
    int cols = block_num_cols(block_size), col;
    for (col = 0; col < cols; col++) {
        unsigned char s0 = block[0 + 4*col], s1 = block[1 + 4*col];
        unsigned char s2 = block[2 + 4*col], s3 = block[3 + 4*col];
        unsigned char t  = s0 ^ s1 ^ s2 ^ s3;
        block[0 + 4*col] = s0 ^ t ^ xtime(s0 ^ s1);
        block[1 + 4*col] = s1 ^ t ^ xtime(s1 ^ s2);
        block[2 + 4*col] = s2 ^ t ^ xtime(s2 ^ s3);
        block[3 + 4*col] = s3 ^ t ^ xtime(s3 ^ s0);
    }
}

/* InvMixColumns: inverse matrix [14,11,13,9 / 9,14,11,13 / 13,9,14,11 / 11,13,9,14]. */
void invert_mix_columns(unsigned char *block, aes_block_size_t block_size) {
    int cols = block_num_cols(block_size), col;
    for (col = 0; col < cols; col++) {
        unsigned char s0 = block[0 + 4*col], s1 = block[1 + 4*col];
        unsigned char s2 = block[2 + 4*col], s3 = block[3 + 4*col];
        block[0 + 4*col] = gmul(14,s0)^gmul(11,s1)^gmul(13,s2)^gmul( 9,s3);
        block[1 + 4*col] = gmul( 9,s0)^gmul(14,s1)^gmul(11,s2)^gmul(13,s3);
        block[2 + 4*col] = gmul(13,s0)^gmul( 9,s1)^gmul(14,s2)^gmul(11,s3);
        block[3 + 4*col] = gmul(11,s0)^gmul(13,s1)^gmul( 9,s2)^gmul(14,s3);
    }
}

/* AddRoundKey: XOR each byte with the round key. Self-inverse. */
void add_round_key(unsigned char *block, unsigned char *round_key,
                   aes_block_size_t block_size) {
    size_t n = block_size_to_bytes(block_size), i;
    for (i = 0; i < n; i++) block[i] ^= round_key[i];
}

/*
 * expand_key — Rijndael key schedule.
 * Returns heap-allocated (num_rounds+1)*key_bytes array. Caller must free.
 */
unsigned char *expand_key(unsigned char *cipher_key, aes_block_size_t block_size) {
    size_t key_bytes  = block_size_to_bytes(block_size);
    int    num_rounds = block_num_rounds(block_size);
    int    Nk         = (int)(key_bytes / 4);
    size_t total      = key_bytes * (size_t)(num_rounds + 1);
    int    bytes_done, rcon_idx, i;
    unsigned char temp[4];

    unsigned char *expanded = (unsigned char *)malloc(total);
    if (!expanded) { fprintf(stderr,"expand_key: malloc failed\n"); exit(1); }

    memcpy(expanded, cipher_key, key_bytes);
    bytes_done = (int)key_bytes;
    rcon_idx   = 1;

    while (bytes_done < (int)total) {
        memcpy(temp, expanded + bytes_done - 4, 4);
        if ((bytes_done / 4) % Nk == 0) {
            /* RotWord */
            unsigned char t = temp[0];
            temp[0]=temp[1]; temp[1]=temp[2]; temp[2]=temp[3]; temp[3]=t;
            /* SubWord */
            for (i = 0; i < 4; i++) temp[i] = sbox[temp[i]];
            /* Rcon */
            temp[0] ^= rcon[rcon_idx++];
        }
        for (i = 0; i < 4; i++) {
            expanded[bytes_done] = expanded[bytes_done - (int)key_bytes] ^ temp[i];
            bytes_done++;
        }
    }
    return expanded;
}

/*
 * aes_encrypt_block — full Rijndael encryption.
 * Returns heap-allocated ciphertext. Caller must free.
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key,
                                 aes_block_size_t block_size) {
    size_t n          = block_size_to_bytes(block_size);
    int    num_rounds = block_num_rounds(block_size), round;

    unsigned char *expanded = expand_key(key, block_size);
    unsigned char *output   = (unsigned char *)malloc(n);
    if (!output) { fprintf(stderr,"aes_encrypt_block: malloc failed\n"); free(expanded); exit(1); }

    memcpy(output, plaintext, n);
    add_round_key(output, expanded, block_size);

    for (round = 1; round < num_rounds; round++) {
        sub_bytes(output, block_size);
        shift_rows(output, block_size);
        mix_columns(output, block_size);
        add_round_key(output, expanded + round * (int)n, block_size);
    }
    /* Final round: no MixColumns */
    sub_bytes(output, block_size);
    shift_rows(output, block_size);
    add_round_key(output, expanded + num_rounds * (int)n, block_size);

    free(expanded);
    return output;
}

/*
 * aes_decrypt_block — full Rijndael decryption.
 * Returns heap-allocated plaintext. Caller must free.
 */
unsigned char *aes_decrypt_block(unsigned char *ciphertext, unsigned char *key,
                                 aes_block_size_t block_size) {
    size_t n          = block_size_to_bytes(block_size);
    int    num_rounds = block_num_rounds(block_size), round;

    unsigned char *expanded = expand_key(key, block_size);
    unsigned char *output   = (unsigned char *)malloc(n);
    if (!output) { fprintf(stderr,"aes_decrypt_block: malloc failed\n"); free(expanded); exit(1); }

    memcpy(output, ciphertext, n);
    add_round_key(output, expanded + num_rounds * (int)n, block_size);

    for (round = num_rounds - 1; round >= 1; round--) {
        invert_shift_rows(output, block_size);
        invert_sub_bytes(output, block_size);
        add_round_key(output, expanded + round * (int)n, block_size);
        invert_mix_columns(output, block_size);
    }
    invert_shift_rows(output, block_size);
    invert_sub_bytes(output, block_size);
    add_round_key(output, expanded, block_size);

    free(expanded);
    return output;
}