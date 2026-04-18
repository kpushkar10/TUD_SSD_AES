/*
 * TODO: Add your name and student number here, along with
 *       a brief description of this code.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rijndael.h"

// declaring sbox, inverse sbox, round constant table(for key expansion)
// sbox
static const unsigned char sbox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

// inverse sbox
static const unsigned char inv_sbox[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
  };

// Round constants for key expansion Rcon
static const unsigned char rcon[30] = {
    0x00, /* unused */
    0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,
    0x6c,0xd8,0xab,0x4d,0x9a,0x2f,0x5e,0xbc,0x63,0xc6,
    0x97,0x35,0x6a,0xd4,0xb3,0x7d,0xfa,0xef,0xc5
};

// ---------------------


/* ----------------------------------------------------------
 *  Helper: Number of bytes in a block 
 * ---------------------------------------------------------- */

size_t block_size_to_bytes(aes_block_size_t block_size) {
  switch (block_size) {
  case AES_BLOCK_128:
    return 16;
  case AES_BLOCK_256:
    return 32;
  case AES_BLOCK_512:
    return 64;
  default:
    fprintf(stderr, "Invalid block size %d\n", block_size);
    exit(1);
  }
}


/* ----------------------------------------------------------
 *  Helper: number of columns( = bytes/4 rows) 
 * ---------------------------------------------------------- */
static int block_num_cols(aes_block_size_t block_size) {
    return (int)(block_size_to_bytes(block_size) / 4);
}

/* ----------------------------------------------------------
 *  Helper: number of cipher rounds
 * ---------------------------------------------------------- */
static int block_num_rounds(aes_block_size_t block_size) {
    switch (block_size) {
    case AES_BLOCK_128: return 10;
    case AES_BLOCK_256: return 14;
    case AES_BLOCK_512: return 22;
    default:
        fprintf(stderr, "Invalid block size %d\n", block_size);
        exit(1);
    }
}



unsigned char block_access(unsigned char *block, size_t row, size_t col, aes_block_size_t block_size) {
  int row_len;
  switch (block_size) {
    case AES_BLOCK_128:
      row_len = 4;
      break;
    case AES_BLOCK_256:
      row_len = 8;
      break;
    case AES_BLOCK_512:
      row_len = 16;
      break;
    default:
      fprintf(stderr, "Invalid block size for block_access: %d\n", block_size);
      exit(1);
  }

  return block[(row * row_len) + col];
}

char *message(char n) {
  char *output = (char *)malloc(7);
  strcpy(output, "hello");
  output[5] = n;
  output[6] = 0;
  return output;
}

/* Multiply a byte by 2 in GF(2^8) */
static unsigned char xtime(unsigned char a) {
    return (a & 0x80) ? ((unsigned char)((a << 1) ^ 0x1b)) : (unsigned char)(a << 1);
}
 
/* General multiplication in GF(2^8) using the "Russian peasant" method */
static unsigned char gmul(unsigned char a, unsigned char b) {
    unsigned char p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        unsigned char hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

/*
 * Operations used when encrypting a block
 */

/* ----------------------------------------------------------
 *  SubBytes: replace every byte with its S-Box value 
 * ---------------------------------------------------------- */
void sub_bytes(unsigned char *block, aes_block_size_t block_size) {
  size_t n = block_size_to_bytes(block_size);
  for (size_t i = 0; i < n; i++) {
      block[i] = sbox[block[i]];
  }
}

/* ----------------------------------------------------------
 * ShiftRows: cyclically shift row i left by i positions
 *
 * Row 0: no shift
 * Row 1: shift left 1
 * Row 2: shift left 2
 * Row 3: shift left 3
 * ---------------------------------------------------------- */
void shift_rows(unsigned char *block, aes_block_size_t block_size) {
  int cols = block_num_cols(block_size);
    unsigned char temp[cols];
 
    for (int row = 1; row < 4; row++) {
      /* Copy current row into temp with a left-shift of 'row' positions */
      for (int col = 0; col < cols; col++) {
          temp[col] = block[row * cols + ((col + row) % cols)];
      }
      memcpy(&block[row * cols], temp, cols);
    }
}

/* ----------------------------------------------------------
 * MixColumns: multiply each column by the AES MixColumns matrix in GF(2^8)
 *
 * Matrix:
 *   [ 2  3  1  1 ]
 *   [ 1  2  3  1 ]
 *   [ 1  1  2  3 ]
 *   [ 3  1  1  2 ]
 *
 * Column col contains bytes: block[0*cols+col], block[1*cols+col],
 *                            block[2*cols+col], block[3*cols+col]
 * ---------------------------------------------------------- */
void mix_columns(unsigned char *block, aes_block_size_t block_size) {
  int cols = block_num_cols(block_size);
 
  for (int col = 0; col < cols; col++) {
    unsigned char s0 = block[0 * cols + col];
    unsigned char s1 = block[1 * cols + col];
    unsigned char s2 = block[2 * cols + col];
    unsigned char s3 = block[3 * cols + col];

    block[0 * cols + col] = xtime(s0) ^ xtime(s1) ^ s1 ^ s2 ^ s3;
    block[1 * cols + col] = s0 ^ xtime(s1) ^ xtime(s2) ^ s2 ^ s3;
    block[2 * cols + col] = s0 ^ s1 ^ xtime(s2) ^ xtime(s3) ^ s3;
    block[3 * cols + col] = xtime(s0) ^ s0 ^ s1 ^ s2 ^ xtime(s3);
  }
}



/*
 * Operations used when decrypting a block
 */

 /* ----------------------------------------------------------
 *  invert_sub_bytes: replace every byte with its inverse S-Box value
 * ---------------------------------------------------------- */
void invert_sub_bytes(unsigned char *block, aes_block_size_t block_size) {
  size_t n = block_size_to_bytes(block_size);
  for (size_t i = 0; i < n; i++) {
      block[i] = inv_sbox[block[i]];
  }
}


/* ----------------------------------------------------------
 *  invert_shift_rows: shift row i right by i positions
 * ---------------------------------------------------------- */
void invert_shift_rows(unsigned char *block, aes_block_size_t block_size) {
  int cols = block_num_cols(block_size);
  unsigned char temp[cols];

  for (int row = 1; row < 4; row++) {
    /* Right shift = left shift by (cols - row) */
    for (int col = 0; col < cols; col++) {
      temp[col] = block[row * cols + ((col - row + cols) % cols)];
    }
    memcpy(&block[row * cols], temp, cols);
  }
}

/* ----------------------------------------------------------
 *  Multiply each column by inverse mixColumns matrix

 * Inverse matrix:
 *  [ 14  11  13   9 ]
 *  [  9  14  11  13 ]
 *  [ 13   9  14  11 ]
 *  [ 11  13   9  14 ]
 * ---------------------------------------------------------- */
void invert_mix_columns(unsigned char *block, aes_block_size_t block_size) {
  int cols = block_num_cols(block_size);
 
  for (int col = 0; col < cols; col++) {
    unsigned char s0 = block[0 * cols + col];
    unsigned char s1 = block[1 * cols + col];
    unsigned char s2 = block[2 * cols + col];
    unsigned char s3 = block[3 * cols + col];

    block[0 * cols + col] = gmul(14,s0) ^ gmul(11,s1) ^ gmul(13,s2) ^ gmul( 9,s3);
    block[1 * cols + col] = gmul( 9,s0) ^ gmul(14,s1) ^ gmul(11,s2) ^ gmul(13,s3);
    block[2 * cols + col] = gmul(13,s0) ^ gmul( 9,s1) ^ gmul(14,s2) ^ gmul(11,s3);
    block[3 * cols + col] = gmul(11,s0) ^ gmul(13,s1) ^ gmul( 9,s2) ^ gmul(14,s3);
  }
}

/*
 * This operation is shared between encryption and decryption
 */
void add_round_key(unsigned char *block, 
                   unsigned char *round_key,
                   aes_block_size_t block_size) {
  size_t n = block_size_to_bytes(block_size);
  for (size_t i = 0; i < n; i++) {
    block[i] ^= round_key[i];
  }
}

/*
 * This function should expand the round key. Given an input,
 * which is a single 128-bit key, it should return a 176-byte
 * vector, containing the 11 round keys one after the other
 */
unsigned char *expand_key(unsigned char *cipher_key, aes_block_size_t block_size) {
  size_t key_bytes  = block_size_to_bytes(block_size);
    int    num_rounds = block_num_rounds(block_size);
    int    Nk         = (int)(key_bytes / 4);  /* words in original key */
    size_t total      = key_bytes * (num_rounds + 1);
 
    unsigned char *expanded = (unsigned char *)malloc(total);
    if (!expanded) {
        fprintf(stderr, "expand_key: malloc failed\n");
        exit(1);
    }
 
    /* Copy original key as first round key */
    memcpy(expanded, cipher_key, key_bytes);
 
    int bytes_done = (int)key_bytes;
    int rcon_idx   = 1;
 
    unsigned char temp[4];
 
    while (bytes_done < (int)total) {
        /* temp = last 4 bytes generated */
        memcpy(temp, expanded + bytes_done - 4, 4);
 
        if ((bytes_done / 4) % Nk == 0) {
            /* RotWord: rotate left by 1 byte */
            unsigned char t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
 
            /* SubWord: apply S-Box to each byte */
            for (int i = 0; i < 4; i++) temp[i] = sbox[temp[i]];
 
            /* XOR with round constant */
            temp[0] ^= rcon[rcon_idx++];
        }
 
        /* XOR temp with the word Nk positions back */
        for (int i = 0; i < 4; i++) {
            expanded[bytes_done] = expanded[bytes_done - key_bytes] ^ temp[i];
            bytes_done++;
        }
    }
 
    return expanded;
}

/*
 * The implementations of the functions declared in the
 * header file should go here
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext,
                                 unsigned char *key,
                                 aes_block_size_t block_size) {
  size_t n = block_size_to_bytes(block_size);
  int num_rounds = block_num_rounds(block_size);


  unsigned char *output = (unsigned char *)malloc(sizeof(unsigned char) * block_size_to_bytes(block_size));
    
  if (!output) {
    fprintf(stderr, "aes_encrypt_block: malloc failed\n");
    free(expanded);
    exit(1);
  }
  memcpy(output, plaintext, n);

  /* Initial round key addition */
  add_round_key(output, expanded, block_size);

  /* Main rounds */
  for (int round = 1; round < num_rounds; round++) {
    sub_bytes(output, block_size);
    shift_rows(output, block_size);
    mix_columns(output, block_size);
    add_round_key(output, expanded + round * n, block_size);
  }

  /* Final round (no MixColumns) */
  sub_bytes(output, block_size);
  shift_rows(output, block_size);
  add_round_key(output, expanded + num_rounds * n, block_size);

  free(expanded);
  return output;

}

unsigned char *aes_decrypt_block(unsigned char *ciphertext,
                                 unsigned char *key,
                                 aes_block_size_t block_size) {

  size_t n = block_size_to_bytes(block_size);
  int num_rounds = block_num_rounds(block_size);
  
  unsigned char *expanded = expand_key(key, block_size);

  unsigned char *output = (unsigned char *)malloc(sizeof(unsigned char) * block_size_to_bytes(block_size));
  
  if (!output) {
    fprintf(stderr, "aes_decrypt_block: malloc failed\n");
    free(expanded);
    exit(1);
  }

  memcpy(output, ciphertext, n);

  /* Undo the final encryption round key */
  add_round_key(output, expanded + num_rounds * n, block_size);

  for (int round = num_rounds - 1; round >= 1; round--) {
    invert_shift_rows(output, block_size);
    invert_sub_bytes(output, block_size);
    add_round_key(output, expanded + round * n, block_size);
    invert_mix_columns(output, block_size);
  }

  /* Undo the initial (round 0) addition */
  invert_shift_rows(output, block_size);
  invert_sub_bytes(output, block_size);
  add_round_key(output, expanded, block_size);

  free(expanded);
  return output;
}
