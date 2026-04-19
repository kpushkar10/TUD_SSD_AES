#!/usr/bin/env python3
"""
test_rijndael.py
Unit tests for the C Rijndael/AES implementation.

Each sub-step is tested by:
  1. Calling the C function via ctypes
  2. Comparing against an independent Python reference
  3. Asserting outputs match for at least 3 random inputs

Run:  python3 test_rijndael.py -v
Requires: rijndael.so (built by `make`), and optionally the boppreh/aes
          submodule at ./aes/ for the cross-library comparison tests.
"""

import ctypes
import os
import sys
import random
import unittest

# ---------------------------------------------------------------------------
# Load shared library
# ---------------------------------------------------------------------------
LIB_PATH = "./rijndael.so"
if not os.path.exists(LIB_PATH):
    print(f"ERROR: {LIB_PATH} not found. Run `make` first.", file=sys.stderr)
    sys.exit(1)

lib = ctypes.CDLL(LIB_PATH)

AES_BLOCK_128 = 0
AES_BLOCK_256 = 1
AES_BLOCK_512 = 2

lib.aes_encrypt_block.restype = ctypes.c_void_p
lib.aes_decrypt_block.restype = ctypes.c_void_p
lib.expand_key.restype        = ctypes.POINTER(ctypes.c_ubyte)

# ---------------------------------------------------------------------------
# Try to load boppreh/aes reference
# ---------------------------------------------------------------------------
try:
    sys.path.insert(0, "./aes")
    import aes as ref
    HAS_REF = True
except ImportError:
    HAS_REF = False
    print("WARNING: boppreh/aes not found – reference comparison tests skipped.")
    print("         git submodule add https://github.com/boppreh/aes aes")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def random_block(n=16):
    return bytes(random.randint(0, 255) for _ in range(n))

def c_buf(data):
    return ctypes.create_string_buffer(data)

def c_inplace(fn, data, block_enum):
    """Call a void C function that edits a block in-place; return result."""
    buf = c_buf(data)
    fn(buf, block_enum)
    return ctypes.string_at(buf, len(data))

def c_encrypt(pt, key, block_enum=AES_BLOCK_128):
    n = {0:16, 1:32, 2:64}[block_enum]
    ptr = lib.aes_encrypt_block(c_buf(pt), c_buf(key), block_enum)
    return ctypes.string_at(ptr, n)

def c_decrypt(ct, key, block_enum=AES_BLOCK_128):
    n = {0:16, 1:32, 2:64}[block_enum]
    ptr = lib.aes_decrypt_block(c_buf(ct), c_buf(key), block_enum)
    return ctypes.string_at(ptr, n)

# ---------------------------------------------------------------------------
# Pure-Python reference implementations (column-major, matching NIST/boppreh)
# ---------------------------------------------------------------------------

SBOX = [
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
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]

INV_SBOX = [
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
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
]

RCON = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,
        0x6c,0xd8,0xab,0x4d,0x9a,0x2f,0x5e,0xbc,0x63,0xc6,
        0x97,0x35,0x6a,0xd4,0xb3,0x7d,0xfa,0xef,0xc5]


def py_sub_bytes(block):
    return bytes(SBOX[b] for b in block)

def py_inv_sub_bytes(block):
    return bytes(INV_SBOX[b] for b in block)

def py_shift_rows(block, cols=4):
    """Column-major: row r at indices r, r+4, r+8, ... Shift row r left by r."""
    s = bytearray(block)
    for row in range(1, 4):
        tmp = [block[row + 4 * ((col + row) % cols)] for col in range(cols)]
        for col in range(cols):
            s[row + 4 * col] = tmp[col]
    return bytes(s)

def py_inv_shift_rows(block, cols=4):
    s = bytearray(block)
    for row in range(1, 4):
        tmp = [block[row + 4 * ((col - row + cols) % cols)] for col in range(cols)]
        for col in range(cols):
            s[row + 4 * col] = tmp[col]
    return bytes(s)

def xtime(a):
    return ((a << 1) ^ 0x1b) & 0xff if (a & 0x80) else (a << 1) & 0xff

def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        hi = a & 0x80; a = (a << 1) & 0xff
        if hi: a ^= 0x1b
        b >>= 1
    return p

def py_mix_columns(block, cols=4):
    """Column-major: column c at block[4c..4c+3]."""
    s = bytearray(block)
    for col in range(cols):
        s0,s1,s2,s3 = block[4*col],block[4*col+1],block[4*col+2],block[4*col+3]
        t = s0^s1^s2^s3
        s[4*col+0] = s0^t^xtime(s0^s1)
        s[4*col+1] = s1^t^xtime(s1^s2)
        s[4*col+2] = s2^t^xtime(s2^s3)
        s[4*col+3] = s3^t^xtime(s3^s0)
    return bytes(s)

def py_inv_mix_columns(block, cols=4):
    s = bytearray(block)
    for col in range(cols):
        s0,s1,s2,s3 = block[4*col],block[4*col+1],block[4*col+2],block[4*col+3]
        s[4*col+0] = gmul(14,s0)^gmul(11,s1)^gmul(13,s2)^gmul( 9,s3)
        s[4*col+1] = gmul( 9,s0)^gmul(14,s1)^gmul(11,s2)^gmul(13,s3)
        s[4*col+2] = gmul(13,s0)^gmul( 9,s1)^gmul(14,s2)^gmul(11,s3)
        s[4*col+3] = gmul(11,s0)^gmul(13,s1)^gmul( 9,s2)^gmul(14,s3)
    return bytes(s)

def py_add_round_key(block, key):
    return bytes(b^k for b,k in zip(block, key))

def py_expand_key(key):
    Nk = len(key) // 4
    Nr = {4:10, 8:14, 16:22}[Nk]
    total = len(key) * (Nr + 1)
    exp = bytearray(key)
    rcon_idx = 1
    while len(exp) < total:
        temp = list(exp[-4:])
        if (len(exp) // 4) % Nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [SBOX[b] for b in temp]
            temp[0] ^= RCON[rcon_idx]; rcon_idx += 1
        for i in range(4):
            exp.append(exp[-len(key)] ^ temp[i])
    return bytes(exp)


# ===========================================================================
# Test Classes
# ===========================================================================

class TestAddRoundKey(unittest.TestCase):
    """AddRoundKey is XOR — self-inverse, matches Python XOR."""

    def _test(self, block_enum, n):
        for trial in range(5):
            block = random_block(n)
            key   = random_block(n)
            buf   = c_buf(block)
            lib.add_round_key(buf, c_buf(key), block_enum)
            result = ctypes.string_at(buf, n)
            self.assertEqual(result, py_add_round_key(block, key),
                f"Trial {trial}: add_round_key mismatch (block_enum={block_enum})")
            # Applying again must recover original
            buf2 = c_buf(result)
            lib.add_round_key(buf2, c_buf(key), block_enum)
            self.assertEqual(ctypes.string_at(buf2, n), block,
                f"Trial {trial}: add_round_key not self-inverse (block_enum={block_enum})")

    def test_128(self): self._test(AES_BLOCK_128, 16)
    def test_256(self): self._test(AES_BLOCK_256, 32)
    def test_512(self): self._test(AES_BLOCK_512, 64)


class TestSubBytes(unittest.TestCase):
    """SubBytes output matches S-Box table; InvSubBytes is the inverse."""

    def _test(self, block_enum, n):
        for trial in range(5):
            block = random_block(n)
            c_fwd = c_inplace(lib.sub_bytes, block, block_enum)
            self.assertEqual(c_fwd, py_sub_bytes(block),
                f"Trial {trial}: sub_bytes mismatch (block_enum={block_enum})")
            c_inv = c_inplace(lib.invert_sub_bytes, c_fwd, block_enum)
            self.assertEqual(c_inv, block,
                f"Trial {trial}: invert_sub_bytes did not recover original (block_enum={block_enum})")

    def test_128(self): self._test(AES_BLOCK_128, 16)
    def test_256(self): self._test(AES_BLOCK_256, 32)
    def test_512(self): self._test(AES_BLOCK_512, 64)


class TestShiftRows(unittest.TestCase):
    """ShiftRows matches Python reference; InvShiftRows is the inverse."""

    def _test(self, block_enum, n, cols):
        for trial in range(5):
            block = random_block(n)
            c_fwd = c_inplace(lib.shift_rows, block, block_enum)
            self.assertEqual(c_fwd, py_shift_rows(block, cols),
                f"Trial {trial}: shift_rows mismatch (block_enum={block_enum})")
            c_inv = c_inplace(lib.invert_shift_rows, c_fwd, block_enum)
            self.assertEqual(c_inv, block,
                f"Trial {trial}: invert_shift_rows did not recover original (block_enum={block_enum})")

    def test_128(self): self._test(AES_BLOCK_128, 16, 4)
    def test_256(self): self._test(AES_BLOCK_256, 32, 8)
    def test_512(self): self._test(AES_BLOCK_512, 64, 16)


class TestMixColumns(unittest.TestCase):
    """MixColumns matches Python reference; InvMixColumns is the inverse."""

    def _test(self, block_enum, n, cols):
        for trial in range(5):
            block = random_block(n)
            c_fwd = c_inplace(lib.mix_columns, block, block_enum)
            self.assertEqual(c_fwd, py_mix_columns(block, cols),
                f"Trial {trial}: mix_columns mismatch (block_enum={block_enum})")
            c_inv = c_inplace(lib.invert_mix_columns, c_fwd, block_enum)
            self.assertEqual(c_inv, block,
                f"Trial {trial}: invert_mix_columns did not recover original (block_enum={block_enum})")

    def test_128(self): self._test(AES_BLOCK_128, 16, 4)
    def test_256(self): self._test(AES_BLOCK_256, 32, 8)
    def test_512(self): self._test(AES_BLOCK_512, 64, 16)


class TestExpandKey(unittest.TestCase):
    """Key expansion: NIST known-answer test + random inputs vs Python reference."""

    NIST_KEY = bytes([0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                      0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c])

    def _c_expanded(self, key, total):
        ptr = lib.expand_key(c_buf(key), AES_BLOCK_128)
        return bytes(ptr[i] for i in range(total))

    def test_128_fixed(self):
        """NIST FIPS-197 Appendix A.1: round key 0 must equal original key."""
        c_exp = self._c_expanded(self.NIST_KEY, 176)
        self.assertEqual(c_exp[:16], self.NIST_KEY, "Round key 0 != original key")
        self.assertEqual(c_exp, py_expand_key(self.NIST_KEY),
            "Full expanded key mismatch vs Python reference")

    def test_128_random(self):
        """3 random 128-bit keys: C must match Python reference."""
        for trial in range(3):
            key = random_block(16)
            ptr = lib.expand_key(c_buf(key), AES_BLOCK_128)
            c_exp = bytes(ptr[i] for i in range(176))
            self.assertEqual(c_exp, py_expand_key(key),
                f"Trial {trial}: expand_key mismatch")

    def test_256_random(self):
        """3 random 256-bit keys: C must match Python reference."""
        for trial in range(3):
            key = random_block(32)
            ptr = lib.expand_key(c_buf(key), AES_BLOCK_256)
            total = 32 * 15
            c_exp = bytes(ptr[i] for i in range(total))
            self.assertEqual(c_exp, py_expand_key(key),
                f"Trial {trial}: 256-bit expand_key mismatch")

    def test_512_random(self):
        """3 random 512-bit keys: round key 0 must equal original key."""
        for trial in range(3):
            key = random_block(64)
            ptr = lib.expand_key(c_buf(key), AES_BLOCK_512)
            total = 64 * 23
            c_exp = bytes(ptr[i] for i in range(total))
            self.assertEqual(c_exp[:64], key,
                f"Trial {trial}: 512-bit round key 0 mismatch")


class TestNISTKnownAnswer(unittest.TestCase):
    """
    NIST FIPS-197 Appendix B known-answer test.
    Our implementation uses column-major layout (same as NIST), so
    outputs must match exactly.
    """
    PT     = bytes([0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,
                    0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34])
    KEY    = bytes([0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                    0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c])
    CT     = bytes([0x39,0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,
                    0xdc,0x11,0x85,0x97,0x19,0x6a,0x0b,0x32])

    def test_encrypt(self):
        ct = c_encrypt(self.PT, self.KEY)
        self.assertEqual(ct, self.CT,
            f"NIST encrypt failed:\n  got {ct.hex()}\n  exp {self.CT.hex()}")

    def test_decrypt(self):
        pt = c_decrypt(self.CT, self.KEY)
        self.assertEqual(pt, self.PT,
            f"NIST decrypt failed:\n  got {pt.hex()}\n  exp {self.PT.hex()}")

    def test_roundtrip(self):
        ct  = c_encrypt(self.PT, self.KEY)
        pt2 = c_decrypt(ct, self.KEY)
        self.assertEqual(pt2, self.PT, "NIST roundtrip failed")


class TestEncryptDecryptRoundTrip(unittest.TestCase):
    """5 random encrypt->decrypt round-trips per block size."""

    def _roundtrip(self, block_enum, n, label):
        for trial in range(5):
            pt  = random_block(n)
            key = random_block(n)
            ct  = c_encrypt(pt, key, block_enum)
            pt2 = c_decrypt(ct, key, block_enum)
            self.assertEqual(pt2, pt,
                f"{label} trial {trial}: round-trip failed\n"
                f"  pt={pt.hex()}\n  ct={ct.hex()}\n  pt2={pt2.hex()}")

    def test_roundtrip_128(self): self._roundtrip(AES_BLOCK_128, 16, "AES-128")
    def test_roundtrip_256(self): self._roundtrip(AES_BLOCK_256, 32, "AES-256")
    def test_roundtrip_512(self): self._roundtrip(AES_BLOCK_512, 64, "AES-512")


class TestAgainstBoppreh(unittest.TestCase):
    """
    Compare C output directly against boppreh/aes.
    Both use column-major state layout, so outputs must be identical
    with no byte reordering.
    """

    @unittest.skipUnless(HAS_REF, "boppreh/aes submodule not available")
    def test_encrypt_128_vs_reference(self):
        """3 random inputs: C encrypt == boppreh encrypt_block."""
        for trial in range(3):
            pt  = random_block(16)
            key = random_block(16)
            c_ct  = c_encrypt(pt, key)
            py_ct = ref.AES(key).encrypt_block(pt)
            self.assertEqual(c_ct, py_ct,
                f"Trial {trial}: encrypt mismatch vs boppreh\n"
                f"  C ={c_ct.hex()}\n  Py={py_ct.hex()}")

    @unittest.skipUnless(HAS_REF, "boppreh/aes submodule not available")
    def test_decrypt_128_vs_reference(self):
        """3 random inputs: C decrypt == boppreh decrypt_block."""
        for trial in range(3):
            pt  = random_block(16)
            key = random_block(16)
            # Use boppreh to encrypt, C to decrypt
            ct    = ref.AES(key).encrypt_block(pt)
            c_pt2 = c_decrypt(ct, key)
            self.assertEqual(c_pt2, pt,
                f"Trial {trial}: decrypt mismatch vs boppreh\n"
                f"  C pt2={c_pt2.hex()}\n  orig={pt.hex()}")


class TestEdgeCases(unittest.TestCase):
    """All-zero, all-0xFF, wrong key, different plaintexts."""

    def test_zero_block_roundtrip(self):
        for be, n in [(AES_BLOCK_128,16),(AES_BLOCK_256,32),(AES_BLOCK_512,64)]:
            pt = key = bytes(n)
            ct  = c_encrypt(pt, key, be)
            self.assertNotEqual(ct, pt, f"Zero: ciphertext == plaintext (be={be})")
            pt2 = c_decrypt(ct, key, be)
            self.assertEqual(pt2, pt, f"Zero: roundtrip failed (be={be})")

    def test_all_ff_roundtrip(self):
        for be, n in [(AES_BLOCK_128,16),(AES_BLOCK_256,32)]:
            pt = key = bytes([0xff]*n)
            ct  = c_encrypt(pt, key, be)
            pt2 = c_decrypt(ct, key, be)
            self.assertEqual(pt2, pt, f"0xFF: roundtrip failed (be={be})")

    def test_different_keys_different_ciphertext(self):
        for be, n in [(AES_BLOCK_128,16),(AES_BLOCK_256,32)]:
            pt   = random_block(n)
            key1 = random_block(n)
            key2 = random_block(n)
            while key2 == key1: key2 = random_block(n)
            ct1 = c_encrypt(pt, key1, be)
            ct2 = c_encrypt(pt, key2, be)
            self.assertNotEqual(ct1, ct2, f"Different keys produced same ciphertext (be={be})")

    def test_wrong_key_fails(self):
        for be, n in [(AES_BLOCK_128,16),(AES_BLOCK_256,32)]:
            pt  = random_block(n)
            key = random_block(n)
            wrong = random_block(n)
            while wrong == key: wrong = random_block(n)
            ct  = c_encrypt(pt, key, be)
            pt2 = c_decrypt(ct, wrong, be)
            self.assertNotEqual(pt2, pt, f"Wrong key still decrypted correctly (be={be})")


if __name__ == "__main__":
    print("=" * 60)
    print("Rijndael/AES Unit Test Suite")
    print("=" * 60)
    unittest.main(verbosity=2)