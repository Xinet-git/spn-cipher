import unittest

from spn_ecb_cbc_iso7816 import (
    BLOCK_SIZE,
    decrypt,
    encrypt,
    p_box,
    pad,
    unpad,
)


KEY = bytes.fromhex("00112233445566778899aabbccddeeff")


class SPNTests(unittest.TestCase):
    def test_round_trip_at_padding_boundaries(self):
        for mode in ("ECB", "CBC"):
            for length in (0, 1, 15, 16, 17, 31, 32, 48):
                with self.subTest(mode=mode, length=length):
                    data = bytes(range(length))
                    self.assertEqual(decrypt(encrypt(data, KEY, mode), KEY, mode), data)

    def test_p_box_inverse(self):
        block = bytes(range(BLOCK_SIZE))
        self.assertEqual(p_box(p_box(block), inverse=True), block)

    def test_full_block_padding(self):
        data = b"A" * BLOCK_SIZE
        self.assertEqual(pad(data), data + b"\x80" + b"\x00" * 15)
        self.assertEqual(unpad(pad(data)), data)

    def test_cbc_iv_and_ecb_repeated_blocks(self):
        data = b"A" * (BLOCK_SIZE * 2)
        ecb = encrypt(data, KEY, "ECB")
        self.assertEqual(ecb[:BLOCK_SIZE], ecb[BLOCK_SIZE:2 * BLOCK_SIZE])
        cbc1 = encrypt(data, KEY, "CBC")
        cbc2 = encrypt(data, KEY, "CBC")
        self.assertNotEqual(cbc1[:BLOCK_SIZE], cbc2[:BLOCK_SIZE])
        self.assertEqual(len(cbc1), len(ecb) + BLOCK_SIZE)

    def test_rejects_invalid_input(self):
        with self.assertRaises(ValueError):
            encrypt(b"data", b"short")
        with self.assertRaises(ValueError):
            decrypt(b"too short", KEY, "CBC")
        with self.assertRaises(ValueError):
            unpad(b"\x00" * BLOCK_SIZE)


if __name__ == "__main__":
    unittest.main()
