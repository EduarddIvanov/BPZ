import unittest

from symmetric_cipher import SymmetricCipher, CipherError, ALGORITHMS, MODES


class TestSymmetricCipher(unittest.TestCase):

    def test_roundtrip_all_combinations(self):
        text = "Таємне повідомлення для перевірки шифру!"
        for algo in ALGORITHMS:
            for mode in MODES:
                cipher = SymmetricCipher(algo, mode)
                key = cipher.generate_key()
                iv = cipher.generate_iv() if cipher.needs_iv else None
                enc = cipher.encrypt_text(text, key, iv)
                dec = cipher.decrypt_text(enc, key, iv)
                self.assertEqual(dec, text, f"{algo}/{mode}")

    def test_ecb_needs_no_iv(self):
        cipher = SymmetricCipher("AES", "ECB")
        self.assertFalse(cipher.needs_iv)

    def test_cbc_needs_iv(self):
        cipher = SymmetricCipher("DES", "CBC")
        self.assertTrue(cipher.needs_iv)

    def test_wrong_key_size_rejected(self):
        cipher = SymmetricCipher("DES", "ECB")
        with self.assertRaises(CipherError):
            cipher.encrypt_text("abc", b"short")

    def test_wrong_iv_size_rejected(self):
        cipher = SymmetricCipher("DES", "CBC")
        key = cipher.generate_key()
        with self.assertRaises(CipherError):
            cipher.encrypt_text("abc", key, b"123")

    def test_wrong_key_fails_decrypt(self):
        cipher = SymmetricCipher("AES", "CBC")
        key = cipher.generate_key()
        iv = cipher.generate_iv()
        enc = cipher.encrypt_text("дані", key, iv)
        other = cipher.generate_key()
        with self.assertRaises(CipherError):
            cipher.decrypt_text(enc, other, iv)

    def test_unknown_algorithm(self):
        with self.assertRaises(CipherError):
            SymmetricCipher("RSA", "CBC")

    def test_unknown_mode(self):
        with self.assertRaises(CipherError):
            SymmetricCipher("DES", "XTS")

    def test_bad_base64_rejected(self):
        cipher = SymmetricCipher("DES", "ECB")
        key = cipher.generate_key()
        with self.assertRaises(CipherError):
            cipher.decrypt_text("не base64 @@@", key)

    def test_triple_des_key_length(self):
        cipher = SymmetricCipher("TripleDES", "ECB")
        self.assertIn(len(cipher.generate_key()), (16, 24))


if __name__ == "__main__":
    unittest.main()
