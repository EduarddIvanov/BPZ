import os
import unittest

from caesar import CaesarCipher, ByteCaesarCipher, CipherError
from bruteforce import BruteForceAttack


class TestCaesarCipher(unittest.TestCase):

    def test_roundtrip_uk(self):
        cipher = CaesarCipher("uk")
        text = "Привіт, світе!"
        self.assertEqual(cipher.decrypt(cipher.encrypt(text, 5), 5), text)

    def test_roundtrip_en(self):
        cipher = CaesarCipher("en")
        text = "Hello, World!"
        self.assertEqual(cipher.decrypt(cipher.encrypt(text, 7), 7), text)

    def test_known_shift_en(self):
        self.assertEqual(CaesarCipher("en").encrypt("abc", 3), "def")

    def test_case_is_preserved(self):
        result = CaesarCipher("en").encrypt("AbC", 1)
        self.assertEqual(result, "BcD")

    def test_non_alpha_untouched(self):
        text = "abc 123 .,!"
        result = CaesarCipher("en").encrypt(text, 4)
        self.assertEqual(result[3:], text[3:])

    def test_wraparound(self):
        self.assertEqual(CaesarCipher("en").encrypt("z", 1), "a")

    def test_key_reduced_by_modulo(self):
        cipher = CaesarCipher("en")
        self.assertEqual(cipher.encrypt("abc", 29), cipher.encrypt("abc", 3))


class TestValidation(unittest.TestCase):

    def test_zero_key_rejected(self):
        with self.assertRaises(CipherError):
            CaesarCipher("en").encrypt("abc", 0)

    def test_non_int_key_rejected(self):
        with self.assertRaises(CipherError):
            CaesarCipher("en").encrypt("abc", "5")

    def test_unknown_language(self):
        with self.assertRaises(CipherError):
            CaesarCipher("de")

    def test_text_type_checked(self):
        with self.assertRaises(CipherError):
            CaesarCipher("en").encrypt(123, 3)


class TestByteCipher(unittest.TestCase):

    def test_roundtrip_bytes(self):
        cipher = ByteCaesarCipher()
        data = os.urandom(64)
        self.assertEqual(cipher.decrypt(cipher.encrypt(data, 100), 100), data)

    def test_bytes_type_checked(self):
        with self.assertRaises(CipherError):
            ByteCaesarCipher().encrypt("not bytes", 3)


class TestBruteForce(unittest.TestCase):

    def test_finds_correct_key(self):
        cipher = CaesarCipher("uk")
        original = "це секретне повідомлення для перевірки атаки перебором"
        encrypted = cipher.encrypt(original, 11)
        best_key, best_text, _ = BruteForceAttack("uk").best_guess(encrypted)
        self.assertEqual(best_key, 11)
        self.assertEqual(best_text, original)


if __name__ == "__main__":
    unittest.main()
