import random
import unittest

from book_cipher import BookCipher, PoemKey, CipherError, DEFAULT_POEM
from word_book_cipher import WordBookCipher


class TestPoemCipher(unittest.TestCase):

    def setUp(self):
        self.cipher = BookCipher()
        self.key = PoemKey(DEFAULT_POEM, 10, 10)

    def test_roundtrip(self):
        text = "небо"
        enc = self.cipher.encrypt(text, self.key)
        self.assertEqual(self.cipher.decrypt(enc, self.key), text)

    def test_ignores_non_alpha(self):
        enc = self.cipher.encrypt("не бо!", self.key)
        self.assertEqual(self.cipher.decrypt(enc, self.key), "небо")

    def test_code_format(self):
        enc = self.cipher.encrypt("н", self.key)
        self.assertRegex(enc, r"^\d{2}/\d{2}$")

    def test_random_gives_valid_coords(self):
        # різні випадкові координати все одно розшифровуються в той самий символ
        rng = random.Random(1)
        enc = self.cipher.encrypt("ннн", self.key, rng=rng)
        self.assertEqual(self.cipher.decrypt(enc, self.key), "ннн")

    def test_missing_char_raises(self):
        with self.assertRaises(CipherError):
            self.cipher.encrypt("x", self.key)

    def test_bad_token_raises(self):
        with self.assertRaises(CipherError):
            self.cipher.decrypt("99/99", self.key)

    def test_empty_poem_rejected(self):
        with self.assertRaises(CipherError):
            PoemKey("   ")


class TestWordBookCipher(unittest.TestCase):

    def setUp(self):
        self.cipher = WordBookCipher()

    def test_encrypt_returns_numbers(self):
        enc = self.cipher.encrypt("антон був")
        self.assertTrue(all(t.isdigit() for t in enc.split()))

    def test_recovers_first_letters(self):
        # пословний шифр відновлює перші літери слів
        enc = self.cipher.encrypt("антон був")
        dec = self.cipher.decrypt(enc)
        self.assertEqual(dec.split()[0], "А")
        self.assertEqual(dec.split()[1], "Б")

    def test_unknown_letter_raises(self):
        with self.assertRaises(CipherError):
            self.cipher.encrypt("ы")

    def test_bad_code_raises(self):
        with self.assertRaises(CipherError):
            self.cipher.decrypt("abc")

    def test_out_of_range_raises(self):
        with self.assertRaises(CipherError):
            self.cipher.decrypt("99999")


if __name__ == "__main__":
    unittest.main()
