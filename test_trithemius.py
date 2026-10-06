import unittest

from trithemius import (
    TrithemiusCipher, LinearKey, NonlinearKey, KeywordKey, CipherError,
)
from trithemius_attack import KnownPlaintextAttack


class TestTrithemiusCipher(unittest.TestCase):

    def test_roundtrip_linear_uk(self):
        cipher = TrithemiusCipher("uk")
        key = LinearKey(2, 3)
        text = "Привіт, світе!"
        self.assertEqual(cipher.decrypt(cipher.encrypt(text, key), key), text)

    def test_roundtrip_nonlinear_uk(self):
        cipher = TrithemiusCipher("uk")
        key = NonlinearKey(1, 2, 3)
        text = "таємне повідомлення"
        self.assertEqual(cipher.decrypt(cipher.encrypt(text, key), key), text)

    def test_roundtrip_keyword_en(self):
        cipher = TrithemiusCipher("en")
        key = KeywordKey("secret", cipher.alphabet)
        text = "Hello, World!"
        self.assertEqual(cipher.decrypt(cipher.encrypt(text, key), key), text)

    def test_shift_depends_on_position(self):
        # лінійний ключ дає різний зсув для однакових літер на різних позиціях
        cipher = TrithemiusCipher("en")
        result = cipher.encrypt("aa", LinearKey(1, 0))
        self.assertNotEqual(result[0], result[1])

    def test_case_is_preserved(self):
        cipher = TrithemiusCipher("en")
        result = cipher.encrypt("AbC", LinearKey(0, 1))
        self.assertEqual(result, "BcD")

    def test_non_alpha_untouched(self):
        cipher = TrithemiusCipher("en")
        result = cipher.encrypt("ab 12!", LinearKey(1, 1))
        self.assertEqual(result[2:], " 12!")


class TestValidation(unittest.TestCase):

    def test_zero_coeffs_rejected(self):
        with self.assertRaises(CipherError):
            LinearKey(0, 0)

    def test_non_int_coeffs_rejected(self):
        with self.assertRaises(CipherError):
            LinearKey(1.5, 2)

    def test_empty_keyword_rejected(self):
        with self.assertRaises(CipherError):
            KeywordKey("   ", TrithemiusCipher("uk").alphabet)

    def test_keyword_without_alpha_rejected(self):
        with self.assertRaises(CipherError):
            KeywordKey("123!", TrithemiusCipher("en").alphabet)

    def test_unknown_language(self):
        with self.assertRaises(CipherError):
            TrithemiusCipher("de")

    def test_text_type_checked(self):
        with self.assertRaises(CipherError):
            TrithemiusCipher("en").encrypt(123, LinearKey(1, 1))


class TestKnownPlaintextAttack(unittest.TestCase):

    def test_recover_linear(self):
        cipher = TrithemiusCipher("uk")
        key = LinearKey(2, 5)
        plain = "атака на шифр тритеміуса методом відомого тексту"
        enc = cipher.encrypt(plain, key)

        attacker = KnownPlaintextAttack("uk")
        a, b = attacker.recover_linear(plain, enc)
        # перевіряємо не рівність коефіцієнтів, а те, що знайдений ключ розшифровує
        found = LinearKey(a, b)
        self.assertEqual(cipher.decrypt(enc, found), plain)

    def test_recover_nonlinear(self):
        cipher = TrithemiusCipher("uk")
        key = NonlinearKey(1, 3, 7)
        plain = "ще одне секретне повідомлення для перевірки атаки на шифр"
        enc = cipher.encrypt(plain, key)

        attacker = KnownPlaintextAttack("uk")
        a, b, c = attacker.recover_nonlinear(plain, enc)
        found = NonlinearKey(a, b, c)
        self.assertEqual(cipher.decrypt(enc, found), plain)

    def test_recover_keyword_shifts(self):
        cipher = TrithemiusCipher("uk")
        key = KeywordKey("гасло", cipher.alphabet)
        plain = "перевірка гасла"
        enc = cipher.encrypt(plain, key)

        attacker = KnownPlaintextAttack("uk")
        shifts = attacker.recover_keyword_shifts(plain, enc)
        self.assertTrue(len(shifts) > 0)


if __name__ == "__main__":
    unittest.main()
