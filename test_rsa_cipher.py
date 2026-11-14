import unittest

from rsa_cipher import RSACipher, RSAError, TextbookRSA, modinv


class TestRSACipher(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.cipher = RSACipher()
        cls.pub, cls.priv = cls.cipher.generate_keys(1024)

    def test_roundtrip(self):
        text = "Таємне повідомлення для перевірки RSA!"
        enc = self.cipher.encrypt(text, self.pub)
        dec = self.cipher.decrypt(enc, self.priv)
        self.assertEqual(dec, text)

    def test_ciphertext_differs_from_plaintext(self):
        enc = self.cipher.encrypt("hello", self.pub)
        self.assertNotIn("hello", enc)

    def test_decrypt_with_public_key_fails(self):
        enc = self.cipher.encrypt("дані", self.pub)
        with self.assertRaises(RSAError):
            self.cipher.decrypt(enc, self.pub)

    def test_bad_public_key_rejected(self):
        with self.assertRaises(RSAError):
            self.cipher.encrypt("abc", "не ключ")

    def test_bad_base64_rejected(self):
        with self.assertRaises(RSAError):
            self.cipher.decrypt("@@@ not base64", self.priv)

    def test_short_key_rejected(self):
        with self.assertRaises(RSAError):
            RSACipher().generate_keys(512)


class TestTextbookRSA(unittest.TestCase):

    def test_wikipedia_example(self):
        # класичний приклад з Вікіпедії: p=61, q=53, e=17 -> d=413 (за λ(n)=780)
        rsa = TextbookRSA(61, 53, e=17)
        self.assertEqual(rsa.n, 3233)
        self.assertEqual(rsa.phi, 3120)
        self.assertEqual(rsa.lam, 780)
        self.assertEqual(rsa.d, 413)
        c = rsa.encrypt_num(65)
        self.assertEqual(c, 2790)
        self.assertEqual(rsa.decrypt_num(c), 65)

    def test_roundtrip_small(self):
        rsa = TextbookRSA(17, 23)
        for m in (0, 1, 42, 100, rsa.n - 1):
            self.assertEqual(rsa.decrypt_num(rsa.encrypt_num(m)), m)

    def test_non_prime_rejected(self):
        with self.assertRaises(RSAError):
            TextbookRSA(10, 7)

    def test_equal_primes_rejected(self):
        with self.assertRaises(RSAError):
            TextbookRSA(13, 13)

    def test_message_too_big(self):
        rsa = TextbookRSA(11, 13)  # n = 143
        with self.assertRaises(RSAError):
            rsa.encrypt_num(200)

    def test_modinv(self):
        self.assertEqual(modinv(17, 780), 413)


if __name__ == "__main__":
    unittest.main()
